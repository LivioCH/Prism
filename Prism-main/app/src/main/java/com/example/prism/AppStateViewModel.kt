package com.example.prism

import android.app.Application
import android.content.Context
import androidx.compose.runtime.*
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.example.prism.data.DbMap
import com.example.prism.data.PrismDatabase
import com.example.prism.data.ReasonsJson
import com.example.prism.data.ScanHistoryEntity
import com.example.prism.data.ScanRepository
import com.example.prism.data.ScanSource
import com.example.prism.data.UrlKeys
import com.example.prism.net.AdminUser
import com.example.prism.net.ApiClient
import com.example.prism.net.ApiException
import com.example.prism.net.AuthResult
import com.example.prism.net.GoogleKeyStatus
import com.example.prism.net.GoogleQuota
import com.example.prism.scan.GoogleStatus
import com.example.prism.scan.QuotaText
import org.json.JSONObject
import com.example.prism.scan.AutoProtectionPolicy
import com.example.prism.scan.CombinedScan
import com.example.prism.scan.FreeScanLimit
import com.example.prism.scan.ManualScanAnalyzer
import com.example.prism.scan.PhoneNumbers
import com.example.prism.scan.UrlMlModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlin.time.Duration.Companion.milliseconds

class AppStateViewModel(application: Application) : AndroidViewModel(application) {

    private val sharedPrefs = application.getSharedPreferences("prism_prefs", Context.MODE_PRIVATE)

    var activeTab by mutableStateOf("scan")
    var scanInput by mutableStateOf("")
    var scanType by mutableStateOf(ScanType.URL)
    var isScanning by mutableStateOf(false)

    // Friendly input error for Manual Scan (null = nothing to show)
    var scanError by mutableStateOf<String?>(null)

    // Local URL model (assets/url_model.json); null if it cannot be loaded -> heuristics only
    private val urlModel: UrlMlModel? by lazy {
        runCatching {
            UrlMlModel.fromJson(getApplication<Application>().assets.open("url_model.json").bufferedReader().use { it.readText() })
        }.getOrNull()
    }

    // Optimized primitive backing state for Compose
    var privacyScore = mutableIntStateOf(85)

    var isLoggedIn by mutableStateOf(false)
    var showFrontPage by mutableStateOf(true)
    var showSubscriptionModal by mutableStateOf(false)
    var subscriptionPlan by mutableStateOf<SubscriptionPlan?>(null)
    var showThreatAlert by mutableStateOf(false)
    var threatAlertData by mutableStateOf<ScanResult?>(null)
    // Where the popup's verdict came from: decides which popup variant is shown (blocked / trusted / normal)
    var threatAlertSource by mutableStateOf(ScanSource.FRESH)
    // Auto-Protection switch (saved on this device). Off by default: the user turns it on themselves.
    // It only counts as ON when the plan is PLUS and AI Screen Monitoring is enabled (see DashboardScreen).
    var clipboardMonitoring by mutableStateOf(sharedPrefs.getBoolean("prism_auto_protection", false))
        private set

    // Shown on the Account tab
    var accountName by mutableStateOf(sharedPrefs.getString("prism_name", "") ?: "")
    var accountEmail by mutableStateOf(sharedPrefs.getString("prism_email", "") ?: "")

    // Admin: the Admin tab only exists for accounts the backend marks isAdmin (re-checked by the server on every call)
    var isAdmin by mutableStateOf(sharedPrefs.getBoolean("prism_is_admin", false))
    val adminUsers = mutableStateListOf<AdminUser>()
    var adminLoading by mutableStateOf(false)
    var adminError by mutableStateOf<String?>(null)
    var adminBusyId by mutableStateOf<String?>(null)   // account whose plan is being saved

    // Premium check (Google) quota for today. null = not loaded yet or backend unreachable.
    var googleQuota by mutableStateOf<GoogleQuota?>(null)
    var quotaUnreachable by mutableStateOf(false)
    /** Is the server's Google link check switched on? true = active, false = no API key on the server, null = unknown (offline / not asked yet). */
    var googleActive by mutableStateOf<Boolean?>(null)
    // The last Premium check could not reach Google (backend down, key missing...): the indicator says so
    // instead of promising checks that would fail. Cleared by the next successful check.
    var premiumUnavailable by mutableStateOf(false)

    // Free plan: times of the manual scans of the last 24h (FreeScanLimit), saved on the phone
    private var freeScanTimes = FreeScanLimit.decode(sharedPrefs.getString("free_scan_times", null))
    var freeScansLeft by mutableIntStateOf(FreeScanLimit.remaining(freeScanTimes, System.currentTimeMillis()))
    var freeScansResetAt by mutableStateOf(FreeScanLimit.resetsAt(freeScanTimes, System.currentTimeMillis()))

    private fun refreshFreeScans(now: Long = System.currentTimeMillis()) {
        freeScanTimes = FreeScanLimit.recent(freeScanTimes, now)
        freeScansLeft = FreeScanLimit.remaining(freeScanTimes, now)
        freeScansResetAt = FreeScanLimit.resetsAt(freeScanTimes, now)
    }

    private fun recordFreeScan(now: Long = System.currentTimeMillis()) {
        freeScanTimes = FreeScanLimit.recent(freeScanTimes + now, now)
        sharedPrefs.edit().putString("free_scan_times", FreeScanLimit.encode(freeScanTimes)).apply()
        refreshFreeScans(now)
    }

    var loginEmail by mutableStateOf("")
    var loginPassword by mutableStateOf("")
    var isLoggingIn by mutableStateOf(false)

    var showSignUp by mutableStateOf(false)
    var signUpName by mutableStateOf("")
    var signUpEmail by mutableStateOf("")
    var signUpPassword by mutableStateOf("")
    var signUpConfirmPassword by mutableStateOf("")
    var isSigningUp by mutableStateOf(false)

    // Dashboard numbers. Always computed from the database (see observeDatabase), never hard-coded.
    var scansToday by mutableIntStateOf(0)        // total scans
    var threatsBlocked by mutableIntStateOf(0)    // DANGEROUS verdicts
    var privacyAlerts by mutableIntStateOf(0)     // SUSPICIOUS verdicts

    // History and whitelist mirror the encrypted database (permanent across app restarts)
    var scanHistory = mutableStateListOf<ScanResult>()
    var whitelistItems = mutableStateListOf<String>()
    var blacklistItems = mutableStateListOf<String>()

    // Google link check (Web Risk through prism-backend; the API key lives on the server)
    var linkCheckText by mutableStateOf("")
    var isLinkChecking by mutableStateOf(false)
    var linkCheckError by mutableStateOf<String?>(null)


    // Opened off the main thread: the encrypted database must not block the UI
    private val repoDeferred = viewModelScope.async(Dispatchers.IO) {
        val db = PrismDatabase.open(getApplication())
        db.urlCacheDao().deleteOlderThan(System.currentTimeMillis() - ScanRepository.CACHE_TTL_MS)
        db to ScanRepository(db.historyDao(), db.whitelistDao(), db.blacklistDao(), db.urlCacheDao())
    }

    init {
        PhoneNumbers.init(application)
        checkSavedSession()
        observeDatabase()
        refreshQuota()
    }

    /** Changes the password on the server. [onDone] gets null on success, or a message to show. */
    fun changePassword(current: String, new: String, onDone: (String?) -> Unit) {
        val token = sharedPrefs.getString("prism_token", null)
        if (token == null) { onDone("You are signed out. Log in again."); return }
        viewModelScope.launch {
            val error = try {
                withContext(Dispatchers.IO) { ApiClient.changePassword(token, current, new) }
                null
            } catch (e: ApiException) {
                if (e.code == "invalid_credentials") "Current password is incorrect" else e.message ?: "Could not change the password"
            } catch (e: Exception) {
                "Cannot reach the server. Check your connection."
            }
            onDone(error)
        }
    }

    /** Asks the backend how many Premium checks are left (silent: offline just shows "unavailable"). */
    fun refreshQuota() {
        val token = sharedPrefs.getString("prism_token", null) ?: return   // no token = logged out
        viewModelScope.launch {
            try {
                val (q, enabled) = withContext(Dispatchers.IO) { ApiClient.quotaAndStatus(token) }
                googleQuota = q
                googleActive = enabled
                quotaUnreachable = false
            } catch (e: Exception) {
                quotaUnreachable = true
            }
        }
    }

    /** History, stats and whitelist are read from the database; the UI refreshes on every change. */
    private fun observeDatabase() {
        viewModelScope.launch {
            val db = repoDeferred.await().first
            val history = db.historyDao()
            launch {
                history.observeAll().collect { rows ->
                    scanHistory.clear()
                    scanHistory.addAll(rows.map { it.toScanResult() })
                }
            }
            launch { history.observeTotal().collect { scansToday = it; updatePrivacyScore() } }
            launch { history.observeCount("DANGEROUS").collect { threatsBlocked = it; updatePrivacyScore() } }
            launch { history.observeCount("SUSPICIOUS").collect { privacyAlerts = it; updatePrivacyScore() } }
            launch {
                db.whitelistDao().observeAll().collect { rows ->
                    whitelistItems.clear()
                    whitelistItems.addAll(rows.map { it.value })
                }
            }
            launch {
                db.blacklistDao().observeAll().collect { rows ->
                    blacklistItems.clear()
                    blacklistItems.addAll(rows.map { it.value })
                }
            }
        }
    }

    // Same formula as prism-backend: start at 100, -5 per DANGEROUS, -2 per SUSPICIOUS
    private fun updatePrivacyScore() {
        privacyScore.intValue = (100 - threatsBlocked * 5 - privacyAlerts * 2).coerceIn(0, 100)
    }

    private fun ScanHistoryEntity.toScanResult(): ScanResult {
        val reasonList = ReasonsJson.decode(reasons)
        return ScanResult(
            id = id.toString(),
            type = DbMap.type(kind),
            content = input,
            threat = DbMap.threat(verdict),
            timestamp = timestamp,
            details = reasonList.take(2).joinToString("; ") { it.detail },
            reasons = reasonList,
            infoLines = mlScore?.let { listOf("ML: ${ManualScanAnalyzer.percent(it)}% phishing probability") } ?: emptyList()
        )
    }

    /** Adds the host of the URL in the popup to the whitelist. */
    fun trustCurrentUrl(onMessage: (String) -> Unit) {
        val data = threatAlertData ?: return
        if (data.type != ScanType.URL) return
        viewModelScope.launch {
            val ok = repoDeferred.await().second.trust(data.content)
            showThreatAlert = false
            onMessage(if (ok) "Added to trusted sites: ${UrlKeys.host(data.content)}" else "Could not add to trusted sites")
        }
    }

    /** Adds the host of the URL in the popup to the blacklist (always DANGEROUS from now on). */
    fun blacklistCurrentUrl(onMessage: (String) -> Unit) {
        val data = threatAlertData ?: return
        if (data.type != ScanType.URL) return
        viewModelScope.launch {
            val ok = repoDeferred.await().second.block(data.content)
            showThreatAlert = false
            onMessage(if (ok) "Blocked: ${UrlKeys.host(data.content)}" else "Could not block this site")
        }
    }

    /** Popup "Unblock this site": DELETE the host from the block list, then close. */
    fun unblockCurrentUrl() {
        val data = threatAlertData ?: return
        showThreatAlert = false
        viewModelScope.launch { repoDeferred.await().second.let { it.unblock(UrlKeys.host(data.content) ?: data.content) } }
    }

    /** Popup "Untrust this site": DELETE the host from the trust list, then close. */
    fun untrustCurrentUrl() {
        val data = threatAlertData ?: return
        showThreatAlert = false
        viewModelScope.launch { repoDeferred.await().second.let { it.untrust(UrlKeys.host(data.content) ?: data.content) } }
    }

    fun removeFromBlacklist(value: String) {
        viewModelScope.launch { repoDeferred.await().second.unblock(value) }
    }

    fun removeFromWhitelist(value: String) {
        viewModelScope.launch { repoDeferred.await().second.untrust(value) }
    }

    private fun checkSavedSession() {
        val savedLogin = sharedPrefs.getBoolean("prism_logged_in", false)
        val savedPlanString = sharedPrefs.getString("prism_plan", null)

        if (savedLogin) {
            isLoggedIn = true
            showFrontPage = false
            subscriptionPlan = when (savedPlanString) {
                "FREE" -> SubscriptionPlan.FREE
                "PLUS" -> SubscriptionPlan.PLUS
                else -> {
                    showSubscriptionModal = true
                    null
                }
            }
        }
    }

    fun handleLogin(onValidationError: (String) -> Unit, onLoginSuccess: (String) -> Unit) {
        if (loginEmail.isBlank() || loginPassword.isBlank()) {
            onValidationError("Please enter email and password")
            return
        }

        isLoggingIn = true

        viewModelScope.launch {
            try {
                val r = withContext(Dispatchers.IO) { ApiClient.login(loginEmail.trim(), loginPassword) }
                saveSession(r)
                isLoggedIn = true
                subscriptionPlan = r.plan?.let { SubscriptionPlan.valueOf(it) }
                if (r.plan == null) {
                    showSubscriptionModal = true
                } else {
                    onLoginSuccess("Welcome back! You are now logged in securely.")
                }
            } catch (e: Exception) {
                onValidationError(friendlyError(e))
            } finally {
                isLoggingIn = false
            }
        }
    }

    /** Stores the server session (token, profile, plan) so the app stays logged in after a restart. */
    private fun saveSession(r: AuthResult) {
        sharedPrefs.edit().apply {
            putBoolean("prism_logged_in", true)
            putString("prism_token", r.token)
            putString("prism_email", r.email)
            putString("prism_name", r.name)
            putBoolean("prism_is_admin", r.isAdmin)
            if (r.plan != null) putString("prism_plan", r.plan) else remove("prism_plan")
            apply()
        }
        accountName = r.name
        accountEmail = r.email
        isAdmin = r.isAdmin
        googleQuota = null
        refreshQuota()
    }

    fun setAutoProtection(on: Boolean) {
        clipboardMonitoring = on
        sharedPrefs.edit().putBoolean("prism_auto_protection", on).apply()
    }

    /** Ends the session on this device: forgets the token and profile and returns to the login screen. */
    fun logout() {
        sharedPrefs.edit()
            .remove("prism_logged_in").remove("prism_token").remove("prism_email")
            .remove("prism_name").remove("prism_plan").remove("prism_auto_protection").remove("prism_is_admin")
            .apply()
        isAdmin = false
        adminUsers.clear()
        adminError = null
        googleQuota = null
        googleActive = null
        quotaUnreachable = false
        premiumUnavailable = false
        isLoggedIn = false
        showFrontPage = false
        showSubscriptionModal = false
        showThreatAlert = false
        subscriptionPlan = null
        clipboardMonitoring = false
        accountName = ""
        accountEmail = ""
        loginEmail = ""
        loginPassword = ""
        activeTab = "scan"
    }

    // ---------------------------------------------------------------- admin

    /** The server says this account is no longer an admin: hide the tab right away. */
    private fun revokeAdmin() {
        isAdmin = false
        sharedPrefs.edit().remove("prism_is_admin").apply()
        adminUsers.clear()
        if (activeTab == "admin" || activeTab == "google") activeTab = "scan"
    }

    /** Loads every account from the backend (GET /api/admin/users). */
    fun loadAdminUsers() {
        val token = sharedPrefs.getString("prism_token", null)
        if (token == null) { adminError = "Please log in again"; return }
        adminLoading = true
        adminError = null
        viewModelScope.launch {
            try {
                val list = withContext(Dispatchers.IO) { ApiClient.adminUsers(token) }
                adminUsers.clear()
                adminUsers.addAll(list)
            } catch (e: Exception) {
                if (e is ApiException && e.code == "forbidden") revokeAdmin() else adminError = friendlyError(e)
            } finally {
                adminLoading = false
            }
        }
    }

    /** Admin: set a new password for [user]. [onDone] gets null on success, or a message to show. */
    fun adminSetPassword(user: AdminUser, newPassword: String, onDone: (String?) -> Unit) {
        val token = sharedPrefs.getString("prism_token", null)
        if (token == null) { onDone("Please log in again"); return }
        viewModelScope.launch {
            val error = try {
                withContext(Dispatchers.IO) { ApiClient.adminSetPassword(token, user.id, newPassword) }
                null
            } catch (e: Exception) {
                if (e is ApiException && e.code == "forbidden") { revokeAdmin(); "You are not an admin" } else friendlyError(e)
            }
            onDone(error)
        }
    }

    // ---- Google API key screen (admin only)
    var googleKeyStatus by mutableStateOf<GoogleKeyStatus?>(null)
    var googleKeyBusy by mutableStateOf(false)
    /** Result line under the key field: (text, isError). */
    var googleKeyMessage by mutableStateOf<Pair<String, Boolean>?>(null)

    fun loadGoogleKey() {
        val token = sharedPrefs.getString("prism_token", null) ?: return
        viewModelScope.launch {
            try {
                val s = withContext(Dispatchers.IO) { ApiClient.googleKeyStatus(token) }
                googleKeyStatus = s
                googleActive = s.active
            } catch (e: Exception) {
                if (e is ApiException && e.code == "forbidden") revokeAdmin()
                else googleKeyMessage = friendlyError(e) to true
            }
        }
    }

    /** Sends the key to the server, which checks it with Google and saves it only if Google accepts it. */
    fun saveGoogleKey(key: String, onSaved: () -> Unit) {
        val token = sharedPrefs.getString("prism_token", null)
        if (token == null) { googleKeyMessage = "Please log in again" to true; return }
        googleKeyBusy = true
        googleKeyMessage = null
        viewModelScope.launch {
            try {
                val s = withContext(Dispatchers.IO) { ApiClient.setGoogleKey(token, key.trim()) }
                googleKeyStatus = s
                googleActive = s.active
                googleKeyMessage = "Saved. Google accepted the key and the link check is now active." to false
                onSaved()
                refreshQuota()
            } catch (e: Exception) {
                googleKeyMessage = friendlyError(e) to true
            } finally {
                googleKeyBusy = false
            }
        }
    }

    fun removeGoogleKey() {
        val token = sharedPrefs.getString("prism_token", null) ?: return
        googleKeyBusy = true
        googleKeyMessage = null
        viewModelScope.launch {
            try {
                val s = withContext(Dispatchers.IO) { ApiClient.clearGoogleKey(token) }
                googleKeyStatus = s
                googleActive = s.active
                googleKeyMessage = (if (s.active) "Removed the saved key. The server's .env key is used instead." else "Key removed. The Google link check is now off.") to false
                refreshQuota()
            } catch (e: Exception) {
                googleKeyMessage = friendlyError(e) to true
            } finally {
                googleKeyBusy = false
            }
        }
    }

    /** Changes any account's plan on the server. If it is the admin's own account, the app follows at once. */
    fun setUserPlan(user: AdminUser, plan: SubscriptionPlan) {
        if (user.plan == plan.name || adminBusyId != null) return
        val token = sharedPrefs.getString("prism_token", null)
        if (token == null) { adminError = "Please log in again"; return }
        adminBusyId = user.id
        adminError = null
        viewModelScope.launch {
            try {
                val updated = withContext(Dispatchers.IO) { ApiClient.adminSetPlan(token, user.id, plan.name) }
                val i = adminUsers.indexOfFirst { it.id == user.id }
                if (i >= 0) adminUsers[i] = adminUsers[i].copy(plan = updated.plan)
                if (user.email.equals(accountEmail, ignoreCase = true)) {
                    subscriptionPlan = plan
                    sharedPrefs.edit().putString("prism_plan", plan.name).apply()
                    refreshQuota()
                }
            } catch (e: Exception) {
                if (e is ApiException && e.code == "forbidden") revokeAdmin() else adminError = friendlyError(e)
            } finally {
                adminBusyId = null
            }
        }
    }

    private fun friendlyError(e: Exception): String =
        if (e is ApiException) e.message ?: "Request failed" else "Cannot reach the server. Check your connection."

    fun handlePlanSelection(plan: SubscriptionPlan, onMessage: (String, String) -> Unit) {
        subscriptionPlan = plan

        sharedPrefs.edit().apply {
            putString("prism_plan", plan.name)
            apply()
        }

        showSubscriptionModal = false

        // Tell the server too (best effort: the plan is already saved locally)
        val token = sharedPrefs.getString("prism_token", null)
        if (token != null) {
            viewModelScope.launch {
                runCatching { withContext(Dispatchers.IO) { ApiClient.setPlan(token, plan.name) } }
                refreshQuota()   // Free <-> Plus changes the number of Premium checks
            }
        }

        if (plan == SubscriptionPlan.FREE) {
            onMessage("Welcome to Prism!", "You can upgrade anytime for advanced features.")
        } else {
            onMessage("Welcome to Prism Premium!", "Enjoy unlimited scans and premium protection features.")
        }
    }

    fun handleSignUp(
        onValidationError: (String) -> Unit,
        onSignUpSuccess: (String, String) -> Unit
    ) {
        if (signUpName.isBlank() || signUpEmail.isBlank() || signUpPassword.isBlank() || signUpConfirmPassword.isBlank()) {
            onValidationError("Please fill in all fields")
            return
        }

        if (signUpPassword != signUpConfirmPassword) {
            onValidationError("Passwords do not match")
            return
        }

        if (signUpPassword.length < 6) {
            onValidationError("Password must be at least 6 characters")
            return
        }

        isSigningUp = true

        viewModelScope.launch {
            try {
                val r = withContext(Dispatchers.IO) {
                    ApiClient.signup(signUpName.trim(), signUpEmail.trim(), signUpPassword)
                }
                saveSession(r)
                isLoggedIn = true
                showSignUp = false
                showSubscriptionModal = true
                onSignUpSuccess("Account created successfully!", "Now choose your protection plan.")
            } catch (e: Exception) {
                onValidationError(friendlyError(e))
            } finally {
                isSigningUp = false
            }
        }
    }

    // Last copied text that was checked, so the same clipboard is not checked twice (survives rotation)
    private var lastClipboardScan: String? = null

    /**
     * Auto-Protection for copied links (Plus). MainActivity reads the clipboard while Prism is open,
     * because Android does not let apps read it in the background. Same pipeline as a Plus manual scan:
     * blacklist -> whitelist -> cache -> rules + ML, then Google Web Risk. Only links are checked; other
     * copied text is ignored. The result is saved to History; a popup opens only when it is not safe.
     */
    fun autoScanClipboard(copied: String) {
        val text = copied.trim()
        val token = sharedPrefs.getString("prism_token", null)
        val plan = subscriptionPlan?.name
        if (!AutoProtectionPolicy.armed(plan, clipboardMonitoring, token != null)) return
        if (text.isEmpty() || text == lastClipboardScan) return
        val url = if (ManualScanAnalyzer.detectKind(text) == ScanType.URL) text
            else ManualScanAnalyzer.extractUrls(text).firstOrNull() ?: return
        lastClipboardScan = text

        viewModelScope.launch {
            val repo = repoDeferred.await().second
            val res = runCatching {
                val blocked = repo.blacklistValues()
                repo.scan(url) { link ->
                    val manual = ManualScanAnalyzer.analyze(link, urlModel, true, blocked)
                    CombinedScan.run(manual) { links ->
                        withContext(Dispatchers.IO) { ApiClient.webRiskCheck(token!!, links, CLIPBOARD_GOOGLE_TIMEOUT_MS) }
                    }
                }
            }.getOrNull() ?: return@launch
            val outcome = res.outcome
            if (outcome.threat == ThreatLevel.SAFE) return@launch    // safe links are only saved to History

            threatAlertSource = res.source
            threatAlertData = ScanResult(
                id = System.currentTimeMillis().toString(),
                type = outcome.kind,
                content = url,
                threat = outcome.threat,
                timestamp = System.currentTimeMillis(),
                details = outcome.reasons.take(2).joinToString("; ") { it.detail },
                reasons = outcome.reasons,
                infoLines = outcome.infoLines + "Found in your clipboard (Auto-Protection)",
                googleStatus = if (res.source == ScanSource.FRESH) outcome.googleStatus else null
            )
            showThreatAlert = true
        }
    }

    fun handleScan(
        onSafeScan: (String, String) -> Unit
    ) {
        val input = scanInput.trim()
        scanError = null
        if (input.isEmpty()) {
            scanError = "Please enter something to scan"
            return
        }
        val isPlus = subscriptionPlan == SubscriptionPlan.PLUS
        // Free plan: 10 manual scans a day, on the phone only
        if (!isPlus) {
            refreshFreeScans()
            if (freeScansLeft == 0) {
                scanError = "Free plan: ${FreeScanLimit.PER_DAY} scans a day used up. Next scan in " +
                    "${QuotaText.resetsIn(freeScansResetAt) ?: "a while"}, or upgrade to Prism Plus for unlimited scans."
                return
            }
        }
        // Input kind (URL / text / phone number) is detected automatically by ManualScanAnalyzer.
        isScanning = true

        viewModelScope.launch {
            delay(300.milliseconds)

            val advanced = isPlus
            val repo = repoDeferred.await().second
            // Pipeline: blacklist -> whitelist -> cache -> heuristics + ML -> save (see ScanRepository)
            val blocked = repo.blacklistValues()   // lets the heuristic "blocklisted" rule see blocked URLs inside messages
            // One scan, two layers: the on-device checks always run, then the links found are also checked
            // with Google Web Risk through prism-backend. This only runs on a blacklist/whitelist/cache
            // miss. Google can only raise the verdict, and if it is unavailable (offline, Free daily limit
            // used up) the on-device result is still shown. See CombinedScan.
            val token = sharedPrefs.getString("prism_token", null)
            val res = repo.scan(input) { text ->
                val manual = ManualScanAnalyzer.analyze(text, urlModel, advanced, blocked)
                // The Google (Premium) check is Plus only; Free gets the on-device scan alone
                if (!isPlus) return@scan manual.copy(googleStatus = GoogleStatus.PLUS_ONLY)
                CombinedScan.run(manual) { links ->
                    if (token == null) throw ApiException("unauthorized", "please log in again")
                    // Already known to be used up (and not reset yet): do not even ask the server
                    val q = googleQuota
                    if (q != null && q.exhausted && (q.resetsAt ?: Long.MAX_VALUE) > System.currentTimeMillis()) {
                        throw ApiException("daily_limit", "Premium checks used up",
                            JSONObject().put("limit", q.limit).put("resetsAt", q.resetsAt))
                    }
                    withContext(Dispatchers.IO) { ApiClient.webRiskCheck(token, links) }
                }
            }
            val outcome = res.outcome
            val newScan = ScanResult(
                id = System.currentTimeMillis().toString(),
                type = outcome.kind,
                content = input,
                threat = outcome.threat,
                timestamp = System.currentTimeMillis(),
                details = outcome.reasons.take(2).joinToString("; ") { it.detail },
                reasons = outcome.reasons,
                infoLines = outcome.infoLines,
                // badges "Normal scan / Premium check" only for a fresh scan; cached and user-listed results have no engine info
                googleStatus = if (res.source == ScanSource.FRESH) outcome.googleStatus else null
            )

            // Premium check bookkeeping: remember what is left, and tell the user when it runs out
            if (res.source == ScanSource.FRESH) {
                val before = googleQuota
                outcome.googleQuota?.let { googleQuota = it; quotaUnreachable = false }
                when (outcome.googleStatus) {
                    GoogleStatus.UNAVAILABLE -> premiumUnavailable = true
                    GoogleStatus.CHECKED -> {
                        premiumUnavailable = false
                        googleActive = true   // Google just answered a real check
                        val q = outcome.googleQuota
                        if (q != null && q.exhausted && before?.exhausted != true) {
                            onSafeScan(QuotaText.lastUsedTitle(), QuotaText.lastUsedBody(q))
                        }
                    }
                    GoogleStatus.LIMIT_REACHED -> onSafeScan(QuotaText.usedUpTitle(), QuotaText.usedUpBody(googleQuota))
                    else -> {}
                }
            }
            // History and the dashboard numbers update themselves from the database flows.
            if (!isPlus) recordFreeScan()      // every Free manual scan uses one of today's 10
            isScanning = false
            scanInput = ""

            // Every verdict (SAFE / SUSPICIOUS / DANGEROUS) opens the ThreatAlertDialog popup.
            threatAlertSource = res.source
            threatAlertData = newScan
            showThreatAlert = true
        }
    }

    /**
     * Google link check: sends a link, or a message with links, to prism-backend, which checks each
     * link with Google Cloud Web Risk. The verdict is saved to History and opens the same popup as
     * Manual Scan. A failed call shows an error and never a "safe" result.
     */
    fun handleLinkCheck() {
        val text = linkCheckText.trim()
        linkCheckError = null
        if (text.isEmpty()) {
            linkCheckError = "Paste a link or a message with links"
            return
        }
        val token = sharedPrefs.getString("prism_token", null)
        if (token == null) {
            linkCheckError = "Please log in again to use the Google link check"
            return
        }
        isLinkChecking = true

        viewModelScope.launch {
            try {
                val r = withContext(Dispatchers.IO) { ApiClient.webRiskCheck(token, text) }
                val threat = if (r.isDangerous) ThreatLevel.DANGER else ThreatLevel.SAFE
                val reasons = r.reasons.map { (line, listed) ->
                    ScanReason("web_risk", line, if (listed) 100 else 0, if (listed) "high" else "low")
                }
                val type = if (text.any { it.isWhitespace() }) ScanType.MESSAGE else ScanType.URL
                val now = System.currentTimeMillis()
                withContext(Dispatchers.IO) {
                    repoDeferred.await().first.historyDao().insert(
                        ScanHistoryEntity(
                            input = text,
                            kind = DbMap.kind(type),
                            verdict = DbMap.verdict(threat),
                            mlScore = null,
                            reasons = ReasonsJson.encode(reasons),
                            timestamp = now
                        )
                    )
                }
                linkCheckText = ""

                threatAlertSource = ScanSource.FRESH
                threatAlertData = ScanResult(
                    id = now.toString(),
                    type = type,
                    content = text,
                    threat = threat,
                    timestamp = now,
                    details = r.details,
                    reasons = reasons,
                    infoLines = listOf(
                        "Checked online by Google Web Risk",
                        "Not listed means Google hasn't reported the site, not that it is proven safe"
                    )
                )
                showThreatAlert = true
            } catch (e: Exception) {
                linkCheckError = friendlyError(e)
            } finally {
                isLinkChecking = false
            }
        }
    }

    fun getThreatColorHex(threat: ThreatLevel): Long {
        return when (threat) {
            ThreatLevel.SAFE -> 0xFF16A34A
            ThreatLevel.WARNING -> 0xFFCA8A04
            ThreatLevel.DANGER -> 0xFFDC2626
        }
    }

    fun getThreatBgHex(threat: ThreatLevel): Long {
        return when (threat) {
            ThreatLevel.SAFE -> 0xFFF0FDF4
            ThreatLevel.WARNING -> 0xFFFEFCE8
            ThreatLevel.DANGER -> 0xFFFEF2F2
        }
    }

    private companion object {
        // A copied link waits for Google only briefly; if it is slow the on-device verdict is used
        const val CLIPBOARD_GOOGLE_TIMEOUT_MS = 5_000
    }
}