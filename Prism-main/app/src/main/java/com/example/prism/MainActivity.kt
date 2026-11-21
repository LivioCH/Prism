package com.example.prism

import com.example.prism.data.ScanSource
import com.example.prism.scan.GoogleStatus
import com.example.prism.scan.QuotaText
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.viewModels
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext

class MainActivity : ComponentActivity() {
    private val viewModel: AppStateViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    AntiPhishingMainScreen(viewModel)
                }
            }
        }
    }
}

private const val SHOW_SEPARATE_GOOGLE_CARD = false

@Composable
fun AntiPhishingMainScreen(viewModel: AppStateViewModel) {
    val context = LocalContext.current

    val showToast: (String, String) -> Unit = { title, body ->
        Toast.makeText(context, "$title: $body", Toast.LENGTH_LONG).show()
    }

    // 1. First Entry: Show Welcome Screen
    if (viewModel.showFrontPage && !viewModel.isLoggedIn) {
        FrontWelcomeScreen(
            onGetStartedClick = {
                viewModel.showFrontPage = false
            }
        )
        return
    }

    // 2 & 3. Authentication Flow (Unified if/else chain ensures seamless sign-in/sign-up switching)
    if (!viewModel.isLoggedIn) {
        if (viewModel.showSignUp) {
            SignUpScreen(
                viewModel = viewModel,
                onBackToLogin = { viewModel.showSignUp = false },
                onShowMessage = showToast
            )
        } else {
            LoginScreen(
                viewModel = viewModel,
                onSignUpClick = { viewModel.showSignUp = true },
                onLoginSuccess = { viewModel.isLoggedIn = true },
                onShowMessage = { msg -> Toast.makeText(context, msg, Toast.LENGTH_LONG).show() }
            )
        }
        return
    }

    // The Premium check quota resets by the hour: look again whenever the Scan tab is opened
    LaunchedEffect(viewModel.activeTab) {
        if (viewModel.activeTab == "scan") viewModel.refreshQuota()
    }

    // 4. Core Dashboard App Layout: Connects the real DashboardScreen from loginandsubscription.kt
    DashboardScreen(
        subscriptionPlan = viewModel.subscriptionPlan ?: SubscriptionPlan.FREE,
        privacyScore = viewModel.privacyScore.intValue,
        stats = DashboardStats(
            scansToday = viewModel.scansToday,
            threatsBlocked = viewModel.threatsBlocked,
            privacyAlerts = viewModel.privacyAlerts
        ),
        activeTab = viewModel.activeTab,
        clipboardMonitoring = viewModel.clipboardMonitoring,
        scanType = viewModel.scanType.name.lowercase(),
        scanInput = viewModel.scanInput,
        isScanning = viewModel.isScanning,
        // Transforms the list of ScanResult items to match the required ScanHistoryItem structures
        scanHistory = viewModel.scanHistory.map { result ->
            ScanHistoryItem(
                id = result.id,
                type = result.type.name.lowercase(),
                threat = result.threat.name.lowercase(),
                content = result.content,
                details = result.details,
                timestamp = formatAgo(result.timestamp)
            )
        },
        onToggleClipboardMonitoring = { newValue -> viewModel.setAutoProtection(newValue) },
        accountName = viewModel.accountName,
        accountEmail = viewModel.accountEmail,
        onRequestUpgrade = { viewModel.showSubscriptionModal = true },
        onLogout = { viewModel.logout() },
        onChangePassword = { cur, new, done -> viewModel.changePassword(cur, new, done) },
        googleQuota = viewModel.googleQuota,
        googleActive = viewModel.googleActive,
        quotaUnreachable = viewModel.quotaUnreachable,
        premiumUnavailable = viewModel.premiumUnavailable,
        isAdmin = viewModel.isAdmin,
        googleApiContent = {
            GoogleApiTab(
                status = viewModel.googleKeyStatus,
                busy = viewModel.googleKeyBusy,
                message = viewModel.googleKeyMessage,
                onLoad = { viewModel.loadGoogleKey() },
                onSave = { key, onSaved -> viewModel.saveGoogleKey(key, onSaved) },
                onRemove = { viewModel.removeGoogleKey() }
            )
        },
        adminContent = {
            AdminTab(
                users = viewModel.adminUsers.toList(),
                loading = viewModel.adminLoading,
                error = viewModel.adminError,
                busyId = viewModel.adminBusyId,
                myEmail = viewModel.accountEmail,
                onRefresh = { viewModel.loadAdminUsers() },
                onSetPlan = { user, plan -> viewModel.setUserPlan(user, plan) },
                onSetPassword = { user, pw, done -> viewModel.adminSetPassword(user, pw, done) }
            )
        },
        onScanTypeChange = { newTypeStr ->
            val matchedType = ScanType.entries.find { it.name.equals(newTypeStr, ignoreCase = true) }
            if (matchedType != null) viewModel.scanType = matchedType
        },
        onScanInputChange = { viewModel.scanInput = it; viewModel.scanError = null },
        onExecuteScan = { viewModel.handleScan(onSafeScan = showToast) },
        onTabChange = { viewModel.activeTab = it },
        scanError = viewModel.scanError,
        whitelist = viewModel.whitelistItems.toList(),
        onRemoveWhitelist = { viewModel.removeFromWhitelist(it) },
        blacklist = viewModel.blacklistItems.toList(),
        onRemoveBlacklist = { viewModel.removeFromBlacklist(it) },
        linkCheckContent = {
            // Google is now part of the normal scan (see CombinedScan), so the separate card is hidden.
            // Nothing was deleted: set SHOW_SEPARATE_GOOGLE_CARD to true to bring it back.
            if (SHOW_SEPARATE_GOOGLE_CARD) {
                LinkCheckCard(
                    text = viewModel.linkCheckText,
                    onTextChange = { viewModel.linkCheckText = it; viewModel.linkCheckError = null },
                    isChecking = viewModel.isLinkChecking,
                    error = viewModel.linkCheckError,
                    onCheck = { viewModel.handleLinkCheck() }
                )
            }
        }
    )

    // Plan picker: new accounts choose a plan here; "Upgrade / Change plan" on the Account tab reopens it
    SubscriptionPlanDialog(viewModel = viewModel, onPlanMessage = showToast)

    // 5. Threat Overlay Dialog Alert: Connects the real ThreatAlertDialog from loginandsubscription.kt
    if (viewModel.showThreatAlert && viewModel.threatAlertData != null) {
        val alertSource = viewModel.threatAlertData!!

        // Badges: which engines produced this result (Normal scan on the phone, Premium check = Google)
        val engine = when {
            viewModel.threatAlertSource == ScanSource.CACHE -> "cache"
            viewModel.threatAlertSource != ScanSource.FRESH -> ""   // blocked / trusted by the user: no engines ran
            else -> when (alertSource.googleStatus) {
                GoogleStatus.CHECKED -> "premium"
                GoogleStatus.LIMIT_REACHED -> "limit"
                GoogleStatus.UNAVAILABLE -> "unavailable"
                GoogleStatus.NOT_APPLICABLE -> "no_links"
                null -> ""
            }
        }
        val quotaLine = if (engine == "premium" || engine == "limit") viewModel.googleQuota?.let { QuotaText.line(it) } else null

        ThreatAlertDialog(
            showThreatAlert = viewModel.showThreatAlert,
            // Maps the data structure over to the required ThreatData format
            threatAlertData = ThreatData(
                threat = alertSource.threat.name.lowercase(),
                type = alertSource.type.name.lowercase(),
                content = alertSource.content,
                details = alertSource.details,
                reasons = alertSource.reasons.map { it.detail },
                infoLines = alertSource.infoLines,
                state = when (viewModel.threatAlertSource) {
                    ScanSource.BLACKLIST -> "blocked"
                    ScanSource.WHITELIST -> "trusted"
                    else -> "scan"
                },
                engine = engine,
                quotaLine = quotaLine
            ),
            onDismiss = { viewModel.showThreatAlert = false },
            // Trust / Block act on the URL's host, so they are only enabled for URL results
            onTrust = if (alertSource.type == ScanType.URL) {
                { viewModel.trustCurrentUrl { msg -> Toast.makeText(context, msg, Toast.LENGTH_LONG).show() } }
            } else null,
            onBlacklist = if (alertSource.type == ScanType.URL) {
                { viewModel.blacklistCurrentUrl { msg -> Toast.makeText(context, msg, Toast.LENGTH_LONG).show() } }
            } else null,
            onUnblock = { viewModel.unblockCurrentUrl() },
            onUntrust = { viewModel.untrustCurrentUrl() }
        )
    }
}

/** "Just now" / "5 min ago" / "3 h ago" / "2 d ago" for the history list. */
internal fun formatAgo(timestamp: Long, now: Long = System.currentTimeMillis()): String {
    val minutes = ((now - timestamp) / 60_000).coerceAtLeast(0)
    return when {
        minutes < 1 -> "Just now"
        minutes < 60 -> "$minutes min ago"
        minutes < 24 * 60 -> "${minutes / 60} h ago"
        else -> "${minutes / (24 * 60)} d ago"
    }
}
