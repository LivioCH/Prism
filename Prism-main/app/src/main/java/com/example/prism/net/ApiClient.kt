package com.example.prism.net

import org.json.JSONObject
import java.io.IOException
import java.net.ConnectException
import java.net.HttpURLConnection
import java.net.URL

/** [extra] is the backend's whole "error" object, e.g. {"limit":10,"resetsAt":...} on a 429 daily_limit. */
class ApiException(val code: String, message: String, val extra: JSONObject? = null) : Exception(message)

/**
 * Premium (Google) checks left today. Free: [limit] a day (rolling 24h), Plus: [unlimited].
 * [resetsAt] is when the next check frees up (epoch ms), null if none was used.
 */
data class GoogleQuota(val unlimited: Boolean, val limit: Int, val used: Int, val resetsAt: Long?) {
    val remaining: Int get() = if (unlimited) Int.MAX_VALUE else (limit - used).coerceAtLeast(0)
    val exhausted: Boolean get() = !unlimited && remaining == 0
}

/** [source] is "app" (entered in the admin screen), "env" (server .env file) or "none". */
data class GoogleKeyStatus(val active: Boolean, val source: String, val hint: String?)

data class AuthResult(val token: String, val name: String, val email: String, val plan: String?, val isAdmin: Boolean = false)

/** One account as the admin screen sees it (GET /api/admin/users). [plan] is null until the user picks one. */
data class AdminUser(
    val id: String,
    val name: String,
    val email: String,
    val plan: String?,
    val isAdmin: Boolean,
    val scanCount: Int,
    val createdAt: Long
)

/**
 * Verdict of POST /api/scans/webrisk (Google Web Risk). [reasons] has one readable line per link,
 * paired with whether Google lists that link.
 */
data class WebRiskResult(
    val isDangerous: Boolean,
    val details: String,
    val reasons: List<Pair<String, Boolean>>,
    val quota: GoogleQuota? = null   // what is left after this check (older backends do not send it)
)

/** Minimal client for prism-backend. Calls block: run them on Dispatchers.IO. */
object ApiClient {
    // Reaches the PC's backend through `adb reverse tcp:3000 tcp:3000` (development only).
    const val BASE_URL = "http://localhost:3000"

    // 10.0.2.2 is the Android emulator's own address for the PC: it needs no `adb reverse`, which
    // drops whenever Android Studio or the emulator restarts. A USB phone still uses localhost + adb reverse.
    internal val BASE_URLS = listOf(BASE_URL, "http://10.0.2.2:3000")

    // The address that answered last; tried first next time
    @Volatile private var baseUrl = BASE_URL

    // A link check waits on Google for every link in the message, so it gets more than the normal 8 s
    private const val WEB_RISK_TIMEOUT_MS = 30_000

    /**
     * Sends to the last address that worked. If that one refuses the connection (nothing sent yet, so a
     * retry is safe), the other address is tried and remembered when it answers.
     */
    private fun call(method: String, path: String, body: JSONObject? = null, token: String? = null, timeoutMs: Int = 8000): JSONObject {
        val first = baseUrl
        try {
            return send(first, method, path, body, token, timeoutMs)
        } catch (e: ConnectException) {
            for (other in BASE_URLS) {
                if (other == first) continue
                try {
                    return send(other, method, path, body, token, timeoutMs).also { baseUrl = other }
                } catch (_: IOException) {
                    // keep the first error: it names the address the app normally uses
                }
            }
            throw e
        }
    }

    private fun send(base: String, method: String, path: String, body: JSONObject?, token: String?, timeoutMs: Int): JSONObject {
        val conn = URL(base + path).openConnection() as HttpURLConnection
        try {
            conn.requestMethod = method
            conn.connectTimeout = 8000
            conn.readTimeout = timeoutMs
            conn.setRequestProperty("Accept", "application/json")
            if (token != null) conn.setRequestProperty("Authorization", "Bearer $token")
            if (body != null) {
                conn.doOutput = true
                conn.setRequestProperty("Content-Type", "application/json")
                conn.outputStream.use { it.write(body.toString().toByteArray()) }
            }
            val status = conn.responseCode
            val text = (if (status in 200..299) conn.inputStream else conn.errorStream)
                ?.bufferedReader()?.use { it.readText() }.orEmpty().ifBlank { "{}" }
            val json = JSONObject(text)
            if (status !in 200..299) {
                val err = json.optJSONObject("error")
                throw ApiException(
                    err?.optString("code") ?: "http_$status",
                    err?.optString("message") ?: "Request failed ($status)",
                    err
                )
            }
            return json
        } finally {
            conn.disconnect()
        }
    }

    internal fun auth(json: JSONObject): AuthResult {
        val u = json.getJSONObject("user")
        return AuthResult(
            json.getString("token"),
            u.getString("name"),
            u.getString("email"),
            if (u.isNull("plan")) null else u.getString("plan"),
            u.optBoolean("isAdmin", false)
        )
    }

    fun signup(name: String, email: String, password: String): AuthResult =
        auth(call("POST", "/api/auth/signup",
            JSONObject().put("name", name).put("email", email).put("password", password)))

    fun login(email: String, password: String): AuthResult =
        auth(call("POST", "/api/auth/login",
            JSONObject().put("email", email).put("password", password)))

    fun setPlan(token: String, plan: String) {
        call("PUT", "/api/subscription", JSONObject().put("plan", plan), token)
    }

    /** Changes the signed-in account's password. Throws ApiException("invalid_credentials") if [current] is wrong. */
    fun changePassword(token: String, current: String, new: String) {
        call("PUT", "/api/me/password", JSONObject().put("currentPassword", current).put("newPassword", new), token)
    }

    /** How many Premium (Google) checks are left today (GET /api/quota). */
    fun quota(token: String): GoogleQuota = quotaAndStatus(token).first

    /** The quota plus whether the server's Google check is switched on (false = no API key there). */
    fun quotaAndStatus(token: String): Pair<GoogleQuota, Boolean> {
        val json = call("GET", "/api/quota", token = token)
        return parseQuota(json.getJSONObject("quota")) to json.optBoolean("googleEnabled", true)
    }

    internal fun parseQuota(q: JSONObject) = GoogleQuota(
        unlimited = q.optBoolean("unlimited", false),
        limit = if (q.isNull("limit")) 0 else q.optInt("limit", 0),
        used = q.optInt("used", 0),
        resetsAt = if (q.isNull("resetsAt")) null else q.optLong("resetsAt")
    )

    // ---- Admin (the backend answers 403 "forbidden" to everyone who is not an admin)

    /** Is the Google API key set on the server, where from, and a masked hint ("AIza...x1Yz"). Never the full key. */
    fun googleKeyStatus(token: String): GoogleKeyStatus =
        parseGoogleKey(call("GET", "/api/admin/google-key", token = token))

    /** The server checks the key with Google before saving it: a wrong key throws ApiException (key_rejected...). */
    fun setGoogleKey(token: String, key: String): GoogleKeyStatus =
        parseGoogleKey(call("PUT", "/api/admin/google-key", JSONObject().put("key", key), token, WEB_RISK_TIMEOUT_MS))

    fun clearGoogleKey(token: String): GoogleKeyStatus =
        parseGoogleKey(call("DELETE", "/api/admin/google-key", token = token))

    internal fun parseGoogleKey(json: JSONObject): GoogleKeyStatus {
        val g = json.getJSONObject("google")
        return GoogleKeyStatus(
            active = g.optBoolean("active", false),
            source = g.optString("source", "none"),
            hint = if (g.isNull("hint")) null else g.optString("hint")
        )
    }

    /** Every account in the database, oldest first. */
    fun adminUsers(token: String): List<AdminUser> =
        parseAdminUsers(call("GET", "/api/admin/users", token = token))

    /** Sets any account's plan; returns the updated account (scanCount is not part of this reply). */
    fun adminSetPlan(token: String, userId: String, plan: String): AdminUser =
        parseAdminUser(
            call("PUT", "/api/admin/users/${java.net.URLEncoder.encode(userId, "UTF-8")}/plan",
                JSONObject().put("plan", plan), token).getJSONObject("user")
        )

    /** Admin sets a new password for any account. The old password is not needed; the server refuses non-admins (403). */
    fun adminSetPassword(token: String, userId: String, newPassword: String) {
        call("PUT", "/api/admin/users/${java.net.URLEncoder.encode(userId, "UTF-8")}/password",
            JSONObject().put("newPassword", newPassword), token)
    }

    internal fun parseAdminUsers(json: JSONObject): List<AdminUser> {
        val arr = json.getJSONArray("users")
        return (0 until arr.length()).map { parseAdminUser(arr.getJSONObject(it)) }
    }

    internal fun parseAdminUser(u: JSONObject) = AdminUser(
        id = u.getString("id"),
        name = u.optString("name"),
        email = u.getString("email"),
        plan = if (u.isNull("plan")) null else u.getString("plan"),
        isAdmin = u.optBoolean("isAdmin", false),
        scanCount = u.optInt("scanCount", 0),
        createdAt = u.optLong("createdAt", 0L)
    )

    /** Google Web Risk check of a link, or of every link in a message, through the backend. */
    fun webRiskCheck(token: String, text: String, timeoutMs: Int = WEB_RISK_TIMEOUT_MS): WebRiskResult =
        parseWebRisk(call("POST", "/api/scans/webrisk", JSONObject().put("text", text), token, timeoutMs))

    internal fun parseWebRisk(json: JSONObject): WebRiskResult {
        val results = json.getJSONArray("results")
        val reasons = (0 until results.length()).map { i ->
            val r = results.getJSONObject(i)
            val threats = r.getJSONArray("threats")
            val listed = threats.length() > 0
            val verdict = if (listed) {
                "Google lists it as " + (0 until threats.length()).joinToString(" and ") { threats.getString(it) }
            } else {
                "not on Google's list of dangerous sites"
            }
            "${r.getString("url")}: $verdict" to listed
        }
        return WebRiskResult(
            json.getBoolean("isDangerous"),
            json.getJSONObject("scan").getString("details"),
            reasons,
            json.optJSONObject("quota")?.let { parseQuota(it) }
        )
    }
}
