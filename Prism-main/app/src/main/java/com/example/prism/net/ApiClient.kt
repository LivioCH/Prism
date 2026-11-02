package com.example.prism.net

import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

class ApiException(val code: String, message: String) : Exception(message)

data class AuthResult(val token: String, val name: String, val email: String, val plan: String?)

/** Minimal client for prism-backend. Calls block: run them on Dispatchers.IO. */
object ApiClient {
    // Reaches the PC's backend through `adb reverse tcp:3000 tcp:3000` (development only).
    const val BASE_URL = "http://localhost:3000"

    private fun call(method: String, path: String, body: JSONObject? = null, token: String? = null): JSONObject {
        val conn = URL(BASE_URL + path).openConnection() as HttpURLConnection
        try {
            conn.requestMethod = method
            conn.connectTimeout = 8000
            conn.readTimeout = 8000
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
                    err?.optString("message") ?: "Request failed ($status)"
                )
            }
            return json
        } finally {
            conn.disconnect()
        }
    }

    private fun auth(json: JSONObject): AuthResult {
        val u = json.getJSONObject("user")
        return AuthResult(
            json.getString("token"),
            u.getString("name"),
            u.getString("email"),
            if (u.isNull("plan")) null else u.getString("plan")
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
}
