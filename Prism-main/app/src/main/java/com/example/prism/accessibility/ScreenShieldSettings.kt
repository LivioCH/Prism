package com.example.prism.accessibility

import android.content.Context

/**
 * Small preferences store for the screen shield itself. Detection data lives in the encrypted
 * Room database; only UI switches belong here.
 */
class ScreenShieldSettings(context: Context) {

    private val prefs = context.getSharedPreferences("prism_screen_shield", Context.MODE_PRIVATE)

    /** Master switch for the warning/blocking overlay. */
    var overlayEnabled: Boolean
        get() = prefs.getBoolean(KEY_OVERLAY, true)
        set(value) = prefs.edit().putBoolean(KEY_OVERLAY, value).apply()

    /** When true every app is monitored instead of the curated chat/browser list. */
    var monitorAllApps: Boolean
        get() = prefs.getBoolean(KEY_MONITOR_ALL, false)
        set(value) = prefs.edit().putBoolean(KEY_MONITOR_ALL, value).apply()

    private companion object {
        const val KEY_OVERLAY = "overlay_enabled"
        const val KEY_MONITOR_ALL = "monitor_all_apps"
    }
}
