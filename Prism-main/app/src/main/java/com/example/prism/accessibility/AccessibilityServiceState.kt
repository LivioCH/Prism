package com.example.prism.accessibility

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.provider.Settings

/**
 * Small helper around `Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES`.
 *
 * The dashboard uses this to show whether the screen shield is actually switched on - being
 * installed is not the same as being enabled, and users routinely forget the second step.
 */
object AccessibilityServiceState {

    fun isEnabled(context: Context): Boolean =
        isEnabled(context, PhishingDetectionService::class.java)

    fun isEnabled(context: Context, serviceClass: Class<*>): Boolean {
        if (PhishingDetectionService.isRunning()) return true

        val component = ComponentName(context, serviceClass)
        val fullName = component.flattenToString()
        val shortName = component.flattenToShortString()

        val enabledServices = Settings.Secure.getString(
            context.contentResolver,
            Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES
        ) ?: return false

        return enabledServices.split(':').any { entry ->
            entry.equals(fullName, ignoreCase = true) || entry.equals(shortName, ignoreCase = true)
        }
    }

    /** Opens the system accessibility list, falling back to the top-level settings screen. */
    fun openSettings(context: Context) {
        val direct = Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        val fallback = Intent(Settings.ACTION_SETTINGS)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        runCatching { context.startActivity(direct) }
            .recoverCatching { context.startActivity(fallback) }
    }
}
