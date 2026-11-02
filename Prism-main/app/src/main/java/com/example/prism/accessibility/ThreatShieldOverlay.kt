package com.example.prism.accessibility

import android.accessibilityservice.AccessibilityService
import android.content.Context
import android.content.res.ColorStateList
import android.graphics.Color
import android.graphics.PixelFormat
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.util.Log
import android.view.Gravity
import android.view.LayoutInflater
import android.view.View
import android.view.WindowManager
import android.widget.TextView
import com.example.prism.R
import com.example.prism.ThreatLevel

/** What the shield buttons do. The service supplies these callbacks. */
class ShieldActions(
    val onLeave: () -> Unit,
    val onContinue: (() -> Unit)? = null,
    val onTrust: (() -> Unit)? = null
)

/**
 * Full-screen "intervention overlay" (report section 2.2 step 4).
 *
 * Uses `TYPE_ACCESSIBILITY_OVERLAY`, which an accessibility service may add **without** the
 * `SYSTEM_ALERT_WINDOW` permission - the user already granted screen access. The window is not
 * focusable (so the keyboard is untouched) but it is touchable, which is what lets it sit above
 * the browser and block taps on the page underneath.
 *
 * All view work is marshalled onto the main thread because the service analyses URLs on a
 * background dispatcher.
 */
class ThreatShieldController(private val service: AccessibilityService) {

    private val windowManager =
        service.getSystemService(Context.WINDOW_SERVICE) as WindowManager
    private val mainHandler = Handler(Looper.getMainLooper())

    private var rootView: View? = null
    private var currentUrl: String? = null
    private var currentLevel: ThreatLevel? = null

    val isShowing: Boolean
        get() = rootView != null

    fun show(verdict: UrlVerdict, sourceLabel: String, actions: ShieldActions) {
        if (verdict.level == ThreatLevel.SAFE) return
        if (Looper.myLooper() != Looper.getMainLooper()) {
            mainHandler.post { show(verdict, sourceLabel, actions) }
            return
        }
        if (isShowing) {
            if (currentUrl == verdict.url && currentLevel == verdict.level) return
            dismiss()
        }

        val view = LayoutInflater.from(service).inflate(R.layout.prism_threat_shield, null)
        bind(view, verdict, sourceLabel, actions)

        val params = buildLayoutParams()
        if (!addView(view, params)) return

        rootView = view
        currentUrl = verdict.url
        currentLevel = verdict.level

        view.alpha = 0f
        view.animate().alpha(1f).setDuration(180L).start()
    }

    fun dismiss() {
        if (Looper.myLooper() != Looper.getMainLooper()) {
            mainHandler.post { dismiss() }
            return
        }
        val view = rootView ?: return
        rootView = null
        currentUrl = null
        currentLevel = null
        runCatching { windowManager.removeViewImmediate(view) }
    }

    fun destroy() = dismiss()

    // ---------------------------------------------------------------------------------------

    private fun addView(view: View, params: WindowManager.LayoutParams): Boolean =
        runCatching { windowManager.addView(view, params) }
            .onFailure { Log.e(TAG, "Unable to attach the shield overlay", it) }
            .isSuccess

    private fun buildLayoutParams(): WindowManager.LayoutParams =
        WindowManager.LayoutParams(
            WindowManager.LayoutParams.MATCH_PARENT,
            WindowManager.LayoutParams.MATCH_PARENT,
            WindowManager.LayoutParams.TYPE_ACCESSIBILITY_OVERLAY,
            WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN or
                WindowManager.LayoutParams.FLAG_LAYOUT_NO_LIMITS or
                WindowManager.LayoutParams.FLAG_HARDWARE_ACCELERATED,
            PixelFormat.TRANSLUCENT
        ).apply {
            gravity = Gravity.TOP or Gravity.START
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                layoutInDisplayCutoutMode =
                    WindowManager.LayoutParams.LAYOUT_IN_DISPLAY_CUTOUT_MODE_SHORT_EDGES
            }
            // Not focusable: the IME and back-key handling of the app underneath stay intact.
            flags = flags or WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE
        }

    private fun bind(
        view: View,
        verdict: UrlVerdict,
        sourceLabel: String,
        actions: ShieldActions
    ) {
        val isDanger = verdict.level == ThreatLevel.DANGER
        val accent = Color.parseColor(if (isDanger) "#DC2626" else "#D97706")
        val tint = ColorStateList.valueOf(accent)

        val badge = view.findViewById<TextView>(R.id.shield_badge)
        val icon = view.findViewById<TextView>(R.id.shield_icon)
        val source = view.findViewById<TextView>(R.id.shield_source)
        val title = view.findViewById<TextView>(R.id.shield_title)
        val subtitle = view.findViewById<TextView>(R.id.shield_subtitle)
        val urlBox = view.findViewById<TextView>(R.id.shield_url)
        val scoreValue = view.findViewById<TextView>(R.id.shield_score)
        val meterFill = view.findViewById<View>(R.id.shield_meter_fill)
        val reasons = view.findViewById<TextView>(R.id.shield_reasons)
        val primary = view.findViewById<TextView>(R.id.shield_primary)
        val secondary = view.findViewById<TextView>(R.id.shield_secondary)
        val tertiary = view.findViewById<TextView>(R.id.shield_tertiary)

        badge.text = if (isDanger) "PHISHING SHIELD" else "CAUTION"
        badge.backgroundTintList = tint

        source.text = sourceLabel
        icon.text = if (isDanger) "\uD83D\uDEA8" else "\u26A0\uFE0F"
        title.text = if (isDanger) "Dangerous link blocked" else "Suspicious link detected"
        subtitle.text = if (isDanger) {
            "Prism stopped this page before it could open. Nothing has been entered yet."
        } else {
            "This link shows the patterns of a phishing page. Check the address before you continue."
        }

        urlBox.text = verdict.url
        urlBox.backgroundTintList = ColorStateList.valueOf(
            Color.parseColor(if (isDanger) "#FEF2F2" else "#FEFCE8")
        )
        urlBox.setTextColor(Color.parseColor(if (isDanger) "#7F1D1D" else "#713F12"))

        scoreValue.text = "${verdict.score} / 100"
        scoreValue.setTextColor(accent)

        val weight = verdict.score.coerceIn(3, 100)
        (meterFill.layoutParams as? android.widget.LinearLayout.LayoutParams)?.let { params ->
            params.weight = weight.toFloat()
            meterFill.layoutParams = params
        }
        meterFill.backgroundTintList = tint

        val details = if (verdict.signals.isNotEmpty()) {
            verdict.signals.take(4).joinToString("\n") { "\u2022 ${it.detail}" }
        } else {
            "\u2022 ${verdict.reason}"
        }
        reasons.text = details

        primary.text = if (isDanger) "Back to safety" else "Leave this site"
        primary.backgroundTintList = tint
        primary.setOnClickListener {
            dismiss()
            actions.onLeave()
        }

        if (isDanger) {
            secondary.text = "I trust this site"
            secondary.setOnClickListener {
                dismiss()
                actions.onTrust?.invoke()
            }
            tertiary.visibility = View.GONE
        } else {
            secondary.text = "Continue anyway"
            secondary.setOnClickListener {
                dismiss()
                actions.onContinue?.invoke()
            }
            tertiary.text = "Always allow this site"
            tertiary.visibility = View.VISIBLE
            tertiary.setOnClickListener {
                dismiss()
                actions.onTrust?.invoke()
            }
        }

        // Swallow taps on the dimmed background so nothing reaches the page underneath.
        view.isClickable = true
        view.setOnClickListener { }
        view.contentDescription =
            if (isDanger) "Prism blocked a dangerous link" else "Prism warning for a suspicious link"
    }

    private companion object {
        const val TAG = "PrismShield"
    }
}
