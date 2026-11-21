package com.example.prism.scan

import android.content.Context
import com.example.prism.ScanReason
import com.example.prism.ScanType
import com.example.prism.ThreatLevel
import io.michaelrocks.libphonenumber.android.NumberParseException
import io.michaelrocks.libphonenumber.android.PhoneNumberUtil
import io.michaelrocks.libphonenumber.android.PhoneNumberUtil.PhoneNumberType
import io.michaelrocks.libphonenumber.android.Phonenumber.PhoneNumber
import java.util.Locale

/**
 * Phone number support for the whole world, built on Google libphonenumber, plus the signals that are
 * specific to the user's HOME REGION (default Taiwan). Offline; the metadata ships inside the library.
 */
object PhoneNumbers {
    const val DEFAULT_HOME_REGION = "TW"

    /** Region the user is "at home" in. Later this can come from the SIM card or the device locale. */
    @Volatile var homeRegion: String = DEFAULT_HOME_REGION

    @Volatile private var util: PhoneNumberUtil? = null

    fun init(context: Context) {
        if (util == null) util = PhoneNumberUtil.createInstance(context.applicationContext)
    }

    /** For unit tests, where there is no Android context. */
    fun init(instance: PhoneNumberUtil) { util = instance }

    internal fun get(): PhoneNumberUtil =
        util ?: error("PhoneNumbers.init(context) must be called before scanning phone numbers")
}

/**
 * Conservative phone check: "cannot be confirmed" is NOT "dangerous". A number is SAFE unless one of the
 * clear bad signals below is present. Only these signals may raise the verdict:
 *  - letters / unusual characters in the number            -> suspicious
 *  - absurd length (< 6 or > 17 digits)                    -> suspicious
 *  - premium-rate number                                   -> high (DANGEROUS)
 * Everything else, including a valid or unconfirmable number from any country, stays SAFE.
 */
object PhoneAnalyzer {
    private const val WARNING_AT = 25
    private const val DANGER_AT = 60
    const val NOTE = "This is a heuristic judgement, not an official database"
    const val UNCONFIRMED = "Cannot confirm the country code; stay alert if the call is unexpected"

    // Digits, spaces, hyphens, brackets, and a "+" only at the very start
    private val CLEAN = Regex("^[+]?[0-9()\\s-]+$")
    private val US_PREMIUM = Regex("^[+]?1(900|976)[0-9]{7}$")

    private fun regionName(region: String?): String =
        if (region == null) "International" else "${Locale("", region).getDisplayCountry(Locale.ENGLISH)} ($region)"

    private fun parseOrNull(util: PhoneNumberUtil, text: String, region: String): PhoneNumber? =
        try { util.parse(text, region) } catch (e: NumberParseException) { null }

    fun analyze(raw: String, homeRegion: String = PhoneNumbers.homeRegion): ManualScanOutcome {
        val util = PhoneNumbers.get()
        val reasons = mutableListOf<ScanReason>()
        fun add(rule: String, pts: Int, detail: String) {
            reasons += ScanReason(rule, detail, pts, if (pts >= 35) "high" else if (pts >= 15) "medium" else "low")
        }
        var regionInfo: String? = null

        // 1) Normalise: drop spaces, hyphens and brackets; "00" is the usual international prefix
        val text = raw.trim()
        var compact = text.filterNot { it.isWhitespace() || it == '-' || it == '(' || it == ')' }
        if (compact.startsWith("00")) compact = "+" + compact.drop(2)
        val international = compact.startsWith("+")
        val digitCount = compact.count { it.isDigit() }

        // 2) Allowed bad signals that need no parsing
        val clean = CLEAN.matches(text)
        if (!clean) add("odd_chars", 25, "Contains letters or unusual characters, which real phone numbers do not")
        if (digitCount < 6 || digitCount > 17) add("absurd_length", 25, "Absurd length: $digitCount digits")

        // 3) Parse. With a "+" it is international; without one it is tried against the home region first,
        //    and failing that as an international number. Failing both only means "cannot be confirmed".
        var number: PhoneNumber? = null
        if (clean) {
            number = parseOrNull(util, compact, homeRegion)?.takeIf { util.isValidNumber(it) }
            if (number == null && !international) {
                number = parseOrNull(util, "+$compact", homeRegion)?.takeIf { util.isValidNumber(it) }
            }
        }

        if (number != null) {
            val region = util.getRegionCodeForNumber(number)
            val type = util.getNumberType(number)
            regionInfo = "Number region: ${regionName(region)}"       // neutral information, never adds points
            if (type == PhoneNumberType.PREMIUM_RATE) add("premium_rate", 60, "Premium-rate number: calling can be very costly")
            if (reasons.isEmpty()) {
                val kind = when (type) {
                    PhoneNumberType.MOBILE -> "mobile"
                    PhoneNumberType.FIXED_LINE -> "landline"
                    PhoneNumberType.FIXED_LINE_OR_MOBILE -> "mobile or landline"
                    PhoneNumberType.TOLL_FREE -> "toll-free"
                    else -> "phone"
                }
                add("no_issues", 0, "Valid ${regionName(region)} $kind number")
            }
        } else if (clean && US_PREMIUM.matches(compact)) {
            // libphonenumber rejects some made-up US premium numbers, but the 900/976 prefix is still a costly one
            add("premium_rate", 60, "Premium-rate number (US 900/976): calling can be very costly")
        }
        // Could not be confirmed and nothing bad was found: neutral note only, no points
        if (number == null && reasons.none { it.points > 0 }) add("unconfirmed", 0, UNCONFIRMED)

        val score = minOf(100, reasons.sumOf { it.points })
        val threat = when {
            score >= DANGER_AT -> ThreatLevel.DANGER
            score >= WARNING_AT -> ThreatLevel.WARNING
            else -> ThreatLevel.SAFE
        }
        val sorted = reasons.sortedWith(compareByDescending<ScanReason> { when (it.severity) { "high" -> 3; "medium" -> 2; else -> 1 } }.thenByDescending { it.points })
        return ManualScanOutcome(ScanType.PHONE, threat, sorted, listOfNotNull(regionInfo, NOTE))
    }
}
