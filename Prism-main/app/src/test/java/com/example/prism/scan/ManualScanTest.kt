package com.example.prism.scan

import com.example.prism.ScanType
import com.example.prism.ThreatLevel
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class ManualScanTest {
    private val model = UrlMlModel.fromJson(File("src/main/assets/url_model.json").readText())

    @Test
    fun printFeaturesAndProbability() {
        for (u in listOf(
            "http://185.220.101.45/login",
            "https://pontosapontamentolu.com/gclid/=/c/?gclid=abcdef",
            "https://www.google.com",
            "en.tldp.org/HOWTO/Secure-POP+SSH.html"
        )) {
            val f = model.extract(u)
            val feats = FeatureExtractor.FEATURE_NAMES.indices.joinToString(", ") { "${FeatureExtractor.FEATURE_NAMES[it]}=${f[it]}" }
            println("ML_TEST $u\nML_TEST   $feats\nML_TEST   probability=${model.predictFeatures(f)}")
        }
    }

    @Test
    fun featuresMatchSpec() {
        val f = model.extract("http://185.220.101.45/login")
        // len 27, host 14, dots 3, hyphens 0, digits 11, special 0, slashes 3, ip 1, at 0, subdomains 2, tld "45" no, keyword yes
        assertEquals(27.0, f[0], 0.0); assertEquals(14.0, f[1], 0.0); assertEquals(3.0, f[2], 0.0)
        assertEquals(11.0, f[4], 0.0); assertEquals(3.0, f[6], 0.0); assertEquals(1.0, f[7], 0.0)
        assertEquals(2.0, f[9], 0.0); assertEquals(1.0, f[11], 0.0); assertEquals(0.4074, f[12], 0.0); assertEquals(0.0, f[13], 0.0)
    }

    @Test
    fun kindIsDetected() {
        assertEquals(ScanType.PHONE, ManualScanAnalyzer.detectKind("+886 912 345 678"))
        assertEquals(ScanType.URL, ManualScanAnalyzer.detectKind("185.220.101.45"))
        assertEquals(ScanType.URL, ManualScanAnalyzer.detectKind("https://www.google.com"))
        assertEquals(ScanType.MESSAGE, ManualScanAnalyzer.detectKind("恭喜中獎，請點擊連結 http://a.xyz/x"))
    }

    @Test
    fun urlVerdictIsTheWorseOfMlAndHeuristics() {
        val r = ManualScanAnalyzer.analyze("http://185.220.101.45/login", model)
        assertEquals(ScanType.URL, r.kind)
        assertTrue(r.threat != ThreatLevel.SAFE)
        assertTrue(r.infoLines.first().startsWith("ML:"))
        assertTrue(r.reasons.any { it.rule == "ip_host" })
        val g = ManualScanAnalyzer.analyze("https://www.google.com", model)
        assertEquals(ThreatLevel.SAFE, g.threat)
    }

    @Test
    fun textScansEveryUrlAndScamWords() {
        val r = ManualScanAnalyzer.analyze("【緊急】您的帳號異常，請立即驗證 http://secure-login.xyz/a 或 https://www.google.com", model)
        assertEquals(ScanType.MESSAGE, r.kind)
        assertEquals(2, r.urlResults.size)
        assertTrue(r.reasons.any { it.rule == "scam_urgency" })
        assertEquals(ThreatLevel.DANGER, r.threat)
        assertEquals(ThreatLevel.SAFE, ManualScanAnalyzer.analyze("明天下午三點開會", model).threat)
    }

    // ---- Phone numbers (libphonenumber, home region TW)

    init { PhoneTestSetup.init() }

    private fun phone(s: String) = ManualScanAnalyzer.analyze(s, model)
    private fun text(s: String) = ManualScanAnalyzer.analyze(s, model)

    @Test
    fun phoneUsesHeuristicsOnlyAndSaysSo() {
        val r = phone("+225 07 12 34 56 78")
        assertEquals(ScanType.PHONE, r.kind)
        assertTrue(r.urlResults.isEmpty())
        assertTrue(r.infoLines.contains("This is a heuristic judgement, not an official database"))
    }

    @Test
    fun validTaiwanNumbersAreSafe() {
        for (n in listOf("0912345678", "0912-345-678", "0912 345 678", "(02) 2345-6789", "02-23456789", "037-123456"))
            assertEquals(n, ThreatLevel.SAFE, phone(n).threat)
    }

    @Test
    fun taiwanNumbersAreSafeInLocalAndInternationalFormat() {
        // +886 followed by a Taiwan number is simply the valid international form of the same number
        for (n in listOf("0912345678", "+886912345678", "+886 912 345 678", "+886-912-345-678", "00886912345678", "+886 2 2345 6789")) {
            val r = phone(n)
            assertEquals(n, ThreatLevel.SAFE, r.threat)
            assertTrue(n, r.reasons.all { it.points == 0 })
        }
        val r = phone("+886912345678")
        assertEquals(ScanType.PHONE, r.kind)
        assertTrue(r.reasons.none { it.rule == "fake_local_intl" })
        assertTrue(r.infoLines.contains("Number region: Taiwan (TW)"))
        assertTrue(r.infoLines.contains("This is a heuristic judgement, not an official database"))
    }

    @Test
    fun validNumbersFromAnyCountryAreSafe() {
        // The user's own Indonesian mobile number, plus US, UK, Japan and Singapore examples
        for (n in listOf("+62 812 3456 7890", "+62 821-2345-6789", "+1 202 555 0143", "+44 20 7946 0958", "+81 3 1234 5678", "+65 6123 4567")) {
            val r = phone(n)
            assertEquals(n, ThreatLevel.SAFE, r.threat)
            assertTrue(n, r.reasons.all { it.points == 0 })
        }
    }

    @Test
    fun foreignNumberShowsItsRegionAsNeutralInfo() {
        val id = phone("+62 812 3456 7890")
        assertTrue(id.infoLines.contains("Number region: Indonesia (ID)"))
        assertTrue(id.reasons.any { it.rule == "no_issues" && it.detail.contains("Indonesia (ID)") })
        assertTrue(phone("+1 202 555 0143").infoLines.contains("Number region: United States (US)"))
        assertTrue(phone("+44 20 7946 0958").infoLines.contains("Number region: United Kingdom (GB)"))
        assertTrue(phone("+1 202 555 0143").reasons.none { it.rule == "foreign_number" || it.rule == "risky_country" })
        assertTrue(phone("+225 07 12 34 56 78").reasons.none { it.points > 0 })   // valid Ivory Coast number is not penalised either
    }

    @Test
    fun localFormatNumbersFromOtherCountriesAreNeverDangerous() {
        // A friend's Indonesian number written locally (no country code) cannot be confirmed against TW: stays SAFE
        for (n in listOf("081234567890", "0812-3456-7890", "0812 3456 7890", "08123456789")) {
            val r = phone(n)
            assertEquals(n, ThreatLevel.SAFE, r.threat)
            assertTrue(n, r.reasons.all { it.points == 0 })
        }
        val note = phone("081234567890").reasons.first { it.rule == "unconfirmed" }
        assertTrue(note.detail.contains("Cannot confirm the country code"))
        assertEquals(ThreatLevel.SAFE, phone("+62 812 3456 7890").threat)
        assertEquals(ThreatLevel.SAFE, phone("+628123456789").threat)
    }

    @Test
    fun onlyClearBadSignalsRaiseAPhoneVerdict() {
        // letters / odd characters
        for (n in listOf("abc123", "12ab34567")) {
            val r = ManualScanAnalyzer.analyze(n, model)
            assertEquals(n, ScanType.PHONE, r.kind)
            assertEquals(n, ThreatLevel.WARNING, r.threat)
            assertTrue(n, r.reasons.any { it.rule == "odd_chars" })
        }
        assertEquals(ThreatLevel.WARNING, PhoneAnalyzer.analyze("+62 812 abc 7890").threat)    // letters inside a spaced number
        // absurd length: fewer than 6 or more than 17 digits
        for (n in listOf("12345", "1234", "123456789012345678")) {
            val r = phone(n)
            assertEquals(n, ThreatLevel.WARNING, r.threat)
            assertTrue(n, r.reasons.any { it.rule == "absurd_length" })
        }
        // repeated / sequential digits, VoIP, short-but-plausible numbers are NOT bad signals by themselves
        for (n in listOf("0000000000", "0123456789", "1234567")) assertEquals(n, ThreatLevel.SAFE, phone(n).threat)
        // weak signals never reach DANGER, even when combined
        assertEquals(ThreatLevel.WARNING, ManualScanAnalyzer.analyze("abc1234", model).threat)
    }

    @Test
    fun premiumRateIsAHighSignal() {
        val uk = phone("+44 909 879 0000")
        val us = phone("+1 900 234 5678")
        for (r in listOf(uk, us)) {
            assertTrue(r.reasons.any { it.rule == "premium_rate" && it.points >= 40 })
            assertEquals(ThreatLevel.DANGER, r.threat)
        }
        // 900 + exchange starting with 1 is not a real US number, but the premium prefix is still flagged
        val fake = phone("+1 900 123 4567")
        assertTrue(fake.reasons.any { it.rule == "premium_rate" && it.points >= 40 })
        assertEquals(ThreatLevel.DANGER, fake.threat)
    }

    // ---- Traditional-Chinese scam wording (category based)

    @Test
    fun messagesWithoutSignalsAreSafe() {
        for (t in listOf("明天下午三點開會", "這週有空見面嗎？記得帶資料", "晚上一起吃飯嗎", "Hello, see you tomorrow")) {
            val r = text(t)
            assertEquals(t, ThreatLevel.SAFE, r.threat)
            assertTrue(t, r.reasons.all { it.rule == "no_issues" })
        }
    }

    @Test
    fun badLinkPlusWordingIsDangerous() {
        val r = text("您的帳號異常，請立即點擊 http://plurebo-verify.xyz 重新驗證")
        assertEquals(ThreatLevel.DANGER, r.threat)
        assertTrue(r.reasons.any { it.rule == "scam_account_threat" && it.detail.contains("帳號異常") && it.detail.contains("重新驗證") })
        assertTrue(r.reasons.any { it.rule == "scam_urgency" && it.detail.contains("立即") })
        assertTrue(r.reasons.any { it.rule == "scam_words_with_link" })
        assertTrue(r.reasons.all { it.detail.none { c -> c in '\u4e00'..'\u9fff' } || it.rule.startsWith("scam_") })
    }

    @Test
    fun twoHighRiskCategoriesTogetherAreDangerousWithoutAnyLink() {
        val r = text("恭喜中獎！請提供信用卡與手續費領取獎金")
        assertEquals(ThreatLevel.DANGER, r.threat)
        assertTrue(r.urlResults.isEmpty())
        assertTrue(r.reasons.any { it.rule == "scam_prize_bait" })
        assertTrue(r.reasons.any { it.rule == "scam_money" && it.detail.contains("手續費") })
        assertTrue(r.reasons.any { it.rule == "scam_combined" })
        assertEquals(ThreatLevel.DANGER, text("帳號異常需身分驗證，否則中獎退款作廢，請輸入密碼").threat)
    }

    @Test
    fun credentialRequestWithUrgencyIsDangerous() {
        val r = text("請立即輸入驗證碼")
        assertEquals(ThreatLevel.DANGER, r.threat)
        assertTrue(r.reasons.any { it.rule == "scam_credentials_urgent" })
        assertEquals(ThreatLevel.WARNING, text("請輸入驗證碼").threat)           // credentials alone: suspicious only
    }

    @Test
    fun parcelFeeMessageWithLinkIsFlagged() {
        val r = text("包裹配送失敗，請補繳 NT\$45：http://post-tw-pay.top/pay")
        assertTrue(r.threat != ThreatLevel.SAFE)
        assertTrue(r.reasons.any { it.rule == "scam_parcel" })
        assertTrue(r.reasons.any { it.rule == "scam_money" && it.detail.contains("補繳") })
        assertEquals(1, r.urlResults.size)
    }

    @Test
    fun oneCategoryAloneIsSuspiciousButNeverDangerous() {
        for (t in listOf("limited time 立即領取", "請盡快回覆", "恭喜中獎", "您的帳號異常", "我的包裹到了嗎", "需要匯款嗎")) {
            assertEquals(t, ThreatLevel.WARNING, text(t).threat)
        }
        assertEquals(ThreatLevel.WARNING, text("limited time 立即領取").threat)
    }

    @Test
    fun cleanLinkWithWordingKeepsLinkVerdictAndWordingVerdict() {
        val r = text("包裹無法配送，請見 https://www.google.com")
        assertEquals(1, r.urlResults.size)
        assertEquals(ThreatLevel.SAFE, r.urlResults[0].threat)
        assertEquals(ThreatLevel.WARNING, r.threat)
    }

    @Test
    fun phraseListsAreConstantsThatCanBeExtended() {
        assertEquals(6, ManualScanAnalyzer.SCAM_CATEGORIES.size)
        assertTrue(ManualScanAnalyzer.SCAM_CATEGORIES.all { it.phrases.isNotEmpty() })
        assertTrue("限時" in ManualScanAnalyzer.URGENCY.phrases && "保證金" in ManualScanAnalyzer.MONEY.phrases)
        assertTrue(text("需要匯款嗎").infoLines.any { it.startsWith("Word-based detection is a signal") })
    }

    // ---- English scam wording (bilingual phrase lists)

    @Test
    fun englishAccountSecurityScamIsDangerous() {
        val r = text("Amazon: Unauthorized sign-in detected on your account. Your security code is 482913. Click here immediately to verify, or your account will be locked.")
        assertEquals(ThreatLevel.DANGER, r.threat)
        assertTrue(r.reasons.any { it.rule == "scam_account_threat" && it.detail.contains("unauthorized sign-in") })
        assertTrue(r.reasons.any { it.rule == "scam_credentials" && it.detail.contains("security code") && it.detail.contains("click here") })
        assertTrue(r.reasons.any { it.rule == "scam_urgency" && it.detail.contains("immediately") })
    }

    @Test
    fun englishRenewalMessageWithDomainIsFlagged() {
        val r = text("Xfinity: your plan will expire today. Act now and renew here: http://xfinity-renew.net")
        assertTrue(r.threat != ThreatLevel.SAFE)
        assertTrue(r.reasons.any { it.rule == "scam_urgency" && it.detail.contains("act now") })
        assertTrue(r.reasons.any { it.rule == "scam_money" && it.detail.contains("renew") })
        assertEquals(1, r.urlResults.size)
    }

    @Test
    fun ordinaryEnglishAndChineseChatStaysSafe() {
        for (t in listOf("Hey, are you still on for lunch tomorrow?", "記得明天帶資料", "Packages are stacked in the hallway", "See you at the meeting at noon"))
            assertEquals(t, ThreatLevel.SAFE, text(t).threat)
    }

    @Test
    fun englishMatchingIsCaseInsensitiveAndWholeWordOnly() {
        assertTrue(ManualScanAnalyzer.phraseMatches("ACT NOW before it ends", "act now"))
        assertTrue(ManualScanAnalyzer.phraseMatches("Please   act\tnow", "act now"))
        assertTrue(ManualScanAnalyzer.phraseMatches("Urgent!", "urgent"))
        assertTrue(!ManualScanAnalyzer.phraseMatches("Packages are here", "package"))
        assertTrue(!ManualScanAnalyzer.phraseMatches("a nonurgent matter", "urgent"))
        assertTrue(ManualScanAnalyzer.phraseMatches("請立即處理", "立即"))                       // Chinese stays a substring match
    }

    @Test
    fun chineseScamWithBadLinkIsStillDangerous() {
        assertEquals(ThreatLevel.DANGER, text("您的帳號異常，請立即驗證 http://plurebo-verify.xyz").threat)
    }

    @Test
    fun oneEnglishCategoryAloneIsSuspiciousNotDangerous() {
        assertEquals(ThreatLevel.WARNING, text("Limited time offer, see you there").threat)
        assertEquals(ThreatLevel.WARNING, text("Congratulations on your new job!").threat)
    }
}
