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

    @Test
    fun phoneUsesHeuristicsOnlyAndSaysSo() {
        val r = ManualScanAnalyzer.analyze("+225 07 12 34 56 78", model)
        assertEquals(ScanType.PHONE, r.kind)
        assertTrue(r.threat != ThreatLevel.SAFE)
        assertTrue(r.infoLines.any { it.contains("啟發式") && it.contains("非官方資料庫") })
        assertTrue(r.urlResults.isEmpty())
        assertEquals(ThreatLevel.SAFE, ManualScanAnalyzer.analyze("0912-345-678", model).threat)
        assertTrue(ManualScanAnalyzer.analyze("12345", model).threat != ThreatLevel.SAFE)
    }

    // ---- Taiwan phone heuristics

    private fun phone(s: String) = ManualScanAnalyzer.analyze(s, model)
    private fun text(s: String) = ManualScanAnalyzer.analyze(s, model)

    @Test
    fun validTaiwanNumbersAreSafe() {
        for (n in listOf("0912345678", "0912-345-678", "0912 345 678", "(02) 2345-6789", "02-23456789", "037-123456", "0826-12345", "049-2345678"))
            assertEquals("$n", ThreatLevel.SAFE, phone(n).threat)
    }

    @Test
    fun plus886FakeLocalIsFlagged() {
        val r = phone("+886912345678")
        assertEquals(ScanType.PHONE, r.kind)
        assertTrue(r.threat != ThreatLevel.SAFE)
        assertTrue(r.reasons.any { it.rule == "fake_local_intl" && it.detail.contains("國際冒充本地號碼") })
        assertTrue(r.infoLines.contains("此為啟發式判斷，非官方資料庫"))
    }

    @Test
    fun foreignAndOddNumbersAreSuspicious() {
        val a = phone("+1 900 0000")
        assertTrue(a.threat != ThreatLevel.SAFE)
        assertTrue(a.reasons.any { it.rule == "foreign_number" })
        assertTrue(a.reasons.any { it.rule == "odd_pattern" })
        assertTrue(phone("+44 20 7946 0958").reasons.any { it.rule == "foreign_number" })
        assertTrue(phone("1234").threat != ThreatLevel.SAFE)                // too short
        assertTrue(phone("1234567890123456").reasons.any { it.rule == "too_long" })
        assertTrue(phone("0000000000").reasons.any { it.rule == "odd_pattern" })
        assertTrue(phone("0123456789").threat != ThreatLevel.DANGER)       // weak signals alone never reach DANGEROUS
    }

    // ---- Traditional Chinese scam wording

    @Test
    fun harmlessMessageIsSafe() {
        val r = text("明天見面嗎")
        assertEquals(ThreatLevel.SAFE, r.threat)
        assertTrue(r.reasons.all { it.rule == "no_issues" })
    }

    @Test
    fun badLinkPlusWordingIsDangerous() {
        val r = text("您的帳號異常，請立即點擊 http://plurebo-verify.xyz 驗證")
        assertEquals(ThreatLevel.DANGER, r.threat)
        assertTrue(r.reasons.any { it.rule == "scam_account_threat" && it.detail.contains("帳號異常") })
        assertTrue(r.reasons.any { it.rule == "scam_urgency" && it.detail.contains("立即") })
        assertTrue(r.reasons.any { it.rule == "scam_words_with_link" })
    }

    @Test
    fun wordingWithoutLinkIsSuspiciousNotDangerous() {
        val prize = text("恭喜中獎，請提供信用卡領取")
        assertEquals(ThreatLevel.WARNING, prize.threat)
        assertTrue(prize.urlResults.isEmpty())
        assertTrue(prize.reasons.any { it.rule == "scam_prize_bait" })
        assertEquals(ThreatLevel.WARNING, text("您的帳號異常，請立即處理").threat)   // 2 categories, no URL
        assertEquals(ThreatLevel.SAFE, text("我的包裹到了嗎").threat)                // one weak category alone
    }

    @Test
    fun manyStrongCategoriesWithoutLinkCanBeDangerous() {
        assertEquals(ThreatLevel.DANGER, text("帳號異常需身分驗證，否則中獎退款作廢，請輸入密碼").threat)
    }

    @Test
    fun cleanLinkWithWordingKeepsLinkVerdictAndWordingVerdict() {
        val r = text("包裹無法配送，請見 https://www.google.com")
        assertEquals(1, r.urlResults.size)
        assertEquals(ThreatLevel.SAFE, r.urlResults[0].threat)
        assertTrue(r.threat != ThreatLevel.DANGER)
    }
}
