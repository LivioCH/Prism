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
        assertTrue(r.reasons.any { it.rule == "scam_words" })
        assertEquals(ThreatLevel.DANGER, r.threat)
        assertEquals(ThreatLevel.SAFE, ManualScanAnalyzer.analyze("明天下午三點開會", model).threat)
    }

    @Test
    fun phoneUsesHeuristicsOnlyAndSaysSo() {
        val r = ManualScanAnalyzer.analyze("+225 07 12 34 56 78", model)
        assertEquals(ScanType.PHONE, r.kind)
        assertTrue(r.threat != ThreatLevel.SAFE)
        assertTrue(r.infoLines.any { it.contains("heuristic") && it.contains("official database") })
        assertTrue(r.urlResults.isEmpty())
        assertEquals(ThreatLevel.SAFE, ManualScanAnalyzer.analyze("0912-345-678", model).threat)
        assertTrue(ManualScanAnalyzer.analyze("12345", model).threat != ThreatLevel.SAFE)
    }
}
