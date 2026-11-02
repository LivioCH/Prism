package com.example.prism

enum class ThreatLevel {
    SAFE, WARNING, DANGER
}

enum class ScanType {
    URL, PHONE, MESSAGE
}

enum class SubscriptionPlan {
    FREE, PLUS
}

data class ScanResult(
    val id: String,
    val type: ScanType,
    val content: String,
    val threat: ThreatLevel,
    val timestamp: Long = System.currentTimeMillis(),
    val details: String,
    // Why this verdict was given (empty for older/placeholder scans)
    val reasons: List<ScanReason> = emptyList(),
    // ML percentage / notes shown above the reasons in the popup
    val infoLines: List<String> = emptyList()
)