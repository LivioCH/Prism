package com.example.prism

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.prism.net.GoogleQuota
import com.example.prism.scan.QuotaText

/**
 * Scan tab: the two scan engines and what is left of the Premium check.
 *
 *  - Normal scan: on the phone, every scan, for everyone.
 *  - Premium check: Google Web Risk for the links in a scan. Plus: unlimited. Free: a few a day;
 *    when they are used up the scan simply continues as a Normal scan.
 */
@Composable
fun ScanEngineStatus(
    isPlus: Boolean,
    quota: GoogleQuota?,
    quotaUnreachable: Boolean,
    premiumUnavailable: Boolean,
    onUpgrade: () -> Unit
) {
    val unlimited = quota?.unlimited ?: isPlus
    val exhausted = quota?.exhausted == true && !unlimited

    Column(modifier = Modifier.fillMaxWidth().padding(bottom = 16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        EngineRow(
            icon = "📱", title = "Normal scan", subtitle = "Runs on your phone",
            pill = "ALWAYS ON", pillBg = Color(0xFFDCFCE7), pillFg = Color(0xFF15803D)
        )

        val (pill, bg, fg) = when {
            premiumUnavailable -> Triple("UNAVAILABLE", Color(0xFFFEF3C7), Color(0xFFB45309))
            unlimited -> Triple("UNLIMITED", Color(0xFFF3E8FF), Color(0xFF7E22CE))
            quota == null && quotaUnreachable -> Triple("OFFLINE", Color(0xFFF3F4F6), Color(0xFF6B7280))
            quota == null -> Triple("…", Color(0xFFF3F4F6), Color(0xFF6B7280))
            exhausted -> Triple("0 LEFT", Color(0xFFFEE2E2), Color(0xFFB91C1C))
            quota.remaining <= 3 -> Triple(QuotaText.pill(quota).uppercase(), Color(0xFFFEF3C7), Color(0xFFB45309))
            else -> Triple(QuotaText.pill(quota).uppercase(), Color(0xFFF3E8FF), Color(0xFF7E22CE))
        }
        EngineRow(
            icon = "🌐", title = "Premium check",
            subtitle = if (premiumUnavailable) "Google unreachable, using Normal scan" else "Checks links with Google",
            pill = pill, pillBg = bg, pillFg = fg
        )

        if (exhausted) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(Color(0xFFFEF2F2), RoundedCornerShape(12.dp))
                    .padding(12.dp),
                verticalArrangement = Arrangement.spacedBy(4.dp)
            ) {
                Text(
                    text = "Premium check used up for today. Scans now use Normal scan only. " +
                        "Next one in ${QuotaText.resetsIn(quota?.resetsAt) ?: "a while"}.",
                    fontSize = 12.sp, color = Color(0xFFB91C1C)
                )
                if (!isPlus) {
                    Text(
                        text = "Upgrade to Plus for unlimited checks",
                        fontSize = 12.sp, fontWeight = FontWeight.Bold, color = Color(0xFF7E22CE),
                        modifier = Modifier.clickable { onUpgrade() }
                    )
                }
            }
        } else if (!unlimited && quota != null && !premiumUnavailable) {
            Text(
                text = "Free plan: ${quota.limit} Premium checks a day. Each scan with links uses one.",
                fontSize = 11.sp, color = Color(0xFF9CA3AF)
            )
        }
    }
}

@Composable
private fun EngineRow(icon: String, title: String, subtitle: String, pill: String, pillBg: Color, pillFg: Color) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        Box(modifier = Modifier.size(32.dp).background(Color(0xFFF3F4F6), CircleShape), contentAlignment = Alignment.Center) {
            Text(text = icon, fontSize = 15.sp)
        }
        Column(modifier = Modifier.weight(1f)) {
            Text(text = title, fontSize = 13.sp, fontWeight = FontWeight.Bold, color = Color(0xFF111827))
            Text(text = subtitle, fontSize = 11.sp, color = Color(0xFF6B7280))
        }
        Box(modifier = Modifier.background(pillBg, RoundedCornerShape(100.dp)).padding(horizontal = 10.dp, vertical = 4.dp)) {
            Text(text = pill, fontSize = 10.sp, fontWeight = FontWeight.Bold, color = pillFg)
        }
    }
}

/**
 * Badges at the top of a scan result: which engines produced it.
 * [engine]: "premium" | "limit" | "unavailable" | "no_links" | "cache" ("" = unknown, nothing is shown).
 */
@Composable
fun EngineChips(engine: String, quotaLine: String?) {
    if (engine.isEmpty()) return
    Column(modifier = Modifier.fillMaxWidth().padding(bottom = 12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
        Row(modifier = Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            if (engine == "cache") {
                Chip("💾 Saved result", Color(0xFFF3F4F6), Color(0xFF4B5563))
            } else {
                Chip("📱 Normal scan ✓", Color(0xFFEFF6FF), Color(0xFF1D4ED8))
                when (engine) {
                    "premium" -> Chip("🌐 Premium check ✓", Color(0xFFF3E8FF), Color(0xFF7E22CE))
                    "limit" -> Chip("🌐 Premium check used up", Color(0xFFFEE2E2), Color(0xFFB91C1C))
                    "unavailable" -> Chip("🌐 Premium check unavailable", Color(0xFFFEF3C7), Color(0xFFB45309))
                    else -> Chip("🌐 Premium check: no links", Color(0xFFF3F4F6), Color(0xFF6B7280))
                }
            }
        }
        if (quotaLine != null) Text(text = quotaLine, fontSize = 11.sp, color = Color(0xFF6B7280))
    }
}

@Composable
private fun Chip(text: String, bg: Color, fg: Color) {
    Box(modifier = Modifier.background(bg, RoundedCornerShape(100.dp)).padding(horizontal = 10.dp, vertical = 5.dp)) {
        Text(text = text, fontSize = 11.sp, fontWeight = FontWeight.Bold, color = fg, maxLines = 1)
    }
}
