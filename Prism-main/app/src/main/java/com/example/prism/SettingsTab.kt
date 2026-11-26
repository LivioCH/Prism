package com.example.prism

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/**
 * Settings page (menu > Settings): the two protection switches in one place.
 * Same rules as the Scan tab: Auto-Protection is for Plus members and needs AI Screen Monitoring.
 */
@Composable
fun SettingsTab(
    isPlus: Boolean,
    autoProtectionOn: Boolean,
    screenMonitoringEnabled: Boolean,
    monitoringWarning: Boolean,
    onAutoProtectionTap: () -> Unit,
    googleActive: Boolean? = null
) {
    Text(text = "Protection", fontSize = 18.sp, fontWeight = FontWeight.Bold, color = Color(0xFF111827))

    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(20.dp),
        colors = CardDefaults.cardColors(containerColor = Color.White),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp)
    ) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = if (isPlus) "🛡️  Auto-Protection" else "🔒  Auto-Protection",
                    fontSize = 15.sp, fontWeight = FontWeight.Bold, color = Color(0xFF111827)
                )
                Text(
                    text = when {
                        !isPlus -> "Members only. Tap to upgrade to Plus"
                        !screenMonitoringEnabled -> "Turn on AI Screen Monitoring first"
                        autoProtectionOn -> "On: links you open or copy are checked, with Google"
                        else -> "Off: only your manual scans are checked"
                    },
                    fontSize = 12.sp,
                    color = if (isPlus && !screenMonitoringEnabled) Color(0xFFDC2626) else Color(0xFF6B7280)
                )
            }
            // Tapping goes through the same rules as the Scan tab (upgrade / red warning / toggle)
            Switch(checked = autoProtectionOn, onCheckedChange = { onAutoProtectionTap() })
        }
    }

    // Screen monitoring only works for Plus (part of Auto-Protection), so Free does not see the card
    if (isPlus) ScreenMonitoringCard(enabled = screenMonitoringEnabled, warning = monitoringWarning)

    GoogleStatusCard(googleActive)
}
