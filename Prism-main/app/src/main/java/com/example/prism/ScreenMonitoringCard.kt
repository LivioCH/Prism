package com.example.prism

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.prism.accessibility.AccessibilityServiceState
import kotlinx.coroutines.delay

/**
 * Dashboard entry point for the accessibility service.
 *
 * Being installed is not the same as being enabled, so this card reflects the real state from
 * `Settings.Secure` (polled while visible) and sends the user to the system toggle when tapped.
 */
@Composable
fun ScreenMonitoringCard(modifier: Modifier = Modifier) {
    val context = LocalContext.current
    var enabled by remember { mutableStateOf(AccessibilityServiceState.isEnabled(context)) }

    LaunchedEffect(Unit) {
        while (true) {
            enabled = AccessibilityServiceState.isEnabled(context)
            delay(1500L)
        }
    }

    Card(
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(20.dp),
        colors = CardDefaults.cardColors(containerColor = Color.White),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .clickable(enabled = !enabled) { AccessibilityServiceState.openSettings(context) }
                .padding(16.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Box(
                modifier = Modifier
                    .size(40.dp)
                    .background(
                        if (enabled) Color(0xFFF0FDF4) else Color(0xFFEFF6FF),
                        CircleShape
                    ),
                contentAlignment = Alignment.Center
            ) {
                Text(text = if (enabled) "🛡️" else "👁️", fontSize = 18.sp)
            }

            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = "AI Screen Monitoring",
                    fontSize = 14.sp,
                    fontWeight = FontWeight.Bold,
                    color = Color(0xFF111827)
                )
                Text(
                    text = if (enabled) {
                        "Watching LINE, WhatsApp & browsers"
                    } else {
                        "Turn on to detect links automatically"
                    },
                    fontSize = 12.sp,
                    color = if (enabled) Color(0xFF16A34A) else Color(0xFF6B7280)
                )
            }

            Box(
                modifier = Modifier
                    .background(
                        color = if (enabled) Color(0xFFF0FDF4) else Color(0xFF2563EB),
                        shape = RoundedCornerShape(100.dp)
                    )
                    .clickable { AccessibilityServiceState.openSettings(context) }
                    .padding(horizontal = 12.dp, vertical = 6.dp)
            ) {
                Text(
                    text = if (enabled) "ACTIVE" else "ENABLE",
                    fontSize = 11.sp,
                    fontWeight = FontWeight.Bold,
                    color = if (enabled) Color(0xFF16A34A) else Color.White
                )
            }
        }
    }
}
