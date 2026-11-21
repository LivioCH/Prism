package com.example.prism

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.prism.accessibility.AccessibilityServiceState

/**
 * Dashboard entry point for the accessibility service.
 *
 * Being installed is not the same as being enabled, so the dashboard reads the real state from
 * `Settings.Secure` (polled while visible) and passes it in as [enabled]. Tapping sends the user to
 * the system toggle.
 *
 * [warning] turns the card red: the user tried to open Auto-Protection while this was still off.
 */
@Composable
fun ScreenMonitoringCard(
    enabled: Boolean,
    warning: Boolean = false,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    val red = warning && !enabled

    val cardColor by animateColorAsState(
        targetValue = if (red) Color(0xFFFEF2F2) else Color.White,
        animationSpec = tween(250),
        label = "MonitoringCardColor"
    )
    val iconBg by animateColorAsState(
        targetValue = when {
            red -> Color(0xFFFECACA)
            enabled -> Color(0xFFF0FDF4)
            else -> Color(0xFFEFF6FF)
        },
        animationSpec = tween(250),
        label = "MonitoringIconColor"
    )

    Card(
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(20.dp),
        colors = CardDefaults.cardColors(containerColor = cardColor),
        border = if (red) BorderStroke(2.dp, Color(0xFFDC2626)) else null,
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
                    .background(iconBg, CircleShape),
                contentAlignment = Alignment.Center
            ) {
                Text(text = if (red) "⚠️" else if (enabled) "🛡️" else "👁️", fontSize = 18.sp)
            }

            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = "AI Screen Monitoring",
                    fontSize = 14.sp,
                    fontWeight = FontWeight.Bold,
                    color = if (red) Color(0xFFB91C1C) else Color(0xFF111827)
                )
                Text(
                    text = when {
                        red -> "Turn this on first to use Auto-Protection"
                        enabled -> "Watching LINE, WhatsApp & browsers"
                        else -> "Turn on to detect links automatically"
                    },
                    fontSize = 12.sp,
                    color = when {
                        red -> Color(0xFFDC2626)
                        enabled -> Color(0xFF16A34A)
                        else -> Color(0xFF6B7280)
                    }
                )
            }

            Box(
                modifier = Modifier
                    .background(
                        color = when {
                            enabled -> Color(0xFFF0FDF4)
                            red -> Color(0xFFDC2626)
                            else -> Color(0xFF2563EB)
                        },
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
