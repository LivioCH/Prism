package com.example.prism

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
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/** Short label for the Google link check: "ON" / "OFF", or nothing while it is unknown (offline). */
internal fun googleBadgeText(active: Boolean?): String? = when (active) {
    true -> "Google check: ON"
    false -> "Google check: OFF"
    null -> null
}

/** Text of the chip in the top header. An admin is told where to fix it; everyone else just sees the state. */
internal fun googleHeaderText(active: Boolean?, isAdmin: Boolean): String? = when (active) {
    true -> "Google check: ON"
    false -> if (isAdmin) "Google API not connected · tap to set up" else "Google API not connected"
    null -> null
}

/**
 * Chip in the shared top header, so it is visible on every page. Used by manual scans AND Auto-Protection.
 * Green dot = Google answers; amber dot = the server has no (working) Google API key.
 * An admin can tap it to open the Google API key screen.
 */
@Composable
fun GoogleHeaderChip(active: Boolean?, isAdmin: Boolean, onClick: () -> Unit, modifier: Modifier = Modifier) {
    val text = googleHeaderText(active, isAdmin) ?: return
    val on = active == true
    Row(
        modifier = modifier
            .background(Color.White.copy(alpha = 0.18f), RoundedCornerShape(100.dp))
            .let { if (!on && isAdmin) it.clickable(onClick = onClick) else it }
            .padding(horizontal = 12.dp, vertical = 5.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(7.dp)
    ) {
        Box(Modifier.size(9.dp).background(if (on) Color(0xFF4ADE80) else Color(0xFFFBBF24), CircleShape))
        Text(text, fontSize = 11.sp, fontWeight = FontWeight.Bold, color = Color.White)
    }
}

/** Small pill next to the Manual Scan title: green when the Google link check is active, grey when it is not. */
@Composable
fun GoogleActivePill(active: Boolean?, modifier: Modifier = Modifier) {
    val text = googleBadgeText(active) ?: return
    val on = active == true
    Row(
        modifier = modifier
            .background(if (on) Color(0xFFDCFCE7) else Color(0xFFF3F4F6), RoundedCornerShape(100.dp))
            .padding(horizontal = 10.dp, vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(6.dp)
    ) {
        Box(Modifier.size(8.dp).background(if (on) Color(0xFF16A34A) else Color(0xFF9CA3AF), CircleShape))
        Text(text, fontSize = 11.sp, fontWeight = FontWeight.Bold, color = if (on) Color(0xFF15803D) else Color(0xFF6B7280))
    }
}

/** Settings card that says in words whether the Google link check works, and why not. */
@Composable
fun GoogleStatusCard(active: Boolean?) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(20.dp),
        colors = CardDefaults.cardColors(containerColor = Color.White),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp)
    ) {
        Column(Modifier.fillMaxWidth().padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.SpaceBetween, modifier = Modifier.fillMaxWidth()) {
                Text("🌐  Google link check", fontSize = 15.sp, fontWeight = FontWeight.Bold, color = Color(0xFF111827))
                GoogleActivePill(active)
            }
            Text(
                text = when (active) {
                    true -> "Active. Links you scan are also checked by Google Web Risk."
                    false -> "Not active. The server has no Google API key yet, so scans use the Normal scan only."
                    null -> "Unknown. Could not reach the server to ask."
                },
                fontSize = 12.sp, color = Color(0xFF6B7280)
            )
        }
    }
}
