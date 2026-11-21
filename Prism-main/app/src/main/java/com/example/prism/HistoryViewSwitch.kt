package com.example.prism

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/** The two views of the History tab. */
const val HISTORY_VIEW_SCANS = "scans"
const val HISTORY_VIEW_SITES = "sites"

/** Label of the second option, with how many sites are on the two lists. */
internal fun sitesOptionLabel(trusted: Int, blocked: Int): String =
    if (trusted + blocked == 0) "Trusted & blocked" else "Trusted & blocked (${trusted + blocked})"

/** Two-option switch at the top of the History tab: "Scan history" or "Trusted & blocked". */
@Composable
fun HistoryViewSwitch(selected: String, trustedCount: Int, blockedCount: Int, onSelect: (String) -> Unit) {
    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Option("Scan history", selected == HISTORY_VIEW_SCANS, Modifier.weight(1f)) { onSelect(HISTORY_VIEW_SCANS) }
        Option(sitesOptionLabel(trustedCount, blockedCount), selected == HISTORY_VIEW_SITES, Modifier.weight(1f)) { onSelect(HISTORY_VIEW_SITES) }
    }
}

@Composable
private fun Option(label: String, selected: Boolean, modifier: Modifier, onClick: () -> Unit) {
    Box(
        modifier = modifier
            .height(42.dp)
            .background(if (selected) Color(0xFF2563EB) else Color.White, RoundedCornerShape(12.dp))
            .clickable(onClick = onClick),
        contentAlignment = Alignment.Center
    ) {
        Text(
            text = label,
            fontSize = 13.sp,
            fontWeight = FontWeight.Medium,
            color = if (selected) Color.White else Color(0xFF374151)
        )
    }
}
