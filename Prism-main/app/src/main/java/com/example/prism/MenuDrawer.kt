package com.example.prism

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.ModalDrawerSheet
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/** The three-line button in the top-left of the header. It opens [MenuDrawer]. */
@Composable
fun HamburgerButton(onClick: () -> Unit, modifier: Modifier = Modifier) {
    Box(
        modifier = modifier
            .size(40.dp)
            .background(Color.White.copy(alpha = 0.2f), RoundedCornerShape(12.dp))
            .clickable(onClick = onClick),
        contentAlignment = Alignment.Center
    ) {
        Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
            repeat(3) {
                Box(modifier = Modifier.width(18.dp).height(2.5.dp).background(Color.White, RoundedCornerShape(2.dp)))
            }
        }
    }
}

/**
 * Side menu: who is signed in (round avatar with the name beside it), then the options.
 * The Admin entry only exists for admins (the backend checks it again on every admin call).
 * [onNavigate] receives a tab name: "account", "settings", "privacy", "history" or "admin".
 */
@Composable
fun MenuDrawer(
    name: String,
    email: String,
    isPlus: Boolean,
    isAdmin: Boolean,
    activeTab: String,
    onNavigate: (String) -> Unit,
    onAbout: () -> Unit,
    onLogout: () -> Unit,
    googleActive: Boolean? = null
) {
    ModalDrawerSheet(drawerContainerColor = Color.White) {
        Column(modifier = Modifier.fillMaxWidth().verticalScroll(rememberScrollState())) {

            // --- Profile ---
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(
                        Brush.horizontalGradient(
                            if (isPlus) listOf(Color(0xFF9333EA), Color(0xFF2563EB)) else listOf(Color(0xFF2563EB), Color(0xFF1E40AF))
                        )
                    )
                    .padding(horizontal = 20.dp, vertical = 18.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(14.dp)
            ) {
                Box(
                    modifier = Modifier.size(56.dp).background(Color.White, CircleShape),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        text = name.trim().firstOrNull()?.uppercase() ?: "?",
                        fontSize = 24.sp, fontWeight = FontWeight.Bold, color = Color(0xFF2563EB)
                    )
                }
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = name.ifBlank { "Your account" },
                        fontSize = 18.sp, fontWeight = FontWeight.Bold, color = Color.White,
                        maxLines = 1, overflow = TextOverflow.Ellipsis
                    )
                    Text(
                        text = email, fontSize = 12.sp, color = Color(0xFFDBEAFE),
                        maxLines = 1, overflow = TextOverflow.Ellipsis
                    )
                    Spacer(modifier = Modifier.height(6.dp))
                    Box(
                        modifier = Modifier
                            .background(Color.White.copy(alpha = 0.2f), RoundedCornerShape(100.dp))
                            .padding(horizontal = 8.dp, vertical = 2.dp)
                    ) {
                        Text(
                            text = if (isPlus) "👑 PLUS MEMBER" else "FREE",
                            fontSize = 10.sp, fontWeight = FontWeight.Bold, color = Color.White
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(8.dp))

            // --- Options ---
            // One entry per thing. Anything that has a tab at the bottom (Scan, History) is not repeated here.
            MenuItem("👤", "Account", if (isPlus) "Profile, Prism Plus, password" else "Profile, plan, password", activeTab == "account") { onNavigate("account") }
            MenuItem("⚙️", "Settings", "Auto-Protection and screen monitoring", activeTab == "settings") { onNavigate("settings") }
            MenuItem("🔒", "Privacy", "Privacy health, tips, common scams", activeTab == "privacy") { onNavigate("privacy") }
            MenuItem("ℹ️", "About Prism", null) { onAbout() }

            if (isAdmin) {
                HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp, horizontal = 16.dp))
                Text(
                    text = "ADMIN", fontSize = 11.sp, fontWeight = FontWeight.Bold, color = Color(0xFFB45309),
                    modifier = Modifier.padding(horizontal = 28.dp, vertical = 4.dp)
                )
                MenuItem("🛠️", "Admin", "All accounts and plans", activeTab == "admin", tint = Color(0xFFB45309)) { onNavigate("admin") }
                MenuItem(
                    "🔑", "Google API key",
                    when (googleActive) { true -> "Active"; false -> "Not set up yet"; null -> "Tap to check or enter the key" },
                    activeTab == "google", tint = Color(0xFFB45309)
                ) { onNavigate("google") }
            }

            HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp, horizontal = 16.dp))
            MenuItem("🚪", "Log out", null, false, tint = Color(0xFFDC2626)) { onLogout() }
            Spacer(modifier = Modifier.height(16.dp))
        }
    }
}

@Composable
private fun MenuItem(
    icon: String,
    label: String,
    subtitle: String?,
    selected: Boolean = false,
    tint: Color = Color(0xFF111827),
    onClick: () -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 12.dp, vertical = 2.dp)
            .background(if (selected) Color(0xFFEFF6FF) else Color.Transparent, RoundedCornerShape(12.dp))
            .clickable(onClick = onClick)
            .padding(horizontal = 14.dp, vertical = 7.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        Text(text = icon, fontSize = 20.sp)
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = label, fontSize = 15.sp,
                fontWeight = if (selected) FontWeight.Bold else FontWeight.Medium,
                color = if (selected) Color(0xFF2563EB) else tint
            )
            if (subtitle != null) Text(text = subtitle, fontSize = 11.sp, color = Color(0xFF6B7280), maxLines = 1, overflow = TextOverflow.Ellipsis)
        }
    }
}
