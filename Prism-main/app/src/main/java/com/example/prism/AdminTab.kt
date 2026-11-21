package com.example.prism

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
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
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.prism.net.AdminUser
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Admin tab: every account in the backend database with its plan, and a switch to change any plan.
 * Passwords are never shown (the backend only stores bcrypt hashes and never sends them).
 */
@Composable
fun AdminTab(
    users: List<AdminUser>,
    loading: Boolean,
    error: String?,
    busyId: String?,
    myEmail: String,
    onRefresh: () -> Unit,
    onSetPlan: (AdminUser, SubscriptionPlan) -> Unit,
    onSetPassword: (AdminUser, String, (String?) -> Unit) -> Unit = { _, _, done -> done("Not available") }
) {
    var query by remember { mutableStateOf("") }
    var passwordFor by remember { mutableStateOf<AdminUser?>(null) }
    val context = androidx.compose.ui.platform.LocalContext.current
    LaunchedEffect(Unit) { onRefresh() }

    val shown = users.filter {
        query.isBlank() || it.name.contains(query, ignoreCase = true) || it.email.contains(query, ignoreCase = true)
    }

    // --- Summary + refresh ---
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(24.dp),
        colors = CardDefaults.cardColors(containerColor = Color.White),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp)
    ) {
        Column(modifier = Modifier.fillMaxWidth().padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column {
                    Text(text = "🛠️  Admin", fontSize = 18.sp, fontWeight = FontWeight.Bold, color = Color(0xFF111827))
                    Text(text = "All accounts in the database", fontSize = 12.sp, color = Color(0xFF6B7280))
                }
                OutlinedButton(onClick = onRefresh, enabled = !loading, shape = RoundedCornerShape(12.dp)) {
                    if (loading) {
                        CircularProgressIndicator(modifier = Modifier.size(16.dp), strokeWidth = 2.dp)
                    } else {
                        Text("Refresh", fontSize = 13.sp)
                    }
                }
            }

            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Stat("Accounts", users.size, Color(0xFF2563EB), Modifier.weight(1f))
                Stat("Plus", users.count { it.plan == "PLUS" }, Color(0xFF9333EA), Modifier.weight(1f))
                Stat("Free", users.count { it.plan == "FREE" }, Color(0xFF16A34A), Modifier.weight(1f))
                Stat("No plan", users.count { it.plan == null }, Color(0xFF6B7280), Modifier.weight(1f))
            }

            OutlinedTextField(
                value = query,
                onValueChange = { query = it },
                placeholder = { Text("Search name or email", fontSize = 14.sp) },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(12.dp)
            )

            if (error != null) Text(text = error, fontSize = 13.sp, color = Color(0xFFDC2626))
        }
    }

    // --- Accounts ---
    if (shown.isEmpty() && !loading && error == null) {
        Text(
            text = if (users.isEmpty()) "No accounts yet." else "No account matches \"$query\".",
            fontSize = 14.sp,
            color = Color(0xFF6B7280),
            modifier = Modifier.fillMaxWidth().padding(vertical = 24.dp),
            textAlign = androidx.compose.ui.text.style.TextAlign.Center
        )
    }
    shown.forEach { user ->
        UserCard(
            user = user,
            isMe = user.email.equals(myEmail, ignoreCase = true),
            busy = busyId == user.id,
            locked = busyId != null,
            onSetPlan = { onSetPlan(user, it) },
            onChangePassword = { passwordFor = user }
        )
    }

    passwordFor?.let { target ->
        AdminPasswordDialog(
            who = target.name.ifBlank { target.email },
            onSubmit = { new, done -> onSetPassword(target, new, done) },
            onDismiss = { passwordFor = null },
            onSuccess = {
                passwordFor = null
                android.widget.Toast.makeText(context, "Password changed for ${target.email}", android.widget.Toast.LENGTH_SHORT).show()
            }
        )
    }
}

@Composable
private fun Stat(label: String, value: Int, color: Color, modifier: Modifier) {
    Column(
        modifier = modifier.background(Color(0xFFF9FAFB), RoundedCornerShape(12.dp)).padding(vertical = 10.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text(text = "$value", fontSize = 20.sp, fontWeight = FontWeight.Bold, color = color)
        Text(text = label, fontSize = 11.sp, color = Color(0xFF6B7280))
    }
}

@Composable
private fun UserCard(
    user: AdminUser, isMe: Boolean, busy: Boolean, locked: Boolean,
    onSetPlan: (SubscriptionPlan) -> Unit, onChangePassword: () -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(20.dp),
        colors = CardDefaults.cardColors(containerColor = Color.White),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp)
    ) {
        Column(modifier = Modifier.fillMaxWidth().padding(14.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                Box(
                    modifier = Modifier.size(42.dp).background(Color(0xFFEFF6FF), CircleShape),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        text = user.name.trim().firstOrNull()?.uppercase() ?: "?",
                        fontSize = 18.sp, fontWeight = FontWeight.Bold, color = Color(0xFF2563EB)
                    )
                }
                Column(modifier = Modifier.weight(1f)) {
                    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                        Text(
                            text = user.name.ifBlank { "(no name)" },
                            fontSize = 15.sp, fontWeight = FontWeight.Bold, color = Color(0xFF111827),
                            maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f, fill = false)
                        )
                        if (user.isAdmin) Badge("ADMIN", Color(0xFFFEF3C7), Color(0xFFB45309))
                        if (isMe) Badge("YOU", Color(0xFFDBEAFE), Color(0xFF1D4ED8))
                    }
                    Text(text = user.email, fontSize = 12.sp, color = Color(0xFF6B7280), maxLines = 1, overflow = TextOverflow.Ellipsis)
                    Text(
                        text = "${user.scanCount} scans · joined ${formatDate(user.createdAt)}",
                        fontSize = 11.sp, color = Color(0xFF9CA3AF)
                    )
                }
            }

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                PlanButton("Free", user.plan == "FREE", Color(0xFF2563EB), !locked, Modifier.weight(1f)) { onSetPlan(SubscriptionPlan.FREE) }
                PlanButton("Plus 👑", user.plan == "PLUS", Color(0xFF9333EA), !locked, Modifier.weight(1f)) { onSetPlan(SubscriptionPlan.PLUS) }
                if (busy) CircularProgressIndicator(modifier = Modifier.size(20.dp), strokeWidth = 2.dp)
            }
            if (user.plan == null) {
                Text(text = "Has not chosen a plan yet", fontSize = 11.sp, color = Color(0xFF9CA3AF))
            }
            OutlinedButton(
                onClick = onChangePassword,
                modifier = Modifier.fillMaxWidth().height(40.dp),
                shape = RoundedCornerShape(10.dp)
            ) { Text("🔑  Change password", fontSize = 13.sp) }
        }
    }
}

@Composable
private fun PlanButton(label: String, selected: Boolean, color: Color, enabled: Boolean, modifier: Modifier, onClick: () -> Unit) {
    Box(
        modifier = modifier
            .height(38.dp)
            .background(if (selected) color else Color(0xFFF3F4F6), RoundedCornerShape(10.dp))
            .clickable(enabled = enabled && !selected, onClick = onClick),
        contentAlignment = Alignment.Center
    ) {
        Text(
            text = label,
            fontSize = 13.sp,
            fontWeight = FontWeight.Medium,
            color = if (selected) Color.White else if (enabled) Color(0xFF374151) else Color(0xFF9CA3AF)
        )
    }
}

@Composable
private fun Badge(text: String, bg: Color, fg: Color) {
    Box(modifier = Modifier.background(bg, RoundedCornerShape(100.dp)).padding(horizontal = 6.dp, vertical = 1.dp)) {
        Text(text = text, fontSize = 9.sp, fontWeight = FontWeight.Bold, color = fg)
    }
}

private fun formatDate(ms: Long): String =
    if (ms <= 0) "-" else SimpleDateFormat("d MMM yyyy", Locale.getDefault()).format(Date(ms))
