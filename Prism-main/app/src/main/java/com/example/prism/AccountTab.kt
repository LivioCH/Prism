package com.example.prism

import androidx.compose.foundation.background
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
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/**
 * Account tab: who is signed in, which plan they have (and what it unlocks), and change password.
 * Changing the plan reopens the same plan picker that new accounts see.
 */
@Composable
fun AccountTab(
    name: String,
    email: String,
    plan: SubscriptionPlan,
    onChangePlan: () -> Unit,
    onChangePassword: () -> Unit
) {
    val isPlus = plan == SubscriptionPlan.PLUS

    // --- Profile ---
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(24.dp),
        colors = CardDefaults.cardColors(containerColor = Color.White),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp)
    ) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(14.dp)
        ) {
            Box(
                modifier = Modifier.size(56.dp).background(Color(0xFFEFF6FF), CircleShape),
                contentAlignment = Alignment.Center
            ) {
                Text(
                    text = name.trim().firstOrNull()?.uppercase() ?: "?",
                    fontSize = 24.sp,
                    fontWeight = FontWeight.Bold,
                    color = Color(0xFF2563EB)
                )
            }
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = name.ifBlank { "Your account" },
                    fontSize = 18.sp,
                    fontWeight = FontWeight.Bold,
                    color = Color(0xFF111827),
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                Text(
                    text = email,
                    fontSize = 13.sp,
                    color = Color(0xFF6B7280),
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            }
        }
    }

    // --- Subscription ---
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(24.dp),
        colors = CardDefaults.cardColors(containerColor = if (isPlus) Color(0xFFFAF5FF) else Color.White),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp)
    ) {
        Column(modifier = Modifier.fillMaxWidth().padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column {
                    Text(text = "Subscription", fontSize = 12.sp, color = Color(0xFF6B7280))
                    Text(
                        text = if (isPlus) "👑  Prism Plus" else "🛡️  Prism Free",
                        fontSize = 18.sp,
                        fontWeight = FontWeight.Bold,
                        color = if (isPlus) Color(0xFF7E22CE) else Color(0xFF111827)
                    )
                }
                Box(
                    modifier = Modifier
                        .background(
                            if (isPlus) Color(0xFFF3E8FF) else Color(0xFFF3F4F6),
                            RoundedCornerShape(100.dp)
                        )
                        .padding(horizontal = 10.dp, vertical = 4.dp)
                ) {
                    Text(
                        text = if (isPlus) "MEMBER" else "NON-MEMBER",
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Bold,
                        color = if (isPlus) Color(0xFF7E22CE) else Color(0xFF6B7280)
                    )
                }
            }

            PlanLine(included = true, text = if (isPlus) "Unlimited manual scans" else "Manual scan on your phone, 10 a day")
            PlanLine(included = isPlus, text = "Google Web Risk check on every scan")
            PlanLine(included = isPlus, text = "Auto-Protection: links on screen and copied links")
            PlanLine(included = isPlus, text = "Advanced detection & full history")

            Button(
                onClick = onChangePlan,
                modifier = Modifier.fillMaxWidth().height(48.dp),
                shape = RoundedCornerShape(12.dp),
                colors = ButtonDefaults.buttonColors(
                    containerColor = if (isPlus) Color(0xFF6B7280) else Color(0xFF9333EA)
                )
            ) {
                Text(
                    text = if (isPlus) "Change plan" else "Upgrade to Plus",
                    fontSize = 15.sp,
                    fontWeight = FontWeight.Medium
                )
            }
        }
    }

    // --- Password (Log out lives in the side menu, once) ---
    OutlinedButton(
        onClick = onChangePassword,
        modifier = Modifier.fillMaxWidth().height(48.dp),
        shape = RoundedCornerShape(12.dp)
    ) {
        Text(text = "🔑  Change password", fontSize = 15.sp, fontWeight = FontWeight.Medium, color = Color(0xFF111827))
    }
}

@Composable
private fun PlanLine(included: Boolean, text: String) {
    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(
            text = if (included) "✓" else "🔒",
            fontSize = 13.sp,
            fontWeight = FontWeight.Bold,
            color = if (included) Color(0xFF16A34A) else Color(0xFF9CA3AF)
        )
        Text(
            text = text,
            fontSize = 13.sp,
            color = if (included) Color(0xFF374151) else Color(0xFF9CA3AF)
        )
    }
}
