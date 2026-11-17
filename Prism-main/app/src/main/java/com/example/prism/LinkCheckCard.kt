package com.example.prism

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/**
 * Google link check: a link, or a message with links, checked online against Google Cloud Web Risk
 * through prism-backend (POST /api/scans/webrisk). The API key stays on the server; the app never sees it.
 */
@Composable
fun LinkCheckCard(
    text: String,
    onTextChange: (String) -> Unit,
    isChecking: Boolean,
    error: String?,
    onCheck: () -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(24.dp),
        colors = CardDefaults.cardColors(containerColor = Color.White),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp)
    ) {
        Column(modifier = Modifier.fillMaxWidth().padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Column {
                Text(text = "Google Link Check", fontSize = 16.sp, fontWeight = FontWeight.Bold, color = Color(0xFF111827))
                Text(text = "Checks links against Google's list of phishing and malware sites", fontSize = 12.sp, color = Color(0xFF6B7280))
            }

            OutlinedTextField(
                value = text,
                onValueChange = onTextChange,
                placeholder = { Text(text = "Paste a link or a message with links", fontSize = 15.sp) },
                maxLines = 4,
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(12.dp)
            )

            Button(
                onClick = onCheck,
                enabled = text.isNotBlank() && !isChecking,
                modifier = Modifier.fillMaxWidth().height(52.dp),
                shape = RoundedCornerShape(12.dp),
                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF7C3AED))
            ) {
                if (isChecking) {
                    CircularProgressIndicator(color = Color.White, modifier = Modifier.size(20.dp), strokeWidth = 2.dp)
                } else {
                    Text(text = "🌐  Check with Google", fontSize = 15.sp, fontWeight = FontWeight.Medium)
                }
            }

            if (error != null) {
                Text(text = error, fontSize = 13.sp, color = Color(0xFFDC2626))
            }
        }
    }
}
