package com.example.prism

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
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
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.prism.net.GoogleKeyStatus

/** Where the active key comes from, in words. */
internal fun googleSourceText(s: GoogleKeyStatus?): String = when {
    s == null -> "Checking with the server..."
    !s.active -> "No key yet. Paste one below to turn the Google link check on."
    s.source == "app" -> "Key entered in this app (${s.hint ?: "hidden"})"
    s.source == "env" -> "Key from the server's .env file (${s.hint ?: "hidden"})"
    else -> "Active"
}

/** The server needs 20+ letters/digits/-/_ ; the same rule is checked here so typos fail fast. */
internal fun looksLikeGoogleKey(key: String): Boolean = Regex("^[A-Za-z0-9_-]{20,200}$").matches(key.trim())

/**
 * Admin screen: is the Google API key set, and a field to enter it. The server checks the key with
 * Google before saving, applies it at once (no restart), and never sends the full key back.
 */
@Composable
fun GoogleApiTab(
    status: GoogleKeyStatus?,
    busy: Boolean,
    message: Pair<String, Boolean>?,
    onLoad: () -> Unit,
    onSave: (key: String, onSaved: () -> Unit) -> Unit,
    onRemove: () -> Unit
) {
    var key by remember { mutableStateOf("") }
    LaunchedEffect(Unit) { onLoad() }

    Text(text = "Google API key", fontSize = 18.sp, fontWeight = FontWeight.Bold, color = Color(0xFF111827))

    // --- Status ---
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(20.dp),
        colors = CardDefaults.cardColors(containerColor = Color.White),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp)
    ) {
        Column(Modifier.fillMaxWidth().padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                Text("🌐  Google link check", fontSize = 15.sp, fontWeight = FontWeight.Bold, color = Color(0xFF111827))
                GoogleActivePill(status?.active)
            }
            Text(googleSourceText(status), fontSize = 13.sp, color = Color(0xFF6B7280))
        }
    }

    // --- Enter / replace the key ---
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(20.dp),
        colors = CardDefaults.cardColors(containerColor = Color.White),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp)
    ) {
        Column(Modifier.fillMaxWidth().padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text(if (status?.active == true) "Replace the key" else "Enter the key", fontSize = 15.sp, fontWeight = FontWeight.Bold, color = Color(0xFF111827))
            OutlinedTextField(
                value = key,
                onValueChange = { key = it },
                label = { Text("Google API key (AIza...)") },
                singleLine = true,
                enabled = !busy,
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                modifier = Modifier.fillMaxWidth()
            )
            Button(
                onClick = { onSave(key) { key = "" } },
                enabled = !busy && looksLikeGoogleKey(key),
                modifier = Modifier.fillMaxWidth().height(48.dp),
                shape = RoundedCornerShape(12.dp),
                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF2563EB))
            ) { Text(if (busy) "Checking with Google..." else "Check & save", fontSize = 15.sp, fontWeight = FontWeight.Medium) }

            if (message != null) {
                Text(
                    text = message.first,
                    fontSize = 13.sp,
                    color = if (message.second) Color(0xFFDC2626) else Color(0xFF15803D),
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(if (message.second) Color(0xFFFEF2F2) else Color(0xFFF0FDF4), RoundedCornerShape(10.dp))
                        .padding(10.dp)
                )
            }

            if (status?.source == "app") {
                OutlinedButton(
                    onClick = onRemove,
                    enabled = !busy,
                    modifier = Modifier.fillMaxWidth().height(44.dp),
                    shape = RoundedCornerShape(12.dp)
                ) { Text("Remove saved key", color = Color(0xFFDC2626), fontSize = 14.sp) }
            }

            Text(
                text = "The app sends the key to your server over this connection. The server checks it with Google first, saves it only if Google accepts it, and starts using it right away. The full key is never shown again.",
                fontSize = 11.sp, color = Color(0xFF6B7280)
            )
        }
    }
}
