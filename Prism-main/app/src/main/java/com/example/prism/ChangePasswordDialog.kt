package com.example.prism

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/** Checks the form before anything is sent. Returns a message, or null when it is fine. */
internal fun passwordFormError(current: String, new: String, confirm: String): String? = when {
    current.isEmpty() -> "Enter your current password"
    new.length < 6 -> "New password must be at least 6 characters"
    new == current -> "New password must be different from the current one"
    new != confirm -> "The new passwords do not match"
    else -> null
}

/** Form check for an admin setting someone else's password (no "current password": the admin does not know it). */
internal fun adminPasswordError(new: String, confirm: String): String? = when {
    new.length < 6 -> "Password must be at least 6 characters"
    new != confirm -> "The two passwords do not match"
    else -> null
}

/** Admin screen: set a new password for [who] (their name or email). */
@Composable
fun AdminPasswordDialog(
    who: String,
    onSubmit: (new: String, onDone: (String?) -> Unit) -> Unit,
    onDismiss: () -> Unit,
    onSuccess: () -> Unit
) {
    var new by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }

    AlertDialog(
        onDismissRequest = { if (!busy) onDismiss() },
        title = { Text("New password for $who") },
        text = {
            Column {
                val kb = KeyboardOptions(keyboardType = KeyboardType.Password)
                OutlinedTextField(new, { new = it }, label = { Text("New password") }, singleLine = true,
                    visualTransformation = PasswordVisualTransformation(), keyboardOptions = kb, modifier = Modifier.fillMaxWidth())
                Spacer(Modifier.height(8.dp))
                OutlinedTextField(confirm, { confirm = it }, label = { Text("Repeat new password") }, singleLine = true,
                    visualTransformation = PasswordVisualTransformation(), keyboardOptions = kb, modifier = Modifier.fillMaxWidth())
                Spacer(Modifier.height(8.dp))
                Text("Passwords cannot be read back, only replaced. Tell the user the new one yourself.", fontSize = 12.sp, color = Color(0xFF6B7280))
                if (error != null) {
                    Spacer(Modifier.height(8.dp))
                    Text(error!!, color = Color(0xFFDC2626), fontSize = 13.sp)
                }
            }
        },
        confirmButton = {
            TextButton(enabled = !busy, onClick = {
                val problem = adminPasswordError(new, confirm)
                if (problem != null) { error = problem; return@TextButton }
                busy = true; error = null
                onSubmit(new) { result ->
                    busy = false
                    if (result == null) onSuccess() else error = result
                }
            }) { Text(if (busy) "Saving..." else "Set password") }
        },
        dismissButton = { TextButton(enabled = !busy, onClick = onDismiss) { Text("Cancel") } },
        containerColor = Color.White
    )
}

@Composable
fun ChangePasswordDialog(
    onSubmit: (current: String, new: String, onDone: (String?) -> Unit) -> Unit,
    onDismiss: () -> Unit,
    onSuccess: () -> Unit
) {
    var current by remember { mutableStateOf("") }
    var new by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }

    AlertDialog(
        onDismissRequest = { if (!busy) onDismiss() },
        title = { Text("Change password") },
        text = {
            Column {
                val kb = KeyboardOptions(keyboardType = KeyboardType.Password)
                OutlinedTextField(current, { current = it }, label = { Text("Current password") }, singleLine = true,
                    visualTransformation = PasswordVisualTransformation(), keyboardOptions = kb, modifier = Modifier.fillMaxWidth())
                Spacer(Modifier.height(8.dp))
                OutlinedTextField(new, { new = it }, label = { Text("New password") }, singleLine = true,
                    visualTransformation = PasswordVisualTransformation(), keyboardOptions = kb, modifier = Modifier.fillMaxWidth())
                Spacer(Modifier.height(8.dp))
                OutlinedTextField(confirm, { confirm = it }, label = { Text("Repeat new password") }, singleLine = true,
                    visualTransformation = PasswordVisualTransformation(), keyboardOptions = kb, modifier = Modifier.fillMaxWidth())
                if (error != null) {
                    Spacer(Modifier.height(8.dp))
                    Text(error!!, color = Color(0xFFDC2626), fontSize = 13.sp)
                }
            }
        },
        confirmButton = {
            TextButton(enabled = !busy, onClick = {
                val problem = passwordFormError(current, new, confirm)
                if (problem != null) { error = problem; return@TextButton }
                busy = true; error = null
                onSubmit(current, new) { result ->
                    busy = false
                    if (result == null) onSuccess() else error = result
                }
            }) { Text(if (busy) "Saving..." else "Change") }
        },
        dismissButton = { TextButton(enabled = !busy, onClick = onDismiss) { Text("Cancel") } },
        containerColor = Color.White
    )
}
