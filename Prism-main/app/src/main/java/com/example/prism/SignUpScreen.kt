package com.example.prism

import androidx.compose.animation.core.*
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.blur
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

@Composable
fun SignUpScreen(
    viewModel: AppStateViewModel,
    onBackToLogin: () -> Unit,
    onShowMessage: (String, String) -> Unit // Updated to safely accept two parameters (Title, Body)
) {
    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(
                brush = Brush.linearGradient(
                    colors = listOf(Color(0xFF1E3A8A), Color(0xFF1E40AF), Color(0xFF581C87))
                )
            ),
        contentAlignment = Alignment.Center
    ) {
        val infiniteTransition = rememberInfiniteTransition(label = "Glow")
        val alphaGlow by infiniteTransition.animateFloat(
            initialValue = 0.05f,
            targetValue = 0.15f,
            animationSpec = infiniteRepeatable(
                animation = tween(4000, easing = LinearEasing),
                repeatMode = RepeatMode.Reverse
            ),
            label = "Alpha"
        )

        Box(modifier = Modifier.size(200.dp).align(Alignment.TopStart).offset(x = 10.dp, y = 10.dp).background(Color(0xFF3B82F6).copy(alpha = alphaGlow), CircleShape).blur(40.dp))
        Box(modifier = Modifier.size(250.dp).align(Alignment.BottomEnd).offset(x = (-10).dp, y = (-10).dp).background(Color(0xFFA855F7).copy(alpha = alphaGlow), CircleShape).blur(50.dp))

        Card(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 20.dp, vertical = 24.dp)
                .heightIn(max = 680.dp),
            shape = RoundedCornerShape(24.dp),
            colors = CardDefaults.cardColors(containerColor = Color.White),
            elevation = CardDefaults.cardElevation(defaultElevation = 16.dp)
        ) {
            Column(modifier = Modifier.fillMaxWidth()) {

                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(Brush.horizontalGradient(colors = listOf(Color(0xFF2563EB), Color(0xFF9333EA))))
                        .padding(vertical = 24.dp),
                    contentAlignment = Alignment.Center
                ) {
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        Box(
                            modifier = Modifier
                                .size(64.dp)
                                .background(Color.White.copy(alpha = 0.2f), CircleShape),
                            contentAlignment = Alignment.Center
                        ) {
                            Text(text = "🔒", fontSize = 28.sp)
                        }
                        Spacer(modifier = Modifier.height(12.dp))
                        Text(text = "Create Account", fontSize = 24.sp, fontWeight = FontWeight.Bold, color = Color.White)
                        Text(text = "Join Prism today", fontSize = 14.sp, color = Color(0xFFDBEAFE))
                    }
                }

                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .verticalScroll(rememberScrollState())
                        .padding(20.dp),
                    verticalArrangement = Arrangement.spacedBy(16.dp)
                ) {
                    Column {
                        Text(text = "Full Name", fontSize = 14.sp, fontWeight = FontWeight.Medium, color = Color(0xFF374151), modifier = Modifier.padding(bottom = 6.dp))
                        OutlinedTextField(
                            value = viewModel.signUpName,
                            onValueChange = { viewModel.signUpName = it },
                            placeholder = { Text("John Doe") },
                            modifier = Modifier.fillMaxWidth(),
                            shape = RoundedCornerShape(12.dp),
                            singleLine = true
                        )
                    }

                    Column {
                        Text(text = "Email Address", fontSize = 14.sp, fontWeight = FontWeight.Medium, color = Color(0xFF374151), modifier = Modifier.padding(bottom = 6.dp))
                        OutlinedTextField(
                            value = viewModel.signUpEmail,
                            onValueChange = { viewModel.signUpEmail = it },
                            placeholder = { Text("your.email@example.com") },
                            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Email),
                            modifier = Modifier.fillMaxWidth(),
                            shape = RoundedCornerShape(12.dp),
                            singleLine = true
                        )
                    }

                    Column {
                        Text(text = "Password", fontSize = 14.sp, fontWeight = FontWeight.Medium, color = Color(0xFF374151), modifier = Modifier.padding(bottom = 6.dp))
                        OutlinedTextField(
                            value = viewModel.signUpPassword,
                            onValueChange = { viewModel.signUpPassword = it },
                            placeholder = { Text("At least 6 characters") },
                            visualTransformation = PasswordVisualTransformation(),
                            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                            modifier = Modifier.fillMaxWidth(),
                            shape = RoundedCornerShape(12.dp),
                            singleLine = true
                        )
                    }

                    Column {
                        Text(text = "Confirm Password", fontSize = 14.sp, fontWeight = FontWeight.Medium, color = Color(0xFF374151), modifier = Modifier.padding(bottom = 6.dp))
                        OutlinedTextField(
                            value = viewModel.signUpConfirmPassword,
                            onValueChange = { viewModel.signUpConfirmPassword = it },
                            placeholder = { Text("Re-enter your password") },
                            visualTransformation = PasswordVisualTransformation(),
                            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                            modifier = Modifier.fillMaxWidth(),
                            shape = RoundedCornerShape(12.dp),
                            singleLine = true
                        )
                    }

                    Spacer(modifier = Modifier.height(8.dp))

                    Button(
                        onClick = {
                            viewModel.handleSignUp(
                                onValidationError = { msg -> onShowMessage("Validation Error", msg) },
                                onSignUpSuccess = onShowMessage
                            )
                        },
                        modifier = Modifier.fillMaxWidth().height(50.dp),
                        shape = RoundedCornerShape(12.dp),
                        colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF2563EB)),
                        enabled = !viewModel.isSigningUp
                    ) {
                        if (viewModel.isSigningUp) {
                            CircularProgressIndicator(color = Color.White, modifier = Modifier.size(24.dp), strokeWidth = 2.dp)
                        } else {
                            Text(text = "Sign Up", fontSize = 16.sp, fontWeight = FontWeight.Bold)
                        }
                    }

                    TextButton(
                        onClick = onBackToLogin,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text(text = "Already have an account? Sign In", color = Color(0xFF4B5563), fontSize = 14.sp, textAlign = TextAlign.Center)
                    }
                }
            }
        }
    }
}