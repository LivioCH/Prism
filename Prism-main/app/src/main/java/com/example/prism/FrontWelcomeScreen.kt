package com.example.prism

import androidx.compose.animation.core.*
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.blur
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

@Composable
fun FrontWelcomeScreen(
    onGetStartedClick: () -> Unit
) {
    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(
                brush = Brush.linearGradient(
                    colors = listOf(Color(0xFF0F172A), Color(0xFF1E3A8A), Color(0xFF581C87))
                )
            )
    ) {
        val infiniteTransition = rememberInfiniteTransition(label = "BackgroundGlow")
        val alphaGlow by infiniteTransition.animateFloat(
            initialValue = 0.1f,
            targetValue = 0.25f,
            animationSpec = infiniteRepeatable(
                animation = tween(3000, easing = LinearEasing),
                repeatMode = RepeatMode.Reverse
            ),
            label = "AlphaPulse"
        )

        Box(modifier = Modifier.size(250.dp).align(Alignment.TopStart).offset(x = (-30).dp, y = 30.dp).background(Color(0xFF3B82F6).copy(alpha = alphaGlow), CircleShape).blur(50.dp))
        Box(modifier = Modifier.size(300.dp).align(Alignment.BottomEnd).offset(x = 30.dp, y = (-30).dp).background(Color(0xFFA855F7).copy(alpha = alphaGlow), CircleShape).blur(60.dp))

        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 24.dp, vertical = 32.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            val rotationAngle by infiniteTransition.animateFloat(
                initialValue = 0f,
                targetValue = 360f,
                animationSpec = infiniteRepeatable(
                    animation = tween(20000, easing = LinearEasing),
                    repeatMode = RepeatMode.Restart
                ),
                label = "LogoRotation"
            )

            Box(
                modifier = Modifier
                    .size(130.dp)
                    .graphicsLayer { rotationY = rotationAngle }
                    .background(
                        brush = Brush.linearGradient(
                            colors = listOf(Color(0xFF60A5FA), Color(0xFF7C3AED))
                        ),
                        shape = RoundedCornerShape(16.dp)
                    )
                    .border(1.dp, Color.White.copy(alpha = 0.3f), RoundedCornerShape(16.dp)),
                contentAlignment = Alignment.Center
            ) {
                Text(text = "🛡️", fontSize = 48.sp)
            }

            Spacer(modifier = Modifier.height(24.dp))

            Text(text = "Welcome to Prism", fontSize = 36.sp, fontWeight = FontWeight.Bold, color = Color.White, textAlign = TextAlign.Center)
            Spacer(modifier = Modifier.height(8.dp))
            Text(text = "Protect Your Precious Data", fontSize = 18.sp, fontWeight = FontWeight.Medium, color = Color(0xFFDBEAFE), textAlign = TextAlign.Center)
            Spacer(modifier = Modifier.height(12.dp))
            Text(
                text = "Advanced threat detection and privacy protection powered by AI. Scan URLs, phone numbers, and messages to stay safe from scams and phishing attacks.",
                fontSize = 14.sp, color = Color(0xFFBFDBFE), textAlign = TextAlign.Center, lineHeight = 22.sp, modifier = Modifier.padding(horizontal = 16.dp)
            )

            Spacer(modifier = Modifier.height(32.dp))

            Column(modifier = Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(16.dp)) {
                FeatureCard(emoji = "🛡️", title = "Real-Time Protection", description = "Instant threat detection as you browse", iconContainerColor = Color(0xFF2563EB))
                FeatureCard(emoji = "🔒", title = "100% Secure", description = "End-to-end encrypted protection", iconContainerColor = Color(0xFF7C3AED))
                FeatureCard(emoji = "✨", title = "AI-Powered", description = "Advanced machine learning detection", iconContainerColor = Color(0xFFDB2777))
            }

            Spacer(modifier = Modifier.height(32.dp))

            Button(
                onClick = onGetStartedClick,
                modifier = Modifier.fillMaxWidth().height(50.dp),
                shape = RoundedCornerShape(12.dp)
            ) {
                Text(text = "Get Started", fontSize = 16.sp, fontWeight = FontWeight.Bold)
            }
        }
    }
}

@Composable
fun FeatureCard(emoji: String, title: String, description: String, iconContainerColor: Color) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(Color.White.copy(alpha = 0.1f), RoundedCornerShape(16.dp))
            .border(1.dp, Color.White.copy(alpha = 0.15f), RoundedCornerShape(16.dp))
            .padding(16.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Box(modifier = Modifier.size(48.dp).background(iconContainerColor, CircleShape), contentAlignment = Alignment.Center) {
            Text(text = emoji, fontSize = 20.sp)
        }
        Spacer(modifier = Modifier.width(16.dp))
        Column {
            Text(text = title, fontWeight = FontWeight.Bold, color = Color.White, fontSize = 16.sp)
            Text(text = description, color = Color(0xFFBFDBFE), fontSize = 13.sp)
        }
    }
}