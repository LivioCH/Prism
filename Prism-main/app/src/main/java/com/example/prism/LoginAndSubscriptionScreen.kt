package com.example.prism

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.*
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.BiasAlignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.blur
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties

// ==========================================
// 🛡️ 1. LOGIN SCREEN COMPOSABLE
// ==========================================
@Composable
fun LoginScreen(
    viewModel: AppStateViewModel,
    onSignUpClick: () -> Unit,
    onLoginSuccess: () -> Unit,
    onShowMessage: (String) -> Unit,
    onPlanMessage: (String, String) -> Unit
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
                .heightIn(max = 650.dp),
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
                            Text(text = "🛡️", fontSize = 28.sp)
                        }
                        Spacer(modifier = Modifier.height(12.dp))
                        Text(text = "Prism", fontSize = 28.sp, fontWeight = FontWeight.Bold, color = Color.White)
                        Text(text = "Protect Your Precious Data", fontSize = 14.sp, color = Color(0xFFDBEAFE))
                    }
                }

                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .verticalScroll(rememberScrollState())
                        .padding(20.dp),
                    verticalArrangement = Arrangement.spacedBy(16.dp)
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .background(Color(0xFFE8F5E9), RoundedCornerShape(12.dp))
                            .border(1.dp, Color(0xFFC8E6C9), RoundedCornerShape(12.dp))
                            .padding(10.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.Center
                    ) {
                        Text(text = "🔒", fontSize = 14.sp)
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(text = "Secure & Encrypted Connection", color = Color(0xFF2E7D32), fontSize = 13.sp, fontWeight = FontWeight.Medium)
                    }

                    Column {
                        Text(text = "Email Address", fontSize = 14.sp, fontWeight = FontWeight.Medium, color = Color(0xFF374151), modifier = Modifier.padding(bottom = 6.dp))
                        OutlinedTextField(
                            value = viewModel.loginEmail,
                            onValueChange = { viewModel.loginEmail = it },
                            placeholder = { Text("your.email@example.com") },
                            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Email),
                            modifier = Modifier.fillMaxWidth(),
                            shape = RoundedCornerShape(12.dp)
                        )
                    }

                    Column {
                        Text(text = "Password", fontSize = 14.sp, fontWeight = FontWeight.Medium, color = Color(0xFF374151), modifier = Modifier.padding(bottom = 6.dp))
                        OutlinedTextField(
                            value = viewModel.loginPassword,
                            onValueChange = { viewModel.loginPassword = it },
                            placeholder = { Text("Enter your password") },
                            visualTransformation = PasswordVisualTransformation(),
                            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                            modifier = Modifier.fillMaxWidth(),
                            shape = RoundedCornerShape(12.dp)
                        )
                    }

                    Spacer(modifier = Modifier.height(4.dp))

                    Button(
                        onClick = {
                            viewModel.handleLogin(
                                onValidationError = { error -> onShowMessage(error) },
                                onLoginSuccess = { successMsg ->
                                    onShowMessage(successMsg)
                                    onLoginSuccess()
                                }
                            )
                        },
                        modifier = Modifier.fillMaxWidth().height(50.dp),
                        shape = RoundedCornerShape(12.dp),
                        colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF2563EB))
                    ) {
                        if (viewModel.isLoggingIn) {
                            CircularProgressIndicator(color = Color.White, modifier = Modifier.size(24.dp))
                        } else {
                            Text(text = "Sign In Securely", fontSize = 16.sp, fontWeight = FontWeight.Bold)
                        }
                    }

                    Row(
                        modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp),
                        horizontalArrangement = Arrangement.SpaceEvenly
                    ) {
                        TrustItem(emoji = "🛡️", text = "Encrypted")
                        TrustItem(emoji = "🔒", text = "Private")
                        TrustItem(emoji = "✨", text = "Secure")
                    }

                    TextButton(
                        onClick = onSignUpClick,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text(text = "Don't have an account? Create one now", color = Color(0xFF4B5563), fontSize = 14.sp, textAlign = TextAlign.Center)
                    }
                }
            }
        }

        // --- Subscription Popup Modal Overlay ---
        if (viewModel.showSubscriptionModal) {
            AlertDialog(
                onDismissRequest = { viewModel.showSubscriptionModal = false },
                confirmButton = {
                    Button(
                        onClick = { viewModel.showSubscriptionModal = false },
                        enabled = viewModel.subscriptionPlan != null
                    ) {
                        Text("Continue")
                    }
                },
                dismissButton = {
                    TextButton(onClick = { viewModel.showSubscriptionModal = false }) {
                        Text("Cancel")
                    }
                },
                title = {
                    Column(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        Text(text = "🛡️", fontSize = 40.sp)
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(text = "Welcome to Prism!", fontSize = 22.sp, fontWeight = FontWeight.Bold, textAlign = TextAlign.Center)
                    }
                },
                text = {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .verticalScroll(rememberScrollState()),
                        verticalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        Text(
                            text = "Choose your protection plan to get started.",
                            fontSize = 14.sp,
                            textAlign = TextAlign.Center,
                            color = Color(0xFF4B5563),
                            modifier = Modifier.fillMaxWidth().padding(bottom = 4.dp)
                        )

                        // Free Plan Card
                        val isFreeSelected = viewModel.subscriptionPlan == SubscriptionPlan.FREE
                        Box(
                            modifier = Modifier
                                .fillMaxWidth()
                                .background(
                                    color = if (isFreeSelected) Color(0xFFEFF6FF) else Color.White,
                                    shape = RoundedCornerShape(16.dp)
                                )
                                .border(
                                    width = 2.dp,
                                    color = if (isFreeSelected) Color(0xFF2563EB) else Color(0xFFD1D5DB),
                                    shape = RoundedCornerShape(16.dp)
                                )
                                .clickable {
                                    viewModel.handlePlanSelection(SubscriptionPlan.FREE) { title, desc ->
                                        onPlanMessage(title, desc)
                                    }
                                }
                                .padding(16.dp)
                        ) {
                            Column {
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.Top
                                ) {
                                    Column {
                                        Row(verticalAlignment = Alignment.CenterVertically) {
                                            Text(text = "🛡️", fontSize = 18.sp)
                                            Spacer(modifier = Modifier.width(6.dp))
                                            Text(text = "Prism", fontSize = 16.sp, fontWeight = FontWeight.Bold, color = Color(0xFF1F2937))
                                        }
                                        Spacer(modifier = Modifier.height(2.dp))
                                        Text(text = "Free", fontSize = 22.sp, fontWeight = FontWeight.Black, color = Color(0xFF2563EB))
                                    }
                                    Box(
                                        modifier = Modifier
                                            .size(24.dp)
                                            .border(width = 2.dp, color = if (isFreeSelected) Color(0xFF2563EB) else Color(0xFFD1D5DB), shape = CircleShape),
                                        contentAlignment = Alignment.Center
                                    ) {
                                        if (isFreeSelected) {
                                            Box(modifier = Modifier.size(12.dp).background(Color(0xFF2563EB), CircleShape))
                                        }
                                    }
                                }
                                Spacer(modifier = Modifier.height(12.dp))
                                Column(verticalArrangement = Arrangement.spacedBy(6.dp), modifier = Modifier.padding(bottom = 12.dp)) {
                                    FeatureRow(text = "Basic URL & phone scanning", iconColor = Color(0xFF16A34A))
                                    FeatureRow(text = "10 scans per day", iconColor = Color(0xFF16A34A))
                                    FeatureRow(text = "Scan history (last 24 hours)", iconColor = Color(0xFF16A34A))
                                    FeatureRow(text = "Basic protection tips", iconColor = Color(0xFF16A34A))
                                }
                                Text(text = "Perfect for everyday protection", fontSize = 12.sp, color = Color(0xFF6B7280))
                            }
                        }

                        // Premium Plan Card
                        val isPlusSelected = viewModel.subscriptionPlan == SubscriptionPlan.PLUS
                        Box(
                            modifier = Modifier
                                .fillMaxWidth()
                                .background(
                                    brush = Brush.linearGradient(
                                        colors = if (isPlusSelected) {
                                            listOf(Color(0xFFF3E8FF), Color(0xFFEFF6FF))
                                        } else {
                                            listOf(Color.White, Color.White)
                                        }
                                    ),
                                    shape = RoundedCornerShape(16.dp)
                                )
                                .border(
                                    width = 2.dp,
                                    color = if (isPlusSelected) Color(0xFF9333EA) else Color(0xFFD1D5DB),
                                    shape = RoundedCornerShape(16.dp)
                                )
                                .clickable {
                                    viewModel.handlePlanSelection(SubscriptionPlan.PLUS) { title, desc ->
                                        onPlanMessage(title, desc)
                                    }
                                }
                                .padding(16.dp)
                        ) {
                            Column {
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.Top
                                ) {
                                    Column {
                                        Row(verticalAlignment = Alignment.CenterVertically) {
                                            Text(text = "👑", fontSize = 18.sp)
                                            Spacer(modifier = Modifier.width(6.dp))
                                            Text(text = "Prism", fontSize = 16.sp, fontWeight = FontWeight.Bold, color = Color(0xFF1F2937))
                                        }
                                        Spacer(modifier = Modifier.height(2.dp))
                                        Row(verticalAlignment = Alignment.Bottom) {
                                            Text(text = "$4.99", fontSize = 22.sp, fontWeight = FontWeight.Black, color = Color(0xFF9333EA))
                                            Text(text = "/month", fontSize = 12.sp, color = Color(0xFF4B5563), modifier = Modifier.padding(bottom = 3.dp, start = 2.dp))
                                        }
                                    }
                                    Box(
                                        modifier = Modifier
                                            .size(24.dp)
                                            .border(width = 2.dp, color = if (isPlusSelected) Color(0xFF9333EA) else Color(0xFFD1D5DB), shape = CircleShape),
                                        contentAlignment = Alignment.Center
                                    ) {
                                        if (isPlusSelected) {
                                            Box(modifier = Modifier.size(12.dp).background(Color(0xFF9333EA), CircleShape))
                                        }
                                    }
                                }

                                Spacer(modifier = Modifier.height(12.dp))

                                Column(verticalArrangement = Arrangement.spacedBy(6.dp), modifier = Modifier.padding(bottom = 12.dp)) {
                                    FeatureRow(text = "Everything in Free, plus:", iconColor = Color(0xFF9333EA), isBold = true)
                                    FeatureRow(text = "Unlimited scans", iconColor = Color(0xFF9333EA))
                                    FeatureRow(text = "Advanced AI threat detection", iconColor = Color(0xFF9333EA))
                                    FeatureRow(text = "Real-time clipboard monitoring", iconColor = Color(0xFF9333EA))
                                    FeatureRow(text = "Complete scan history", iconColor = Color(0xFF9333EA))
                                    FeatureRow(text = "Priority support", iconColor = Color(0xFF9333EA))
                                }

                                Text(text = "Maximum protection for you and your family", fontSize = 12.sp, color = Color(0xFF7E22CE), fontWeight = FontWeight.Medium)
                            }
                        }

                        Text(
                            text = "You can change your plan anytime in Settings",
                            fontSize = 11.sp,
                            color = Color(0xFF6B7280),
                            textAlign = TextAlign.Center,
                            modifier = Modifier.fillMaxWidth().padding(top = 4.dp)
                        )
                    }
                },
                shape = RoundedCornerShape(24.dp),
                containerColor = Color.White
            )
        }
    }
}

// ==========================================
// 📊 2. MAIN DASHBOARD CONTENT AREA
// ==========================================
@Composable
fun DashboardScreen(
    subscriptionPlan: SubscriptionPlan,
    privacyScore: Int,
    stats: DashboardStats,
    activeTab: String,
    clipboardMonitoring: Boolean,
    scanType: String,
    scanInput: String,
    isScanning: Boolean,
    scanHistory: List<ScanHistoryItem>,
    onToggleClipboardMonitoring: (Boolean) -> Unit,
    onScanTypeChange: (String) -> Unit,
    onScanInputChange: (String) -> Unit,
    onExecuteScan: () -> Unit,
    onTabChange: (String) -> Unit, // Handles programmatic web bottom tab switches
    scanError: String? = null,     // Friendly message for empty / invalid input
    whitelist: List<String> = emptyList(),          // hosts the user trusts (from the database)
    onRemoveWhitelist: (String) -> Unit = {},
    blacklist: List<String> = emptyList(),          // hosts the user blocked (from the database)
    onRemoveBlacklist: (String) -> Unit = {}
) {
    val isPlus = subscriptionPlan == SubscriptionPlan.PLUS

    val headerGradient = if (isPlus) {
        Brush.horizontalGradient(colors = listOf(Color(0xFF9333EA), Color(0xFF2563EB)))
    } else {
        Brush.horizontalGradient(colors = listOf(Color(0xFF2563EB), Color(0xFF1E40AF)))
    }

    Scaffold(
        bottomBar = {
            NavigationBar(
                containerColor = Color.White,
                tonalElevation = 8.dp,
                modifier = Modifier.windowInsetsPadding(WindowInsets.safeDrawing.only(WindowInsetsSides.Bottom))
            ) {
                NavigationBarItem(
                    selected = activeTab == "scan",
                    onClick = { onTabChange("scan") },
                    icon = { Text(text = "🔍", fontSize = 20.sp) },
                    label = { Text("Scan", fontSize = 12.sp, fontWeight = FontWeight.Medium) },
                    colors = NavigationBarItemDefaults.colors(
                        selectedIconColor = Color(0xFF2563EB),
                        selectedTextColor = Color(0xFF2563EB),
                        unselectedIconColor = Color(0xFF6B7280),
                        unselectedTextColor = Color(0xFF6B7280),
                        indicatorColor = Color(0xFFEFF6FF)
                    )
                )
                NavigationBarItem(
                    selected = activeTab == "history",
                    onClick = { onTabChange("history") },
                    icon = { Text(text = "🛡️", fontSize = 20.sp) },
                    label = { Text("History", fontSize = 12.sp, fontWeight = FontWeight.Medium) },
                    colors = NavigationBarItemDefaults.colors(
                        selectedIconColor = Color(0xFF2563EB),
                        selectedTextColor = Color(0xFF2563EB),
                        unselectedIconColor = Color(0xFF6B7280),
                        unselectedTextColor = Color(0xFF6B7280),
                        indicatorColor = Color(0xFFEFF6FF)
                    )
                )
                NavigationBarItem(
                    selected = activeTab == "privacy",
                    onClick = { onTabChange("privacy") },
                    icon = { Text(text = "🔒", fontSize = 20.sp) },
                    label = { Text("Privacy", fontSize = 12.sp, fontWeight = FontWeight.Medium) },
                    colors = NavigationBarItemDefaults.colors(
                        selectedIconColor = Color(0xFF2563EB),
                        selectedTextColor = Color(0xFF2563EB),
                        unselectedIconColor = Color(0xFF6B7280),
                        unselectedTextColor = Color(0xFF6B7280),
                        indicatorColor = Color(0xFFEFF6FF)
                    )
                )
            }
        }
    ) { innerPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .background(Color(0xFFF9FAFB))
        ) {
            // --- Shared Top Header ---
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(headerGradient)
                    .padding(16.dp)
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth().padding(bottom = 12.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Text(text = if (isPlus) "👑" else "🛡️", fontSize = 32.sp)

                        Column {
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(8.dp)
                            ) {
                                Text(text = "Prism", fontSize = 18.sp, fontWeight = FontWeight.Bold, color = Color.White)
                                if (isPlus) {
                                    Box(
                                        modifier = Modifier
                                            .background(Color.White.copy(alpha = 0.2f), RoundedCornerShape(100.dp))
                                            .padding(horizontal = 8.dp, vertical = 2.dp)
                                    ) {
                                        Text(text = "PREMIUM", fontSize = 10.sp, fontWeight = FontWeight.Bold, color = Color.White)
                                    }
                                }
                            }
                            Text(
                                text = if (isPlus) "Maximum protection" else "Privacy protection",
                                fontSize = 12.sp,
                                color = if (isPlus) Color(0xFFF3E8FF) else Color(0xFFDBEAFE)
                            )
                        }
                    }

                    Column(horizontalAlignment = Alignment.End) {
                        Text(text = "$privacyScore%", fontSize = 24.sp, fontWeight = FontWeight.Bold, color = Color.White)
                        Text(text = "Score", fontSize = 12.sp, color = if (isPlus) Color(0xFFF3E8FF) else Color(0xFFDBEAFE))
                    }
                }

                Spacer(modifier = Modifier.height(4.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Box(
                        modifier = Modifier.weight(1f).background(Color.White.copy(alpha = 0.1f), RoundedCornerShape(12.dp)).padding(vertical = 10.dp),
                        contentAlignment = Alignment.Center
                    ) {
                        Column(horizontalAlignment = Alignment.CenterHorizontally) {
                            Text(text = "🔍", fontSize = 16.sp)
                            Spacer(modifier = Modifier.height(2.dp))
                            Text(text = "Scans", fontSize = 11.sp, color = Color(0xFFDBEAFE))
                            Text(text = "${stats.scansToday}", fontSize = 18.sp, fontWeight = FontWeight.Bold, color = Color.White)
                        }
                    }

                    Box(
                        modifier = Modifier.weight(1f).background(Color.White.copy(alpha = 0.1f), RoundedCornerShape(12.dp)).padding(vertical = 10.dp),
                        contentAlignment = Alignment.Center
                    ) {
                        Column(horizontalAlignment = Alignment.CenterHorizontally) {
                            Text(text = "✅", fontSize = 16.sp)
                            Spacer(modifier = Modifier.height(2.dp))
                            Text(text = "Blocked", fontSize = 11.sp, color = Color(0xFFDBEAFE))
                            Text(text = "${stats.threatsBlocked}", fontSize = 18.sp, fontWeight = FontWeight.Bold, color = Color.White)
                        }
                    }

                    Box(
                        modifier = Modifier.weight(1f).background(Color.White.copy(alpha = 0.1f), RoundedCornerShape(12.dp)).padding(vertical = 10.dp),
                        contentAlignment = Alignment.Center
                    ) {
                        Column(horizontalAlignment = Alignment.CenterHorizontally) {
                            Text(text = "🔔", fontSize = 16.sp)
                            Spacer(modifier = Modifier.height(2.dp))
                            Text(text = "Alerts", fontSize = 11.sp, color = Color(0xFFDBEAFE))
                            Text(text = "${stats.privacyAlerts}", fontSize = 18.sp, fontWeight = FontWeight.Bold, color = Color.White)
                        }
                    }
                }
            }

            // --- DYNAMIC CONTENT WORKSPACE BY SELECTED TAB ---
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f)
                    .verticalScroll(rememberScrollState())
                    .padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(16.dp)
            ) {
                when (activeTab) {
                    // ==========================================
                    // 🔍 SCAN TAB VIEW
                    // ==========================================
                    "scan" -> {
                        Column(
                            modifier = Modifier
                                .fillMaxWidth()
                                .background(
                                    brush = Brush.horizontalGradient(colors = listOf(Color(0xFF2563EB), Color(0xFF1D4ED8))),
                                    shape = RoundedCornerShape(20.dp)
                                )
                                .padding(16.dp)
                        ) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Row(
                                    verticalAlignment = Alignment.CenterVertically,
                                    horizontalArrangement = Arrangement.spacedBy(12.dp)
                                ) {
                                    Box(
                                        modifier = Modifier.size(40.dp).background(Color.White.copy(alpha = 0.2f), CircleShape),
                                        contentAlignment = Alignment.Center
                                    ) {
                                        Text(text = "🛡️", fontSize = 18.sp)
                                    }
                                    Column {
                                        Text(text = "Auto-Protection", fontSize = 14.sp, fontWeight = FontWeight.Bold, color = Color.White)
                                        Text(text = "Monitor copied links", fontSize = 12.sp, color = Color(0xFFDBEAFE))
                                    }
                                }

                                val alignmentBias by animateFloatAsState(
                                    targetValue = if (clipboardMonitoring) 1f else -1f,
                                    animationSpec = tween(durationMillis = 200),
                                    label = "SwitchAnimation"
                                )

                                Box(
                                    modifier = Modifier
                                        .size(width = 56.dp, height = 32.dp)
                                        .background(
                                            color = if (clipboardMonitoring) Color.White else Color.White.copy(alpha = 0.3f),
                                            shape = RoundedCornerShape(100.dp)
                                        )
                                        .clickable { onToggleClipboardMonitoring(!clipboardMonitoring) }
                                        .padding(4.dp),
                                    contentAlignment = BiasAlignment(horizontalBias = alignmentBias, verticalBias = 0f)
                                ) {
                                    Box(modifier = Modifier.size(24.dp).background(color = if (clipboardMonitoring) Color(0xFF2563EB) else Color.White, shape = CircleShape))
                                }
                            }

                            if (clipboardMonitoring) {
                                Spacer(modifier = Modifier.height(12.dp))
                                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                    val pulseAlpha by rememberInfiniteTransition(label = "Pulse").animateFloat(
                                        initialValue = 0.4f, targetValue = 1.0f,
                                        animationSpec = infiniteRepeatable(animation = tween(1000, easing = FastOutSlowInEasing), repeatMode = RepeatMode.Reverse),
                                        label = "Alpha"
                                    )
                                    Box(modifier = Modifier.size(8.dp).background(Color(0xFF4ADE80).copy(alpha = pulseAlpha), CircleShape))
                                    Text(text = "Monitoring clipboard for dangerous links", fontSize = 12.sp, color = Color(0xFFDBEAFE))
                                }
                            }
                        }

                        Card(
                            modifier = Modifier.fillMaxWidth(),
                            shape = RoundedCornerShape(24.dp),
                            colors = CardDefaults.cardColors(containerColor = Color.White),
                            elevation = CardDefaults.cardElevation(defaultElevation = 1.dp)
                        ) {
                            Column(modifier = Modifier.fillMaxWidth().padding(16.dp)) {
                                Text(text = "Manual Scan", fontSize = 16.sp, fontWeight = FontWeight.Bold, color = Color(0xFF111827), modifier = Modifier.padding(bottom = 16.dp))

                                Row(modifier = Modifier.fillMaxWidth().padding(bottom = 16.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                    ScanTypeTabButton(label = "URL", emojiIcon = "🔗", isSelected = scanType == "url", onClick = { onScanTypeChange("url") }, modifier = Modifier.weight(1f))
                                    ScanTypeTabButton(label = "Phone", emojiIcon = "📞", isSelected = scanType == "phone", onClick = { onScanTypeChange("phone") }, modifier = Modifier.weight(1f))
                                    ScanTypeTabButton(label = "Message", emojiIcon = "💬", isSelected = scanType == "message", onClick = { onScanTypeChange("message") }, modifier = Modifier.weight(1f))
                                }

                                Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                                    val contextPlaceholder = when (scanType) {
                                        "url" -> "Enter URL to scan..."
                                        "phone" -> "Enter phone number..."
                                        else -> "Paste suspicious message..."
                                    }

                                    OutlinedTextField(
                                        value = scanInput,
                                        onValueChange = onScanInputChange,
                                        placeholder = { Text(text = contextPlaceholder, fontSize = 15.sp) },
                                        singleLine = scanType != "message",
                                        maxLines = if (scanType == "message") 4 else 1,
                                        keyboardOptions = KeyboardOptions(keyboardType = if (scanType == "phone") KeyboardType.Phone else KeyboardType.Text, imeAction = ImeAction.Search),
                                        keyboardActions = KeyboardActions(onSearch = { if (scanInput.isNotBlank() && !isScanning) onExecuteScan() }),
                                        modifier = Modifier.fillMaxWidth(),
                                        shape = RoundedCornerShape(12.dp)
                                    )

                                    Button(
                                        onClick = onExecuteScan,
                                        enabled = scanInput.isNotBlank() && !isScanning,
                                        modifier = Modifier.fillMaxWidth().height(52.dp),
                                        shape = RoundedCornerShape(12.dp),
                                        colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF2563EB))
                                    ) {
                                        if (isScanning) {
                                            CircularProgressIndicator(color = Color.White, modifier = Modifier.size(20.dp), strokeWidth = 2.dp)
                                        } else {
                                            Text(text = "🔍  Scan Now", fontSize = 15.sp, fontWeight = FontWeight.Medium)
                                        }
                                    }

                                    if (scanError != null) {
                                        Text(text = scanError, fontSize = 13.sp, color = Color(0xFFDC2626))
                                    }
                                }
                            }
                        }


                        if (scanHistory.isNotEmpty()) {
                            Card(
                                modifier = Modifier.fillMaxWidth(),
                                shape = RoundedCornerShape(24.dp),
                                colors = CardDefaults.cardColors(containerColor = Color.White),
                                elevation = CardDefaults.cardElevation(defaultElevation = 1.dp)
                            ) {
                                Column(modifier = Modifier.fillMaxWidth().padding(16.dp)) {
                                    Text(text = "Recent Scans", fontSize = 16.sp, fontWeight = FontWeight.Bold, color = Color(0xFF111827), modifier = Modifier.padding(bottom = 12.dp))

                                    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                                        scanHistory.take(3).forEach { scan ->
                                            val colors = getThreatColors(scan.threat)

                                            Row(
                                                modifier = Modifier
                                                    .fillMaxWidth()
                                                    .background(colors.backgroundColor, RoundedCornerShape(12.dp))
                                                    .border(1.dp, Color(0xFFE5E7EB), RoundedCornerShape(12.dp))
                                                    .padding(12.dp),
                                                horizontalArrangement = Arrangement.spacedBy(12.dp),
                                                verticalAlignment = Alignment.Top
                                            ) {
                                                Text(text = getThreatIcon(scan.threat), fontSize = 18.sp, modifier = Modifier.padding(top = 2.dp))

                                                Column(modifier = Modifier.weight(1f)) {
                                                    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                                                        Text(text = scan.type.uppercase(), fontSize = 11.sp, fontWeight = FontWeight.Bold, color = Color(0xFF6B7280))
                                                        Text(text = scan.timestamp, fontSize = 11.sp, color = Color(0xFF9CA3AF))
                                                    }
                                                    Spacer(modifier = Modifier.height(4.dp))
                                                    Text(text = scan.content, fontSize = 14.sp, fontFamily = FontFamily.Monospace, color = Color(0xFF111827), maxLines = 2, overflow = TextOverflow.Ellipsis)
                                                    Spacer(modifier = Modifier.height(2.dp))
                                                    Text(text = scan.details, fontSize = 12.sp, color = colors.textColor)
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // ==========================================
                    // 📜 HISTORY TAB VIEW
                    // ==========================================
                    "history" -> {
                        Card(
                            modifier = Modifier.fillMaxWidth(),
                            shape = RoundedCornerShape(24.dp),
                            colors = CardDefaults.cardColors(containerColor = Color.White),
                            elevation = CardDefaults.cardElevation(defaultElevation = 1.dp)
                        ) {
                            Column(modifier = Modifier.fillMaxWidth().padding(16.dp)) {
                                Text(text = "Scan History", fontSize = 18.sp, fontWeight = FontWeight.Bold, color = Color(0xFF111827), modifier = Modifier.padding(bottom = 12.dp))

                                if (scanHistory.isEmpty()) {
                                    Column(
                                        modifier = Modifier.fillMaxWidth().padding(vertical = 48.dp),
                                        horizontalAlignment = Alignment.CenterHorizontally,
                                        verticalArrangement = Arrangement.Center
                                    ) {
                                        Text(text = "🔍", fontSize = 48.sp, modifier = Modifier.padding(bottom = 12.dp))
                                        Text(
                                            text = "No scans yet. Start by scanning a URL, phone number, or message.",
                                            fontSize = 14.sp,
                                            color = Color(0xFF6B7280),
                                            textAlign = TextAlign.Center,
                                            modifier = Modifier.padding(horizontal = 16.dp)
                                        )
                                    }
                                } else {
                                    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                                        scanHistory.forEach { scan ->
                                            val colors = getThreatColors(scan.threat)

                                            Row(
                                                modifier = Modifier
                                                    .fillMaxWidth()
                                                    .background(colors.backgroundColor, RoundedCornerShape(12.dp))
                                                    .border(1.dp, Color(0xFFE5E7EB), RoundedCornerShape(12.dp))
                                                    .padding(12.dp),
                                                horizontalArrangement = Arrangement.spacedBy(12.dp),
                                                verticalAlignment = Alignment.Top
                                            ) {
                                                Text(text = getThreatIcon(scan.threat), fontSize = 18.sp, modifier = Modifier.padding(top = 2.dp))

                                                Column(modifier = Modifier.weight(1f)) {
                                                    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                                                        Text(text = scan.type.uppercase(), fontSize = 11.sp, fontWeight = FontWeight.Bold, color = Color(0xFF6B7280))
                                                        Text(text = scan.timestamp, fontSize = 11.sp, color = Color(0xFF9CA3AF))
                                                    }

                                                    Spacer(modifier = Modifier.height(4.dp))
                                                    Text(text = scan.content, fontSize = 14.sp, fontFamily = FontFamily.Monospace, color = Color(0xFF111827), maxLines = 3, overflow = TextOverflow.Ellipsis)
                                                    Spacer(modifier = Modifier.height(2.dp))
                                                    Text(text = scan.details, fontSize = 12.sp, color = colors.textColor)
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // ==========================================
                    // 📊 PRIVACY TAB VIEW
                    // ==========================================
                    "privacy" -> {
                        Card(
                            modifier = Modifier.fillMaxWidth(),
                            shape = RoundedCornerShape(24.dp),
                            border = BorderStroke(1.dp, Color(0xFFBBF7D0)),
                            colors = CardDefaults.cardColors(containerColor = Color(0xFFF0FDF4)),
                            elevation = CardDefaults.cardElevation(defaultElevation = 1.dp)
                        ) {
                            Column(modifier = Modifier.fillMaxWidth().padding(16.dp)) {
                                Row(
                                    modifier = Modifier.fillMaxWidth().padding(bottom = 16.dp),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Column {
                                        Text(text = "Privacy Health", fontSize = 18.sp, fontWeight = FontWeight.Bold, color = Color(0xFF111827))
                                        Text(text = "Your protection level", fontSize = 13.sp, color = Color(0xFF4B5563))
                                    }
                                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                                        Text(text = "$privacyScore", fontSize = 36.sp, fontWeight = FontWeight.Black, color = Color(0xFF16A34A))
                                        Text(text = "Score", fontSize = 12.sp, color = Color(0xFF4B5563))
                                    }
                                }

                                Box(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .height(8.dp)
                                        .background(Color(0xFFE5E7EB), CircleShape)
                                ) {
                                    val progressFraction = (privacyScore.coerceIn(0, 100) / 100f)
                                    Box(
                                        modifier = Modifier
                                            .fillMaxHeight()
                                            .fillMaxWidth(progressFraction)
                                            .background(
                                                brush = Brush.horizontalGradient(colors = listOf(Color(0xFF22C55E), Color(0xFF3B82F6))),
                                                shape = CircleShape
                                            )
                                    )
                                }
                            }
                        }

                        Spacer(modifier = Modifier.height(16.dp))

                        // Manage screen: both lists are read straight from the local database;
                        // "Remove" deletes the row (SQL DELETE) and the list refreshes by itself.
                        SiteListCard(
                            title = "Trusted Sites",
                            subtitle = "Scans of these sites are marked safe without running the checks",
                            emptyText = "No trusted sites yet",
                            items = whitelist,
                            onRemove = onRemoveWhitelist
                        )

                        Spacer(modifier = Modifier.height(16.dp))

                        SiteListCard(
                            title = "Blocked Sites",
                            subtitle = "Scans of these sites are always marked dangerous",
                            emptyText = "No blocked sites yet",
                            items = blacklist,
                            onRemove = onRemoveBlacklist
                        )

                        Spacer(modifier = Modifier.height(16.dp))

                        // Protection Tips Card Block
                        Card(
                            modifier = Modifier.fillMaxWidth(),
                            shape = RoundedCornerShape(24.dp),
                            colors = CardDefaults.cardColors(containerColor = Color.White),
                            elevation = CardDefaults.cardElevation(defaultElevation = 1.dp)
                        ) {
                            Column(modifier = Modifier.fillMaxWidth().padding(16.dp)) {
                                Row(
                                    modifier = Modifier.fillMaxWidth().padding(bottom = 12.dp),
                                    verticalAlignment = Alignment.CenterVertically,
                                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                                ) {
                                    Text(text = "🔒", fontSize = 20.sp)
                                    Text(text = "Protection Tips", fontSize = 16.sp, fontWeight = FontWeight.Bold, color = Color(0xFF111827))
                                }

                                Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                                    PrivacyTipItem(
                                        icon = "ℹ️",
                                        title = "Never share personal info via links",
                                        description = "Legitimate companies won't ask for passwords or credit card details through text or email."
                                    )
                                    PrivacyTipItem(
                                        icon = "👁️",
                                        title = "Verify sender identity",
                                        description = "Check email addresses and phone numbers carefully for suspicious variations."
                                    )
                                    PrivacyTipItem(
                                        icon = "⚠️",
                                        title = "Watch for urgency tactics",
                                        description = "Scammers create fake urgency to pressure quick decisions."
                                    )
                                    PrivacyTipItem(
                                        icon = "📈",
                                        title = "Enable two-factor authentication",
                                        description = "Add extra security to prevent unauthorized access."
                                    )
                                }
                            }
                        }

                        Spacer(modifier = Modifier.height(16.dp))

                        // Common Scam Types Card Block
                        Card(
                            modifier = Modifier.fillMaxWidth(),
                            shape = RoundedCornerShape(24.dp),
                            colors = CardDefaults.cardColors(containerColor = Color.White),
                            elevation = CardDefaults.cardElevation(defaultElevation = 1.dp)
                        ) {
                            Column(modifier = Modifier.fillMaxWidth().padding(16.dp)) {
                                Row(
                                    modifier = Modifier.fillMaxWidth().padding(bottom = 12.dp),
                                    verticalAlignment = Alignment.CenterVertically,
                                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                                ) {
                                    Text(text = "🚨", fontSize = 20.sp)
                                    Text(text = "Common Scam Types", fontSize = 16.sp, fontWeight = FontWeight.Bold, color = Color(0xFF111827))
                                }

                                Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                                    ScamTypeItem(
                                        title = "Phishing Emails",
                                        description = "Fake emails pretending to be from banks, delivery services, or tech companies."
                                    )
                                    ScamTypeItem(
                                        title = "Phone Scams",
                                        description = "Callers posing as government agencies, tech support, or family members in distress."
                                    )
                                    ScamTypeItem(
                                        title = "Prize/Lottery Scams",
                                        description = "Claims you've won a prize but need to pay fees or provide personal info first."
                                    )
                                    ScamTypeItem(
                                        title = "Romance Scams",
                                        description = "Fake profiles on dating sites building trust before asking for money."
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

// ==========================================
// 🕹️ CUSTOM SELECTOR TAB BUTTON COMPONENT
// ==========================================
@Composable
fun ScanTypeTabButton(
    label: String,
    emojiIcon: String,
    isSelected: Boolean,
    onClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    val interactionSource = remember { MutableInteractionSource() }
    val isPressed by interactionSource.collectIsPressedAsState()
    val buttonScale by animateFloatAsState(
        targetValue = if (isPressed) 0.95f else 1.0f,
        animationSpec = spring(stiffness = Spring.StiffnessLow),
        label = "ScaleAnimation"
    )

    val backgroundColor by animateColorAsState(
        targetValue = if (isSelected) Color(0xFF2563EB) else Color(0xFFF3F4F6),
        label = "ColorAnimation"
    )
    val textColor by animateColorAsState(
        targetValue = if (isSelected) Color.White else Color(0xFF374151),
        label = "TextColorAnimation"
    )

    Column(
        modifier = modifier
            .scale(buttonScale)
            .background(backgroundColor, RoundedCornerShape(12.dp))
            .clickable(interactionSource = interactionSource, indication = null, onClick = onClick)
            .padding(vertical = 12.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Text(text = emojiIcon, fontSize = 20.sp)
        Spacer(modifier = Modifier.height(4.dp))
        Text(text = label, fontSize = 12.sp, fontWeight = FontWeight.Medium, color = textColor)
    }
}

// ==========================================
// 🚨 3. THREAT ALERT POPUP OVERLAY
// ==========================================
@Suppress("DEPRECATION")
@Composable
fun ThreatAlertDialog(
    showThreatAlert: Boolean,
    threatAlertData: ThreatData?,
    onDismiss: () -> Unit,
    onTrust: (() -> Unit)? = null,      // "Trust this site" (only rendered for URL results)
    onBlacklist: (() -> Unit)? = null,  // "Block this site": same
    onUnblock: (() -> Unit)? = null,    // "Unblock this site" (state "blocked")
    onUntrust: (() -> Unit)? = null     // "Untrust this site" (state "trusted")
) {
    if (showThreatAlert && threatAlertData != null) {
        val clipboardManager = LocalClipboardManager.current
        // Which confirmation is open: "trust", "block" or null. Only these two buttons ask for confirmation.
        var confirm by remember { mutableStateOf<String?>(null) }

        Dialog(
            onDismissRequest = onDismiss,
            properties = DialogProperties(
                dismissOnBackPress = true,
                dismissOnClickOutside = true,
                usePlatformDefaultWidth = false
            )
        ) {
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 20.dp, vertical = 24.dp)
                    .heightIn(max = 550.dp),
                shape = RoundedCornerShape(24.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White),
                elevation = CardDefaults.cardElevation(defaultElevation = 24.dp)
            ) {
                Column(modifier = Modifier.fillMaxWidth()) {

                    // Three variants share one layout; only colors and texts differ: safe / warning / danger.
                    val isBlocked = threatAlertData.state == "blocked"
                    val isTrusted = threatAlertData.state == "trusted"
                    val isSafe = threatAlertData.threat == "safe"
                    val isDanger = threatAlertData.threat == "danger"
                    val accentColor = if (isSafe) Color(0xFF16A34A) else if (isDanger) Color(0xFFDC2626) else Color(0xFFD97706)
                    val boxBg = if (isSafe) Color(0xFFF0FDF4) else if (isDanger) Color(0xFFFEF2F2) else Color(0xFFFEFCE8)
                    val boxBorder = if (isSafe) Color(0xFFBBF7D0) else if (isDanger) Color(0xFFFEE2E2) else Color(0xFFFEF08A)
                    val strongText = if (isSafe) Color(0xFF14532D) else if (isDanger) Color(0xFF7F1D1D) else Color(0xFF713F12)
                    val softText = if (isSafe) Color(0xFF15803D) else if (isDanger) Color(0xFFB91C1C) else Color(0xFFA16207)
                    val headerGradient = when {
                        isSafe -> Brush.horizontalGradient(colors = listOf(Color(0xFF16A34A), Color(0xFF15803D)))
                        isDanger -> Brush.horizontalGradient(colors = listOf(Color(0xFFDC2626), Color(0xFFB91C1C)))
                        else -> Brush.horizontalGradient(colors = listOf(Color(0xFFD97706), Color(0xFFEA580C)))
                    }

                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .background(headerGradient)
                            .padding(horizontal = 16.dp, vertical = 20.dp)
                    ) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(12.dp),
                                modifier = Modifier.weight(1f)
                            ) {
                                Box(
                                    modifier = Modifier.size(44.dp).background(Color.White.copy(alpha = 0.2f), CircleShape),
                                    contentAlignment = Alignment.Center
                                ) {
                                    Text(text = if (isSafe) "✓" else if (isDanger) "🚨" else "⚠️", fontSize = 22.sp, color = Color.White, fontWeight = FontWeight.Bold)
                                }

                                Column {
                                    Text(text = if (isBlocked) "You blocked this site" else if (isTrusted) "You trust this site" else if (isSafe) "SAFE" else if (isDanger) "THREAT DETECTED!" else "WARNING!", fontSize = 18.sp, fontWeight = FontWeight.Bold, color = Color.White)
                                    Text(
                                        text = if (isBlocked) "Always marked as dangerous" else if (isTrusted) "Never warned about this address" else if (isSafe) (when (threatAlertData.type) { "url" -> "This link looks safe"; "phone" -> "This number looks safe"; else -> "This message looks safe" }) else if (isDanger) "Dangerous content found" else "Suspicious content found",
                                        fontSize = 13.sp,
                                        color = if (isSafe) Color(0xFFDCFCE7) else if (isDanger) Color(0xFFFEE2E2) else Color(0xFFFEF3C7)
                                    )
                                }
                            }

                            IconButton(
                                onClick = onDismiss,
                                modifier = Modifier.background(Color.White.copy(alpha = 0.2f), CircleShape).size(36.dp)
                            ) {
                                Text(text = "✕", color = Color.White, fontSize = 14.sp, fontWeight = FontWeight.Bold)
                            }
                        }
                    }

                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .verticalScroll(rememberScrollState())
                            .padding(16.dp)
                    ) {
                        val typeLabel = when (threatAlertData.type) {
                            "url" -> "Detected Link"
                            "phone" -> "Phone Number"
                            else -> "Message Content"
                        }

                        Text(text = typeLabel.uppercase(), fontSize = 11.sp, fontWeight = FontWeight.Medium, color = Color(0xFF6B7280), modifier = Modifier.padding(bottom = 8.dp))

                        Box(
                            modifier = Modifier
                                .fillMaxWidth()
                                .background(color = boxBg, shape = RoundedCornerShape(12.dp))
                                .border(width = 1.dp, color = boxBorder, shape = RoundedCornerShape(12.dp))
                                .padding(12.dp)
                        ) {
                            Text(text = threatAlertData.content ?: "", fontSize = 14.sp, color = strongText, modifier = Modifier.fillMaxWidth())
                        }

                        Spacer(modifier = Modifier.height(16.dp))

                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .background(color = boxBg, shape = RoundedCornerShape(12.dp))
                                .border(width = 1.dp, color = boxBorder, shape = RoundedCornerShape(12.dp))
                                .padding(16.dp),
                            horizontalArrangement = Arrangement.spacedBy(12.dp),
                            verticalAlignment = Alignment.Top
                        ) {
                            Text(text = if (isSafe) "✅" else "⚠️", fontSize = 18.sp, modifier = Modifier.padding(top = 2.dp))

                            Column(modifier = Modifier.weight(1f)) {
                                Text(text = if (isBlocked || isTrusted) "Reason" else if (isSafe) "No suspicious patterns found" else "Security Warning", fontWeight = FontWeight.Bold, fontSize = 14.sp, color = strongText, modifier = Modifier.padding(bottom = 6.dp))
                                // Model lines ("ML: 83% phishing probability") and notes, shown above the heuristic reasons
                                threatAlertData.infoLines.forEach { line ->
                                    Text(text = line, fontSize = 14.sp, fontWeight = FontWeight.SemiBold, color = strongText, modifier = Modifier.padding(bottom = 4.dp))
                                }
                                if (threatAlertData.reasons.isEmpty()) {
                                    Text(text = threatAlertData.details ?: "No extra details available.", fontSize = 14.sp, color = softText)
                                } else {
                                    // One bullet per reason, highest severity first (the scanner already sorts them)
                                    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                                        threatAlertData.reasons.forEach { reason ->
                                            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.Top) {
                                                Text(text = "•", fontSize = 14.sp, fontWeight = FontWeight.Bold, color = softText)
                                                Text(text = reason, fontSize = 14.sp, color = softText, modifier = Modifier.weight(1f))
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        if (!isBlocked && !isTrusted) {
                        Spacer(modifier = Modifier.height(20.dp))

                        Text(text = "What to do:", fontSize = 14.sp, fontWeight = FontWeight.Medium, color = Color(0xFF111827), modifier = Modifier.padding(bottom = 8.dp))

                        Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                            if (isSafe) {
                                val safeItem = when (threatAlertData.type) { "url" -> "Link appears safe to open"; "phone" -> "Number appears safe"; else -> "Message appears safe" }
                                SafetyTipRow(bullet = "✓", text = safeItem, isDanger = false, isSafe = true)
                                SafetyTipRow(bullet = "✓", text = "Still verify the sender if unexpected", isDanger = false, isSafe = true)
                                SafetyTipRow(bullet = "✓", text = "Avoid entering passwords or card details unless you trust the site", isDanger = false, isSafe = true)
                            } else if (isDanger) {
                                val itemType = if (threatAlertData.type == "url") "link" else "number"
                                SafetyTipRow(bullet = "✕", text = "Do not click or visit this $itemType", isDanger = true)
                                SafetyTipRow(bullet = "✕", text = "Do not share with others", isDanger = true)
                                SafetyTipRow(bullet = "✕", text = "Clear your clipboard immediately", isDanger = true)
                            } else {
                                SafetyTipRow(bullet = "!", text = "Verify the source before proceeding", isDanger = false)
                                SafetyTipRow(bullet = "!", text = "Check for signs of phishing or scams", isDanger = false)
                                SafetyTipRow(bullet = "!", text = "Proceed with caution if you continue", isDanger = false)
                            }
                        }
                        }

                        Spacer(modifier = Modifier.height(24.dp))

                        // Blocked / trusted sites: exactly two buttons (undo the choice + close). Normal result: three.
                        Column(verticalArrangement = Arrangement.spacedBy(12.dp), modifier = Modifier.fillMaxWidth()) {
                            // Trust / Block / Unblock / Untrust only make sense for a single URL.
                            // Message and phone results get just "I Understand".
                            if (!showSiteActions(threatAlertData.type)) {
                                // no site action buttons
                            } else if (isBlocked || isTrusted) {
                                Button(
                                    onClick = { (if (isBlocked) onUnblock else onUntrust)?.invoke() },   // DELETE, closes, no confirmation
                                    modifier = Modifier.fillMaxWidth().height(52.dp),
                                    shape = RoundedCornerShape(12.dp),
                                    colors = ButtonDefaults.buttonColors(containerColor = accentColor, contentColor = Color.White)
                                ) {
                                    Text(text = if (isBlocked) "Unblock this site" else "Untrust this site", fontSize = 15.sp, fontWeight = FontWeight.Bold)
                                }
                            } else {
                            // Whitelist: later scans of this site skip heuristics and ML and are marked SAFE
                            Button(
                                onClick = { confirm = "trust" },
                                modifier = Modifier.fillMaxWidth().height(52.dp),
                                shape = RoundedCornerShape(12.dp),
                                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF16A34A), contentColor = Color.White)
                            ) {
                                Text(text = "Trust this site", fontSize = 15.sp, fontWeight = FontWeight.Bold)
                            }
                            // Block: later scans of this site are always DANGEROUS
                            Button(
                                onClick = { confirm = "block" },
                                modifier = Modifier.fillMaxWidth().height(52.dp),
                                shape = RoundedCornerShape(12.dp),
                                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFDC2626), contentColor = Color.White)
                            ) {
                                Text(text = "Block this site", fontSize = 15.sp, fontWeight = FontWeight.Bold)
                            }
                            }
                            // Neutral button, no confirmation. For a risky result it also clears the clipboard
                            // (this is the old "Clear Clipboard & Close" action, merged here).
                            OutlinedButton(
                                onClick = {
                                    if (!isSafe) clipboardManager.setText(AnnotatedString(""))
                                    onDismiss()
                                },
                                modifier = Modifier.fillMaxWidth().height(52.dp),
                                shape = RoundedCornerShape(12.dp),
                                border = BorderStroke(1.dp, Color(0xFFD1D5DB)),
                                colors = ButtonDefaults.outlinedButtonColors(containerColor = Color.White, contentColor = Color(0xFF374151))
                            ) {
                                Text(text = "I Understand", fontSize = 15.sp, fontWeight = FontWeight.Medium)
                            }
                        }
                    }
                }
            }
        }

        // Confirmation for Trust / Block. Cancel saves nothing.
        confirm?.let { kind ->
            val isTrust = kind == "trust"
            AlertDialog(
                onDismissRequest = { confirm = null },
                title = { Text(text = if (isTrust) "Trust this site?" else "Block this site?", fontWeight = FontWeight.Bold) },
                text = {
                    Text(
                        text = if (isTrust) "You won't be warned about this address again."
                        else "This address will always be marked as dangerous."
                    )
                },
                confirmButton = {
                    TextButton(onClick = {
                        confirm = null
                        if (isTrust) onTrust?.invoke() else onBlacklist?.invoke()
                    }) {
                        Text(text = "Confirm", fontWeight = FontWeight.Bold, color = if (isTrust) Color(0xFF16A34A) else Color(0xFFDC2626))
                    }
                },
                dismissButton = {
                    TextButton(onClick = { confirm = null }) { Text(text = "Cancel", color = Color(0xFF374151)) }
                }
            )
        }
    }
}

/** Site actions (Trust / Block / Unblock / Untrust) are shown only when the scanned input is a URL. */
internal fun showSiteActions(type: String): Boolean = type == "url"

// A titled card listing hosts from the database, each with a "Remove" button.
@Composable
private fun SiteListCard(
    title: String,
    subtitle: String,
    emptyText: String,
    items: List<String>,
    onRemove: (String) -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(24.dp),
        colors = CardDefaults.cardColors(containerColor = Color.White),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp)
    ) {
        Column(modifier = Modifier.fillMaxWidth().padding(16.dp)) {
            Text(text = title, fontSize = 16.sp, fontWeight = FontWeight.Bold, color = Color(0xFF111827))
            Text(text = subtitle, fontSize = 12.sp, color = Color(0xFF6B7280), modifier = Modifier.padding(top = 2.dp, bottom = 8.dp))
            if (items.isEmpty()) {
                Text(text = emptyText, fontSize = 14.sp, color = Color(0xFF9CA3AF))
            } else {
                items.forEach { host ->
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(text = host, fontSize = 14.sp, color = Color(0xFF111827), modifier = Modifier.weight(1f))
                        TextButton(onClick = { onRemove(host) }) {
                            Text(text = "Remove", color = Color(0xFFDC2626))
                        }
                    }
                }
            }
        }
    }
}

// ==========================================
// ⚙️ HELPER REUSABLE UI ELEMENTS & COLOR UTILS
// ==========================================
private data class ThreatColorPalette(val backgroundColor: Color, val textColor: Color)

private fun getThreatColors(threat: String): ThreatColorPalette {
    return when (threat) {
        "safe" -> ThreatColorPalette(Color(0xFFF0FDF4), Color(0xFF16A34A))
        "warning" -> ThreatColorPalette(Color(0xFFFEFCE8), Color(0xFFD97706))
        else -> ThreatColorPalette(Color(0xFFFEF2F2), Color(0xFFDC2626))
    }
}

private fun getThreatIcon(threat: String): String {
    return when (threat) {
        "safe" -> "✅"
        "warning" -> "⚠️"
        else -> "🚨"
    }
}

@Composable
fun FeatureRow(text: String, iconColor: Color, isBold: Boolean = false) {
    Row(modifier = Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
        Text(text = "✓", fontSize = 14.sp, color = iconColor, fontWeight = FontWeight.Bold)
        Spacer(modifier = Modifier.width(8.dp))
        Text(text = text, fontSize = 13.sp, color = if (isBold) Color(0xFF111827) else Color(0xFF374151), fontWeight = if (isBold) FontWeight.SemiBold else FontWeight.Normal)
    }
}

@Composable
fun TrustItem(emoji: String, text: String) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Text(text = emoji, fontSize = 20.sp)
        Text(text = text, fontSize = 12.sp, color = Color(0xFF4B5563), fontWeight = FontWeight.Medium)
    }
}

@Composable
private fun SafetyTipRow(bullet: String, text: String, isDanger: Boolean, isSafe: Boolean = false) {
    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.Top) {
        Box(modifier = Modifier.padding(top = 2.dp).size(20.dp).background(color = if (isSafe) Color(0xFFDCFCE7) else if (isDanger) Color(0xFFFEE2E2) else Color(0xFFFEF08A), shape = CircleShape), contentAlignment = Alignment.Center) {
            Text(text = bullet, fontSize = 11.sp, fontWeight = FontWeight.Bold, color = if (isSafe) Color(0xFF16A34A) else if (isDanger) Color(0xFFDC2626) else Color(0xFFB45309))
        }
        Text(text = text, fontSize = 14.sp, color = Color(0xFF374151))
    }
}

@Composable
fun PrivacyTipItem(icon: String, title: String, description: String) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(Color(0xFFEFF6FF), RoundedCornerShape(16.dp))
            .padding(12.dp),
        horizontalArrangement = Arrangement.spacedBy(12.dp),
        verticalAlignment = Alignment.Top
    ) {
        Text(text = icon, fontSize = 18.sp, modifier = Modifier.padding(top = 2.dp))
        Column {
            Text(text = title, fontSize = 14.sp, fontWeight = FontWeight.Medium, color = Color(0xFF1F2937))
            Spacer(modifier = Modifier.height(2.dp))
            Text(text = description, fontSize = 12.sp, color = Color(0xFF4B5563), lineHeight = 16.sp)
        }
    }
}

@Composable
fun ScamTypeItem(title: String, description: String) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .background(Color(0xFFFEF2F2), RoundedCornerShape(16.dp))
            .border(BorderStroke(1.dp, Color(0xFFFECACA)), RoundedCornerShape(16.dp))
            .padding(12.dp)
    ) {
        Text(
            text = title,
            fontSize = 14.sp,
            fontWeight = FontWeight.Medium,
            color = Color(0xFF7F1D1D)
        )
        Spacer(modifier = Modifier.height(2.dp))
        Text(
            text = description,
            fontSize = 12.sp,
            color = Color(0xFFB91C1C),
            lineHeight = 16.sp
        )
    }
}

// ==========================================
// 📦 STRUCTURAL SHARED DATA MODELS
// ==========================================
data class ThreatData(
    val threat: String,
    val type: String,
    val content: String?,
    val details: String?,
    val reasons: List<String> = emptyList(), // every reason, shown as bullet points
    val infoLines: List<String> = emptyList(), // ML result / notes shown above the bullets
    val state: String = "scan"                 // "scan" (normal result) | "blocked" (user blocked it) | "trusted" (user trusts it)
)

data class DashboardStats(
    val scansToday: Int,
    val threatsBlocked: Int,
    val privacyAlerts: Int
)

data class ScanHistoryItem(
    val id: String,
    val type: String,
    val threat: String,
    val content: String,
    val details: String,
    val timestamp: String
)