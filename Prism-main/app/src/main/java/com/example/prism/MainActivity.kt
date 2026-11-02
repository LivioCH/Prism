package com.example.prism

import com.example.prism.data.ScanSource
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.viewModels
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext

class MainActivity : ComponentActivity() {
    private val viewModel: AppStateViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    AntiPhishingMainScreen(viewModel)
                }
            }
        }
    }
}

@Composable
fun AntiPhishingMainScreen(viewModel: AppStateViewModel) {
    val context = LocalContext.current

    val showToast: (String, String) -> Unit = { title, body ->
        Toast.makeText(context, "$title: $body", Toast.LENGTH_LONG).show()
    }

    // 1. First Entry: Show Welcome Screen
    if (viewModel.showFrontPage && !viewModel.isLoggedIn) {
        FrontWelcomeScreen(
            onGetStartedClick = {
                viewModel.showFrontPage = false
            }
        )
        return
    }

    // 2 & 3. Authentication Flow (Unified if/else chain ensures seamless sign-in/sign-up switching)
    if (!viewModel.isLoggedIn) {
        if (viewModel.showSignUp) {
            SignUpScreen(
                viewModel = viewModel,
                onBackToLogin = { viewModel.showSignUp = false },
                onShowMessage = showToast
            )
        } else {
            LoginScreen(
                viewModel = viewModel,
                onSignUpClick = { viewModel.showSignUp = true },
                onLoginSuccess = { viewModel.isLoggedIn = true },
                onShowMessage = { msg -> Toast.makeText(context, msg, Toast.LENGTH_LONG).show() },
                onPlanMessage = { title, body -> showToast(title, body) }
            )
        }
        return
    }

    // 4. Core Dashboard App Layout: Connects the real DashboardScreen from loginandsubscription.kt
    DashboardScreen(
        subscriptionPlan = viewModel.subscriptionPlan ?: SubscriptionPlan.FREE,
        privacyScore = viewModel.privacyScore.intValue,
        stats = DashboardStats(
            scansToday = viewModel.scansToday,
            threatsBlocked = viewModel.threatsBlocked,
            privacyAlerts = viewModel.privacyAlerts
        ),
        activeTab = viewModel.activeTab,
        clipboardMonitoring = viewModel.clipboardMonitoring,
        scanType = viewModel.scanType.name.lowercase(),
        scanInput = viewModel.scanInput,
        isScanning = viewModel.isScanning,
        // Transforms the list of ScanResult items to match the required ScanHistoryItem structures
        scanHistory = viewModel.scanHistory.map { result ->
            ScanHistoryItem(
                id = result.id,
                type = result.type.name.lowercase(),
                threat = result.threat.name.lowercase(),
                content = result.content,
                details = result.details,
                timestamp = formatAgo(result.timestamp)
            )
        },
        onToggleClipboardMonitoring = { newValue -> viewModel.clipboardMonitoring = newValue },
        onScanTypeChange = { newTypeStr ->
            val matchedType = ScanType.entries.find { it.name.equals(newTypeStr, ignoreCase = true) }
            if (matchedType != null) viewModel.scanType = matchedType
        },
        onScanInputChange = { viewModel.scanInput = it; viewModel.scanError = null },
        onExecuteScan = { viewModel.handleScan(onSafeScan = showToast) },
        onTabChange = { viewModel.activeTab = it },
        scanError = viewModel.scanError,
        whitelist = viewModel.whitelistItems.toList(),
        onRemoveWhitelist = { viewModel.removeFromWhitelist(it) },
        blacklist = viewModel.blacklistItems.toList(),
        onRemoveBlacklist = { viewModel.removeFromBlacklist(it) }
    )

    // 5. Threat Overlay Dialog Alert: Connects the real ThreatAlertDialog from loginandsubscription.kt
    if (viewModel.showThreatAlert && viewModel.threatAlertData != null) {
        val alertSource = viewModel.threatAlertData!!

        ThreatAlertDialog(
            showThreatAlert = viewModel.showThreatAlert,
            // Maps the data structure over to the required ThreatData format
            threatAlertData = ThreatData(
                threat = alertSource.threat.name.lowercase(),
                type = alertSource.type.name.lowercase(),
                content = alertSource.content,
                details = alertSource.details,
                reasons = alertSource.reasons.map { it.detail },
                infoLines = alertSource.infoLines,
                state = when (viewModel.threatAlertSource) {
                    ScanSource.BLACKLIST -> "blocked"
                    ScanSource.WHITELIST -> "trusted"
                    else -> "scan"
                }
            ),
            onDismiss = { viewModel.showThreatAlert = false },
            // Trust / Block act on the URL's host, so they are only enabled for URL results
            onTrust = if (alertSource.type == ScanType.URL) {
                { viewModel.trustCurrentUrl { msg -> Toast.makeText(context, msg, Toast.LENGTH_LONG).show() } }
            } else null,
            onBlacklist = if (alertSource.type == ScanType.URL) {
                { viewModel.blacklistCurrentUrl { msg -> Toast.makeText(context, msg, Toast.LENGTH_LONG).show() } }
            } else null,
            onUnblock = { viewModel.unblockCurrentUrl() },
            onUntrust = { viewModel.untrustCurrentUrl() }
        )
    }
}

/** "Just now" / "5 min ago" / "3 h ago" / "2 d ago" for the history list. */
internal fun formatAgo(timestamp: Long, now: Long = System.currentTimeMillis()): String {
    val minutes = ((now - timestamp) / 60_000).coerceAtLeast(0)
    return when {
        minutes < 1 -> "Just now"
        minutes < 60 -> "$minutes min ago"
        minutes < 24 * 60 -> "${minutes / 60} h ago"
        else -> "${minutes / (24 * 60)} d ago"
    }
}
