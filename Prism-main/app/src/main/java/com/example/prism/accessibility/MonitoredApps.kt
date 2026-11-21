package com.example.prism.accessibility

/**
 * Packages worth watching, matching the communication channels named in the report
 * (WhatsApp, LINE, SMS, e-mail) plus the browsers where a clicked link actually opens.
 *
 * The service filters in code instead of using `android:packageNames` in the XML config so the
 * user can flip "monitor all apps" at runtime without reinstalling the service.
 */
object MonitoredApps {

    val BROWSERS: Set<String> = setOf(
        "com.android.chrome",
        "com.chrome.beta",
        "com.chrome.dev",
        "com.chrome.canary",
        "org.mozilla.firefox",
        "org.mozilla.firefox_beta",
        "org.mozilla.focus",
        "com.microsoft.emmx",
        "com.sec.android.app.sbrowser",
        "com.sec.android.app.sbrowser.beta",
        "com.brave.browser",
        "com.opera.browser",
        "com.opera.mini.native",
        "com.duckduckgo.mobile.android",
        "com.ecosia.android",
        "com.android.browser",
        "com.vivo.browser",
        "com.mi.globalbrowser",
        "com.heytap.browser",
        "com.transsion.phoenix",
        "com.UCMobile.intl",
        "com.quark.browser",
        "com.yandex.browser",
        "org.chromium.webview_shell"
    )

    val MESSAGING: Set<String> = setOf(
        "com.whatsapp",
        "com.whatsapp.w4b",
        "jp.naver.line.android",
        "org.telegram.messenger",
        "org.telegram.messenger.web",
        "org.thunderdog.challegram",
        "com.facebook.orca",
        "com.instagram.android",
        "com.google.android.apps.messaging",
        "com.android.mms",
        "com.samsung.android.messaging",
        "com.discord",
        "com.microsoft.teams",
        "com.slack",
        "com.viber.voip",
        "org.thoughtcrime.securesms",
        "com.kakao.talk",
        "com.tencent.mm",
        "com.google.android.talk"
    )

    val EMAIL: Set<String> = setOf(
        "com.google.android.gm",
        "com.microsoft.office.outlook",
        "com.yahoo.mobile.client.android.mail",
        "com.android.email",
        "com.samsung.android.email.provider",
        "com.fsck.k9"
    )

    val SOCIAL: Set<String> = setOf(
        "com.facebook.katana",
        "com.twitter.android",
        "com.linkedin.android",
        "com.zhiliaoapp.musically",
        "com.snapchat.android",
        "com.reddit.frontpage"
    )

    /** Apps that would only produce noise (or recursion) if scanned. */
    val IGNORED: Set<String> = setOf(
        "com.android.systemui",
        "com.android.settings",
        "com.google.android.permissioncontroller",
        "com.android.permissioncontroller",
        "com.android.packageinstaller",
        "com.google.android.packageinstaller",
        "com.android.launcher3",
        "com.google.android.apps.nexuslauncher",
        "com.sec.android.app.launcher",
        "com.miui.home",
        "com.android.keychain",
        "com.google.android.inputmethod.latin",
        "com.android.inputmethod.latin",
        "com.samsung.android.honeyboard"
    )

    private val FRIENDLY_NAMES: Map<String, String> = mapOf(
        "com.android.chrome" to "Chrome",
        "com.chrome.beta" to "Chrome Beta",
        "org.mozilla.firefox" to "Firefox",
        "com.microsoft.emmx" to "Edge",
        "com.sec.android.app.sbrowser" to "Samsung Internet",
        "com.brave.browser" to "Brave",
        "com.duckduckgo.mobile.android" to "DuckDuckGo",
        "com.whatsapp" to "WhatsApp",
        "com.whatsapp.w4b" to "WhatsApp Business",
        "jp.naver.line.android" to "LINE",
        "org.telegram.messenger" to "Telegram",
        "org.telegram.messenger.web" to "Telegram",
        "com.facebook.orca" to "Messenger",
        "com.instagram.android" to "Instagram",
        "com.google.android.apps.messaging" to "Messages",
        "com.android.mms" to "Messages",
        "com.samsung.android.messaging" to "Samsung Messages",
        "com.discord" to "Discord",
        "com.microsoft.teams" to "Teams",
        "com.slack" to "Slack",
        "com.viber.voip" to "Viber",
        "org.thoughtcrime.securesms" to "Signal",
        "com.kakao.talk" to "KakaoTalk",
        "com.tencent.mm" to "WeChat",
        "com.google.android.gm" to "Gmail",
        "com.microsoft.office.outlook" to "Outlook",
        "com.yahoo.mobile.client.android.mail" to "Yahoo Mail",
        "com.facebook.katana" to "Facebook",
        "com.twitter.android" to "X",
        "com.linkedin.android" to "LinkedIn",
        "com.zhiliaoapp.musically" to "TikTok",
        "com.snapchat.android" to "Snapchat",
        "com.reddit.frontpage" to "Reddit"
    )

    val ALL: Set<String> = BROWSERS + MESSAGING + EMAIL + SOCIAL

    fun isBrowser(packageName: String?): Boolean = packageName != null && packageName in BROWSERS

    fun isMonitored(packageName: String?): Boolean = packageName != null && packageName in ALL

    fun displayName(packageName: String?): String {
        if (packageName.isNullOrBlank()) return "your screen"
        FRIENDLY_NAMES[packageName]?.let { return it }
        val tail = packageName.substringAfterLast('.')
        return tail.replaceFirstChar { it.uppercase() }.ifBlank { packageName }
    }
}
