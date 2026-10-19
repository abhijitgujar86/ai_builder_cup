package com.dhaal.app

import android.app.Notification
import android.app.usage.UsageEvents
import android.app.usage.UsageStatsManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import androidx.core.content.ContextCompat
import org.json.JSONArray
import org.json.JSONObject
import java.util.concurrent.Executors

/**
 * All passive protection lives here: Android gives no ordinary app call audio, but call apps post
 * CATEGORY_CALL notifications, message apps post text, and usage access shows which app is in front.
 */
class GuardListenerService : NotificationListenerService() {

    private data class CallInfo(val key: String, val pkg: String, val title: String, val type: String,
                                val video: Boolean, val unknown: Boolean, val start: Long)

    private val io = Executors.newSingleThreadExecutor()
    private val main = Handler(Looper.getMainLooper())
    private var speaker: Speaker? = null
    private var call: CallInfo? = null
    private val alerted = mutableSetOf<String>()
    private val seen = LinkedHashSet<Int>()
    private var installReceiverOn = false

    override fun onListenerConnected() {
        Api.token = Prefs.token(this)
        Alerts.ensureChannels(this)
        speaker = Speaker(this)
        val f = IntentFilter(Intent.ACTION_PACKAGE_ADDED).apply { addDataScheme("package") }
        ContextCompat.registerReceiver(this, installReceiver, f, ContextCompat.RECEIVER_EXPORTED)
        installReceiverOn = true
    }

    override fun onListenerDisconnected() {
        if (installReceiverOn) unregisterReceiver(installReceiver)
        installReceiverOn = false
        main.removeCallbacksAndMessages(null)
        speaker?.shutdown()
        speaker = null
    }

    override fun onNotificationPosted(sbn: StatusBarNotification) {
        if (sbn.packageName == packageName) return
        val n = sbn.notification ?: return
        val extras = n.extras
        val title = extras.getCharSequence(Notification.EXTRA_TITLE)?.toString().orEmpty()
        val text = (extras.getCharSequence(Notification.EXTRA_BIG_TEXT)
            ?: extras.getCharSequence(Notification.EXTRA_TEXT))?.toString().orEmpty()

        if (n.category == Notification.CATEGORY_CALL) {
            onCallNotification(sbn, title, text)
            return
        }
        if (call != null && OTP_RE.containsMatchIn("$title $text")) {
            sendEvent("otp", JSONObject().put("otp_received_during_call", true))
        }
        if (sbn.packageName in MESSAGE_APPS && text.isNotBlank()) checkMessage(sbn.packageName, title, text)
    }

    override fun onNotificationRemoved(sbn: StatusBarNotification) {
        val c = call ?: return
        if (sbn.key != c.key) return
        // Ringing and ongoing call notifications often swap keys; re-check before ending the call.
        main.postDelayed({
            val next = activeNotifications?.firstOrNull { it.notification?.category == Notification.CATEGORY_CALL }
            if (next == null) endCall() else call = c.copy(key = next.key)
        }, 3000)
    }

    // ---------- calls ----------

    private fun onCallNotification(sbn: StatusBarNotification, title: String, text: String) {
        val c = call
        if (c != null) {
            if (sbn.key != c.key && sbn.packageName != c.pkg) {
                sendEvent("merge", JSONObject().put("second_call_during_call", true))
            }
            return
        }
        val video = "video" in "$title $text".lowercase() || "वीडियो" in "$title $text"
        val callType = when {
            sbn.packageName in WHATSAPP -> if (video) "whatsapp_video" else "whatsapp_voice"
            sbn.packageName in DIALERS -> "phone"
            else -> "other_voip"
        }
        val unknown = looksUnknown(title)
        call = CallInfo(sbn.key, sbn.packageName, title, callType, video, unknown, System.currentTimeMillis())
        alerted.clear()
        val ev = JSONObject()
        if (unknown && title.any { it.isDigit() }) ev.put("caller_number", title)
        sendEvent("start", ev)
        main.postDelayed(poll, 2000)
    }

    private fun endCall() {
        call = null
        alerted.clear()
        main.removeCallbacks(poll)
    }

    private val poll = object : Runnable {
        override fun run() {
            val c = call ?: return
            val front = recentForeground()
            val payApp = front.firstOrNull { it in PAYMENT_APPS }
            val remote = front.any { it in REMOTE_APPS }
            val secs = (System.currentTimeMillis() - c.start) / 1000
            if (payApp != null && c.unknown) {
                sendEvent("pay", JSONObject().put("payment_app_foreground", true).put("payment_app", PAYMENT_APPS[payApp]))
            }
            if (remote) sendEvent("remote", JSONObject().put("remote_app_running", true))
            if (c.video && c.unknown && secs >= 300) sendEvent("long", JSONObject())
            main.postDelayed(this, 2000)
        }
    }

    // MOVE_TO_FOREGROUND (== ACTIVITY_RESUMED) keeps minSdk below 29.
    @Suppress("DEPRECATION")
    private fun recentForeground(): Set<String> {
        val usm = getSystemService(UsageStatsManager::class.java) ?: return emptySet()
        val end = System.currentTimeMillis()
        val events = try { usm.queryEvents(end - 4000, end) } catch (ex: SecurityException) { return emptySet() }
        val ev = UsageEvents.Event()
        val out = mutableSetOf<String>()
        while (events.hasNextEvent()) {
            events.getNextEvent(ev)
            if (ev.eventType == UsageEvents.Event.MOVE_TO_FOREGROUND) out += ev.packageName
        }
        return out
    }

    /** Sends one device event per reason per call; shows the alarm if the server says so. */
    private fun sendEvent(reason: String, extra: JSONObject) {
        if (!alerted.add(reason)) return
        val c = call
        val body = JSONObject()
            .put("on_call", c != null)
            .put("call_type", c?.type ?: "none")
            .put("caller_known", c?.unknown == false)
            .put("call_secs", if (c == null) 0 else (System.currentTimeMillis() - c.start) / 1000)
            .put("remote_apps_installed", JSONArray(installedRemoteApps()))
            .put("lang", Prefs.lang(this))
        extra.keys().forEach { body.put(it, extra.get(it)) }
        io.execute {
            val r = try {
                Api.postJson("/v1/events/device", body, 8000)
            } catch (e: Api.AuthRequired) {
                Alerts.signInAgain(this)
                offlineVerdict(reason)
            } catch (e: Exception) {
                offlineVerdict(reason)
            }
            if (r != null && r.optBoolean("show_fullscreen")) main.post { raise(r) }
        }
    }

    private fun raise(r: JSONObject) {
        val title = r.optString("title")
        val msg = r.optString("message")
        Alerts.alarm(this, title, msg, r.optString("level"))
        speaker?.speak("$title. $msg", Prefs.ttsLang(this))
    }

    /** Same wording as the server, used when the network is down mid-scam. */
    private fun offlineVerdict(reason: String): JSONObject? {
        val hi = Prefs.lang(this) == "hi"
        val (t, m) = when (reason) {
            "pay" -> if (hi) "पैसे भेजने से पहले रुकिए" to "आप अनजान नंबर से कॉल पर हैं और पेमेंट ऐप खोला है। पहले फोन काटिए। कुछ बुरा नहीं होगा।"
                     else "Pause before you pay" to "You are on a call with an unknown number and opened a payment app. Hang up first. Nothing bad will happen."
            "long" -> if (hi) "क्या यह 'डिजिटल अरेस्ट' कॉल है?" to "असली पुलिस कभी वीडियो कॉल पर गिरफ्तारी नहीं करती। आप फोन काट सकते हैं।"
                      else "Is this a 'digital arrest' call?" to "Real police never arrest anyone on a video call. You can hang up now."
            "remote" -> if (hi) "कोई आपका फोन चला सकता है" to "रिमोट-कंट्रोल ऐप चल रहा है। बैंक ऐप न खोलें।"
                        else "Someone can control your phone" to "A remote-control app is running. Do not open your bank app."
            "otp" -> if (hi) "कॉल पर OTP कभी न बताएं" to "बैंक कभी OTP नहीं मांगता।"
                     else "Never read an OTP to a caller" to "Banks never ask for your OTP."
            else -> return null
        }
        return JSONObject().put("show_fullscreen", true).put("title", t).put("message", m).put("level", "HIGH")
    }

    private fun installedRemoteApps(): List<String> = REMOTE_APPS.filter { pkg ->
        try { packageManager.getPackageInfo(pkg, 0); true } catch (e: PackageManager.NameNotFoundException) { false }
    }

    @Suppress("DEPRECATION")
    private fun installerOf(pkg: String): String? = try {
        if (Build.VERSION.SDK_INT >= 30) packageManager.getInstallSourceInfo(pkg).installingPackageName
        else packageManager.getInstallerPackageName(pkg)
    } catch (ex: Exception) {
        null
    }

    private val installReceiver = object : BroadcastReceiver() {
        override fun onReceive(ctx: Context, intent: Intent) {
            if (intent.getBooleanExtra(Intent.EXTRA_REPLACING, false)) return
            val pkg = intent.data?.schemeSpecificPart ?: return
            val installer = installerOf(pkg)
            val sideloaded = installer != null && ("packageinstaller" in installer || installer in MESSAGE_APPS)
            when {
                pkg in REMOTE_APPS -> sendEvent("remote_installed", JSONObject())
                sideloaded -> sendEvent("sideload", JSONObject().put("new_sideload", true))
            }
        }
    }

    // ---------- messages ----------

    private fun checkMessage(pkg: String, sender: String, text: String) {
        val h = (pkg + sender + text).hashCode()
        if (!seen.add(h)) return
        if (seen.size > 300) seen.remove(seen.first())
        if (!suspicious(text)) return
        io.execute {
            try {
                val body = JSONObject().put("text", text).put("source", if (pkg in WHATSAPP) "whatsapp" else "sms")
                    .put("lang", Prefs.apiLang(this)).put("sender", sender)
                val r = Api.postJson("/v1/check/json", body, 20_000)
                val level = r.optString("level")
                if (level == "HIGH" || level == "CRITICAL") main.post { Alerts.scamMessage(this, sender, r) }
            } catch (e: Api.AuthRequired) {
                Alerts.signInAgain(this)
            } catch (e: Exception) {
                // Offline: skip; the prefilter alone is too noisy to alarm on.
            }
        }
    }

    companion object {
        private val WHATSAPP = setOf("com.whatsapp", "com.whatsapp.w4b")
        private val DIALERS = setOf("com.google.android.dialer", "com.samsung.android.incallui", "com.android.incallui",
            "com.android.dialer", "com.oneplus.dialer", "com.miui.voip", "com.android.server.telecom")
        private val MESSAGE_APPS = setOf("com.google.android.apps.messaging", "com.samsung.android.messaging",
            "com.android.mms", "com.whatsapp", "com.whatsapp.w4b", "org.telegram.messenger", "com.truecaller")
        private val PAYMENT_APPS = mapOf(
            "com.phonepe.app" to "PhonePe", "com.google.android.apps.nbu.paisa.user" to "Google Pay",
            "net.one97.paytm" to "Paytm", "in.org.npci.upiapp" to "BHIM", "com.sbi.lotusintouch" to "SBI YONO",
            "com.snapwork.hdfc" to "HDFC Bank", "com.csam.icici.bank.imobile" to "ICICI iMobile",
            "com.axis.mobile" to "Axis Mobile", "com.msf.kbank.mobile" to "Kotak", "com.dreamplug.androidapp" to "CRED",
            "com.mobikwik_new" to "MobiKwik")
        private val REMOTE_APPS = setOf("com.anydesk.anydeskandroid", "com.teamviewer.quicksupport.market",
            "com.teamviewer.teamviewer.market.mobile", "com.rustdesk.rustdesk", "com.sand.airdroid",
            "com.sand.airdroidbiz", "com.splashtop.remote.pad.v2")
        private val OTP_RE = Regex("""\b(otp|one[- ]time password|ओटीपी)\b""", RegexOption.IGNORE_CASE)
        private val NUMBERISH = Regex("""^[+\d\s()\-]{6,}$""")
        private val TRIGGERS = listOf("kyc", "otp", "upi", "pin", "account", "blocked", "bijli", "electricity", "refund",
            "prize", "lottery", "kbc", "parcel", "customs", "police", "cbi", "arrest", "warrant", "court", "rbi", "loan",
            "job", "task", "invest", "profit", "return", "reward", "apk", "anydesk", "urgent", "fine", "challan",
            "new number", "naya number", "paise", "पैसे", "खाता", "बिजली", "गिरफ्तार", "इनाम", "लॉटरी")
        private val LINK_OR_MONEY = Regex("""(https?://|www\.|\.apk\b|@[a-z]{2,}\b|₹|\brs\.?\s?\d|\binr\b)""", RegexOption.IGNORE_CASE)

        fun looksUnknown(title: String): Boolean {
            val t = title.trim()
            return t.isEmpty() || NUMBERISH.matches(t) || t.lowercase() in setOf("unknown", "private number", "unknown caller")
        }

        /** Cheap on-device gate so only suspicious texts leave the phone. */
        fun suspicious(text: String): Boolean {
            val low = text.lowercase()
            return LINK_OR_MONEY.containsMatchIn(low) || TRIGGERS.any { it in low }
        }
    }
}
