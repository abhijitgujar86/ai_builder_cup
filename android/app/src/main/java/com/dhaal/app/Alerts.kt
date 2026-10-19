package com.dhaal.app

import android.annotation.SuppressLint
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import org.json.JSONObject

object Alerts {
    private const val CH_ALARM = "sv_alarm"
    private const val CH_MESSAGES = "sv_messages"

    fun ensureChannels(c: Context) {
        val nm = c.getSystemService(NotificationManager::class.java) ?: return
        nm.createNotificationChannel(NotificationChannel(CH_ALARM, "Scam alarms", NotificationManager.IMPORTANCE_HIGH))
        nm.createNotificationChannel(NotificationChannel(CH_MESSAGES, "Suspicious messages", NotificationManager.IMPORTANCE_HIGH))
    }

    private fun pending(c: Context, code: Int, intent: Intent): PendingIntent =
        PendingIntent.getActivity(c, code, intent, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)

    @SuppressLint("MissingPermission")
    private fun post(c: Context, id: Int, b: NotificationCompat.Builder) {
        try {
            NotificationManagerCompat.from(c).notify(id, b.build())
        } catch (e: SecurityException) {
            // Notifications not allowed: the spoken warning still plays.
        }
    }

    /** Full-screen-capable alarm for risky call situations. */
    fun alarm(c: Context, title: String, message: String, level: String) {
        ensureChannels(c)
        val open = Intent(c, MainActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP)
            .putExtra("alarm_title", title)
            .putExtra("alarm_message", message)
            .putExtra("alarm_level", level)
        val pi = pending(c, 1001, open)
        val b = NotificationCompat.Builder(c, CH_ALARM)
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setContentTitle(title)
            .setContentText(message)
            .setStyle(NotificationCompat.BigTextStyle().bigText(message))
            .setPriority(NotificationCompat.PRIORITY_MAX)
            .setCategory(NotificationCompat.CATEGORY_ALARM)
            .setAutoCancel(true)
            .setContentIntent(pi)
            .setFullScreenIntent(pi, true)
        post(c, 1001, b)
    }

    /** Heads-up for a scam message; tapping opens the full verdict. */
    fun scamMessage(c: Context, sender: String, verdict: JSONObject) {
        ensureChannels(c)
        val v = Verdict.from(verdict)
        val open = Intent(c, MainActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP)
            .putExtra("verdict_json", verdict.toString())
        val id = 2000 + (sender.hashCode() and 0x3ff)
        val title = if (Prefs.lang(c) == "hi") "संभावित धोखा: $sender" else "Possible scam: $sender"
        val b = NotificationCompat.Builder(c, CH_MESSAGES)
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setContentTitle(title)
            .setContentText(v.doNow.ifBlank { v.summary })
            .setStyle(NotificationCompat.BigTextStyle().bigText("${v.summary}\n${v.doNow}"))
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setAutoCancel(true)
            .setContentIntent(pending(c, id, open))
        post(c, id, b)
    }

    /** Server rejected the saved login; message checks pause until the user signs in again. */
    fun signInAgain(c: Context) {
        ensureChannels(c)
        val hi = Prefs.lang(c) == "hi"
        val open = Intent(c, MainActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP)
            .putExtra("sign_in", true)
        val b = NotificationCompat.Builder(c, CH_MESSAGES)
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setContentTitle(if (hi) "Dhaal: फिर से साइन इन करें" else "Dhaal: sign in again")
            .setContentText(if (hi) "साइन इन करने तक मैसेज की जांच रुकी है।" else "Message checks are paused until you sign in.")
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setAutoCancel(true)
            .setContentIntent(pending(c, 3001, open))
        post(c, 3001, b)
    }
}
