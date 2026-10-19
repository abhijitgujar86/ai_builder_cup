package com.dhaal.app

import android.content.Context
import android.speech.tts.TextToSpeech
import org.json.JSONArray
import org.json.JSONObject
import java.util.Locale

data class Flag(val label: String, val evidence: String, val why: String)

/** A scam pattern other Dhaal users reported that matches this check. */
data class Seen(
    val title: String,
    val how: String,
    val warning: String,
    val reporters: Int,
    val last7d: Int,
    val novel: Boolean,
    val demo: Boolean,
)

data class Verdict(
    val level: String,
    val score: Int,
    val verdictLabel: String,
    val category: String?,
    val summary: String,
    val doNow: String,
    val flags: List<Flag>,
    val fact: String?,
    val sayThis: String,
    val steps: List<String>,
    val readAloud: String,
    val lang: String,
    val degraded: Boolean,
    val id: String = "",
    val seen: Seen? = null,
) {
    companion object {
        private fun JSONArray?.strings(): List<String> =
            if (this == null) emptyList() else (0 until length()).map { optString(it) }.filter { it.isNotBlank() }

        fun from(j: JSONObject): Verdict {
            val flagsArr = j.optJSONArray("red_flags")
            val flags = if (flagsArr == null) emptyList() else (0 until flagsArr.length()).map {
                val f = flagsArr.getJSONObject(it)
                Flag(f.optString("label"), f.optString("evidence"), f.optString("why"))
            }
            val next = j.optJSONArray("next_steps").strings()
            val steps = next.ifEmpty { j.optJSONObject("playbook")?.optJSONArray("steps").strings() }
            return Verdict(
                level = j.optString("level", "LOW"),
                score = j.optInt("score"),
                verdictLabel = j.optString("verdict_label", j.optString("level")),
                category = j.optJSONObject("category")?.optString("name"),
                summary = j.optString("summary", j.optString("message")),
                doNow = j.optString("do_now"),
                flags = flags,
                // org.json returns "null" from optString on JSON null, so check isNull first.
                fact = when {
                    j.isNull("official_fact") -> null
                    j.optJSONObject("official_fact") != null -> j.getJSONObject("official_fact").optString("text")
                    else -> j.optString("official_fact").ifBlank { null }
                },
                sayThis = j.optString("say_this"),
                steps = steps,
                readAloud = j.optString("read_aloud", j.optString("message")),
                lang = j.optString("lang", "en-IN"),
                degraded = j.optBoolean("degraded"),
                id = j.optString("id"),
                seen = j.optJSONArray("community")?.optJSONObject(0)?.let {
                    Seen(it.optString("title"), it.optString("how_it_works"), it.optString("warning"),
                        it.optInt("reporters"), it.optInt("last_7d"), it.optBoolean("novel"), it.optBoolean("demo"))
                },
            )
        }
    }
}

object Prefs {
    private fun sp(c: Context) = c.getSharedPreferences("sv", Context.MODE_PRIVATE)
    fun lang(c: Context): String = sp(c).getString("lang", "en") ?: "en"
    fun setLang(c: Context, v: String) = sp(c).edit().putString("lang", v).apply()
    fun apiLang(c: Context) = if (lang(c) == "hi") "hi-IN" else "auto"
    fun ttsLang(c: Context) = if (lang(c) == "hi") "hi-IN" else "en-IN"
    fun token(c: Context): String = sp(c).getString("token", "") ?: ""
    fun setToken(c: Context, v: String) = sp(c).edit().putString("token", v).apply()
    fun trustedName(c: Context): String = sp(c).getString("trusted_name", "") ?: ""
    fun trustedNumber(c: Context): String = sp(c).getString("trusted_number", "") ?: ""
    fun setTrusted(c: Context, name: String, number: String) =
        sp(c).edit().putString("trusted_name", name).putString("trusted_number", number).apply()
    /** Random install id so the server can count distinct reporters; never tied to the user. */
    fun device(c: Context): String = sp(c).getString("device", null)
        ?: java.util.UUID.randomUUID().toString().also { sp(c).edit().putString("device", it).apply() }
}

/** Text-to-speech that queues the first utterance until the engine is ready. */
class Speaker(context: Context) : TextToSpeech.OnInitListener {
    private val tts = TextToSpeech(context.applicationContext, this)
    private var ready = false
    private var pending: Pair<String, String>? = null

    override fun onInit(status: Int) {
        ready = status == TextToSpeech.SUCCESS
        pending?.let { speak(it.first, it.second) }
        pending = null
    }

    fun speak(text: String, lang: String) {
        if (text.isBlank()) return
        if (!ready) { pending = text to lang; return }
        tts.setLanguage(Locale.forLanguageTag(lang.ifBlank { "en-IN" }))
        tts.setSpeechRate(0.92f)
        tts.speak(text, TextToSpeech.QUEUE_FLUSH, null, "sv")
    }

    fun stop() { tts.stop() }
    fun shutdown() { tts.shutdown() }
}
