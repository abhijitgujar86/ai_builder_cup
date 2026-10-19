package com.dhaal.app

import android.Manifest
import android.app.AppOpsManager
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Process
import android.provider.Settings
import android.speech.RecognizerIntent
import android.webkit.MimeTypeMap
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.activity.result.PickVisualMediaRequest
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.GenericShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject

sealed class Screen {
    object Login : Screen()
    object Home : Screen()
    object Check : Screen()
    object Busy : Screen()
    object Paid : Screen()
    data class Result(val v: Verdict) : Screen()
    data class Alarm(val title: String, val message: String, val level: String) : Screen()
    data class Error(val message: String) : Screen()
}

private val Ink = Color(0xFF1C1B19)
private val Paper = Color(0xFFF6F3EC)
private val CardBg = Color(0xFFFFFDF8)
private val Line = Color(0xFFE2DDD1)
private val Accent = Color(0xFF0B5D5B)
private val Muted = Color(0xFF5D5A53)
private val Danger = Color(0xFFB42318)
private val Novel = Color(0xFF6D28D9)
private val NovelBg = Color(0xFFF5F3FF)

// Brand mark: a simple shield (dhaal) polygon.
private val ShieldShape = GenericShape { size, _ ->
    val w = size.width
    val h = size.height
    moveTo(w / 2f, 0f)
    lineTo(w, h * 0.15f)
    lineTo(w, h * 0.5f)
    lineTo(w * 0.82f, h * 0.8f)
    lineTo(w / 2f, h)
    lineTo(w * 0.18f, h * 0.8f)
    lineTo(0f, h * 0.5f)
    lineTo(0f, h * 0.15f)
    close()
}

private fun levelColor(level: String) = when (level) {
    "CRITICAL" -> Color(0xFFB42318)
    "HIGH" -> Color(0xFFC2410C)
    "CAUTION" -> Color(0xFFB45309)
    else -> Color(0xFF3D5A80)
}

class MainActivity : ComponentActivity() {
    private lateinit var speaker: Speaker
    private var screen by mutableStateOf<Screen>(Screen.Home)
    private var lang by mutableStateOf("en")
    private var checkText by mutableStateOf("")
    private var attachment by mutableStateOf<Uri?>(null)
    private var permTick by mutableStateOf(0)
    private val checkTexts = mutableMapOf<String, String>() // verdict id -> text the user checked, for "Report"

    private val pickImage = registerForActivityResult(ActivityResultContracts.PickVisualMedia()) { uri ->
        if (uri != null) attachment = uri
    }
    private val pickAudio = registerForActivityResult(ActivityResultContracts.GetContent()) { uri ->
        if (uri != null) runCheck("", uri, null, "recording")
    }
    private val speech = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { res ->
        val heard = res.data?.getStringArrayListExtra(RecognizerIntent.EXTRA_RESULTS)?.firstOrNull()
        if (!heard.isNullOrBlank()) checkText = (checkText + " " + heard).trim()
    }
    private val notifPerm = registerForActivityResult(ActivityResultContracts.RequestPermission()) { permTick++ }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        speaker = Speaker(this)
        lang = Prefs.lang(this)
        Api.token = Prefs.token(this)
        Alerts.ensureChannels(this)
        handleIntent(intent)
        if (Api.token.isBlank()) screen = Screen.Login
        setContent {
            MaterialTheme(colorScheme = lightColorScheme(primary = Accent, background = Paper, surface = CardBg)) { AppRoot() }
        }
    }

    override fun onResume() {
        super.onResume()
        permTick++
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleIntent(intent)
    }

    override fun onDestroy() {
        speaker.shutdown()
        super.onDestroy()
    }

    private fun tr(en: String, hi: String) = if (lang == "hi") hi else en

    // ---------- intents ----------

    private fun handleIntent(i: Intent?) {
        if (i == null) return
        if (i.getBooleanExtra("sign_in", false)) {
            i.removeExtra("sign_in")
            screen = Screen.Login
            return
        }
        i.getStringExtra("verdict_json")?.let {
            screen = Screen.Result(Verdict.from(JSONObject(it)))
            i.removeExtra("verdict_json")
            return
        }
        i.getStringExtra("alarm_title")?.let { t ->
            val msg = i.getStringExtra("alarm_message").orEmpty()
            screen = Screen.Alarm(t, msg, i.getStringExtra("alarm_level") ?: "HIGH")
            speaker.speak("$t. $msg", Prefs.ttsLang(this))
            i.removeExtra("alarm_title")
            return
        }
        if (i.action == Intent.ACTION_SEND) {
            val type = i.type.orEmpty()
            val text = i.getStringExtra(Intent.EXTRA_TEXT).orEmpty()
            val uri = streamUri(i)
            i.action = null
            runCheck(text, uri, type, if (type.startsWith("audio")) "recording" else "share")
        }
    }

    @Suppress("DEPRECATION")
    private fun streamUri(i: Intent): Uri? =
        if (Build.VERSION.SDK_INT >= 33) i.getParcelableExtra(Intent.EXTRA_STREAM, Uri::class.java)
        else i.getParcelableExtra<Uri>(Intent.EXTRA_STREAM)

    private fun runCheck(text: String, uri: Uri?, mimeHint: String?, source: String) {
        if (text.isBlank() && uri == null) return
        screen = Screen.Busy
        lifecycleScope.launch {
            try {
                val json = withContext(Dispatchers.IO) {
                    val parts = mutableListOf<Api.Part>()
                    if (uri != null) {
                        val mime = contentResolver.getType(uri)
                            ?: mimeHint?.takeIf { '*' !in it } ?: "application/octet-stream"
                        val bytes = contentResolver.openInputStream(uri)?.use { it.readBytes() } ?: ByteArray(0)
                        val ext = MimeTypeMap.getSingleton().getExtensionFromMimeType(mime) ?: "bin"
                        parts += Api.Part("files", "upload.$ext", mime, bytes)
                    }
                    val fields = mapOf("text" to text, "source" to source, "lang" to Prefs.apiLang(this@MainActivity))
                    Api.postMultipart("/v1/check", fields, parts)
                }
                val v = Verdict.from(json)
                checkTexts[v.id] = text
                screen = Screen.Result(v)
                if (v.level == "HIGH" || v.level == "CRITICAL") speaker.speak(v.readAloud, v.lang)
            } catch (e: Api.AuthRequired) {
                screen = Screen.Login
            } catch (e: Exception) {
                screen = Screen.Error(e.message ?: "Network error")
            }
        }
    }

    private fun startVoice() {
        val i = Intent(RecognizerIntent.ACTION_RECOGNIZE_SPEECH)
            .putExtra(RecognizerIntent.EXTRA_LANGUAGE_MODEL, RecognizerIntent.LANGUAGE_MODEL_FREE_FORM)
            .putExtra(RecognizerIntent.EXTRA_LANGUAGE, Prefs.ttsLang(this))
        try {
            speech.launch(i)
        } catch (e: Exception) {
            screen = Screen.Error(tr("Voice input is not available on this phone.", "इस फोन पर बोलकर लिखना उपलब्ध नहीं है।"))
        }
    }

    private fun openWeb(hash: String) =
        startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(Api.BASE.trimEnd('/') + "/#" + hash)))

    private fun dial(number: String) =
        startActivity(Intent(Intent.ACTION_DIAL, Uri.parse("tel:" + number.filter { it.isDigit() || it == '+' })))

    private fun notifAccess() = NotificationManagerCompat.getEnabledListenerPackages(this).contains(packageName)

    private fun usageAccess(): Boolean {
        val ops = getSystemService(AppOpsManager::class.java) ?: return false
        return opMode(ops) == AppOpsManager.MODE_ALLOWED
    }

    @Suppress("DEPRECATION")
    private fun opMode(ops: AppOpsManager): Int =
        if (Build.VERSION.SDK_INT >= 29) ops.unsafeCheckOpNoThrow(AppOpsManager.OPSTR_GET_USAGE_STATS, Process.myUid(), packageName)
        else ops.checkOpNoThrow(AppOpsManager.OPSTR_GET_USAGE_STATS, Process.myUid(), packageName)

    private fun canNotify() = Build.VERSION.SDK_INT < 33 ||
        ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED

    // ---------- UI ----------

    @Composable
    private fun AppRoot() {
        BackHandler(enabled = screen != Screen.Home && screen != Screen.Login) {
            speaker.stop()
            screen = Screen.Home
        }
        Scaffold(containerColor = Paper) { pad ->
            Column(
                Modifier.padding(pad).fillMaxSize().verticalScroll(rememberScrollState())
                    .padding(horizontal = 18.dp, vertical = 12.dp)
            ) {
                Header()
                Gap(12)
                when (val s = screen) {
                    Screen.Login -> LoginScreen()
                    Screen.Home -> HomeScreen()
                    Screen.Check -> CheckScreen()
                    Screen.Busy -> BusyScreen()
                    Screen.Paid -> PaidScreen()
                    is Screen.Result -> ResultScreen(s.v)
                    is Screen.Alarm -> AlarmScreen(s)
                    is Screen.Error -> ErrorScreen(s.message)
                }
            }
        }
    }

    @Composable
    private fun Gap(h: Int) = Spacer(Modifier.height(h.dp))

    @Composable
    private fun Header() {
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            Box(Modifier.size(width = 34.dp, height = 38.dp).background(Accent, ShieldShape))
            Spacer(Modifier.width(10.dp))
            Column(Modifier.weight(1f)) {
                Text("Dhaal", fontSize = 24.sp, fontWeight = FontWeight.Bold, color = Ink)
                Text(tr("Your silent shield against scams.", "धोखेबाज़ों से आपकी खामोश ढाल।"), color = Muted, fontSize = 15.sp)
            }
            TextButton(onClick = {
                lang = if (lang == "hi") "en" else "hi"
                Prefs.setLang(this@MainActivity, lang)
            }) { Text(if (lang == "hi") "English" else "हिंदी", fontSize = 16.sp) }
        }
    }

    @Composable
    private fun Panel(borderColor: Color = Line, content: @Composable ColumnScope.() -> Unit) {
        Column(
            Modifier.fillMaxWidth().padding(bottom = 12.dp)
                .background(CardBg, RoundedCornerShape(14.dp))
                .border(if (borderColor == Line) 1.dp else 3.dp, borderColor, RoundedCornerShape(14.dp))
                .padding(16.dp),
            content = content
        )
    }

    @Composable
    private fun SectionTitle(t: String) {
        Gap(12)
        Text(t, fontWeight = FontWeight.Bold, fontSize = 17.sp, color = Ink)
        Gap(4)
    }

    @Composable
    private fun PrimaryButton(label: String, color: Color = Accent, onClick: () -> Unit) {
        Button(
            onClick = onClick,
            modifier = Modifier.fillMaxWidth().padding(top = 10.dp).heightIn(min = 54.dp),
            shape = RoundedCornerShape(12.dp),
            colors = ButtonDefaults.buttonColors(containerColor = color)
        ) { Text(label, fontSize = 18.sp, fontWeight = FontWeight.Bold) }
    }

    @Composable
    private fun BigButton(title: String, sub: String, danger: Boolean = false, onClick: () -> Unit) {
        OutlinedButton(
            onClick = onClick,
            modifier = Modifier.fillMaxWidth().padding(bottom = 10.dp),
            shape = RoundedCornerShape(14.dp),
            contentPadding = PaddingValues(16.dp)
        ) {
            Column(Modifier.fillMaxWidth()) {
                Text(title, fontWeight = FontWeight.Bold, fontSize = 18.sp, color = if (danger) Danger else Ink)
                Text(sub, fontSize = 14.sp, color = Muted)
            }
        }
    }

    @Composable
    private fun TrustedButton() {
        val num = Prefs.trustedNumber(this)
        if (num.isBlank()) return
        val name = Prefs.trustedName(this).ifBlank { num }
        PrimaryButton(tr("Call $name", "$name को कॉल करें")) { dial(num) }
    }

    @Composable
    private fun HomeScreen() {
        key(permTick) { ProtectionCard() }
        BigButton(tr("Check a message, photo or QR", "मैसेज, फोटो या QR जांचें"),
            tr("Paste, speak or add a screenshot", "लिखें, बोलें या स्क्रीनशॉट जोड़ें")) { screen = Screen.Check }
        BigButton(tr("Check a call recording", "कॉल रिकॉर्डिंग जांचें"),
            tr("Call recording or WhatsApp voice note", "कॉल रिकॉर्डिंग या WhatsApp वॉइस नोट")) { pickAudio.launch("audio/*") }
        BigButton(tr("Before I pay", "पैसे भेजने से पहले"), tr("Three quick questions", "तीन आसान सवाल")) { openWeb("pay") }
        BigButton(tr("Number, UPI ID or link", "नंबर, UPI ID या लिंक"), tr("Check who is asking", "कौन मांग रहा है, जांचें")) { openWeb("lookup") }
        BigButton(tr("Scams going around", "आजकल चल रहे धोखे"), tr("Learned from people's reports", "लोगों की रिपोर्ट से सीखा")) { openWeb("radar") }
        BigButton(tr("I already paid", "मैंने पैसे भेज दिए"), tr("First-hour steps, right now", "पहले घंटे के कदम, अभी"), danger = true) {
            screen = Screen.Paid
        }
        BigButton(tr("See a sample warning", "नमूना चेतावनी देखें"), tr("What the phone guard shows", "फोन गार्ड क्या दिखाता है")) {
            val t = tr("Is this a 'digital arrest' call?", "क्या यह 'डिजिटल अरेस्ट' कॉल है?")
            val m = tr("This is a long video call from an unknown number. Real police, CBI or courts never question or arrest anyone on a video call. You can hang up now.",
                "यह अनजान नंबर से लंबी वीडियो कॉल है। असली पुलिस, CBI या कोर्ट कभी वीडियो कॉल पर पूछताछ या गिरफ्तारी नहीं करते। आप अभी फोन काट सकते हैं।")
            screen = Screen.Alarm(t, m, "HIGH")
            speaker.speak("$t. $m", Prefs.ttsLang(this))
        }
        TrustedCard()
        TextButton(onClick = {
            Prefs.setToken(this@MainActivity, "")
            Api.token = ""
            screen = Screen.Login
        }) { Text(tr("Sign out", "साइन आउट"), color = Muted) }
    }

    @Composable
    private fun LoginScreen() {
        var user by remember { mutableStateOf("") }
        var pass by remember { mutableStateOf("") }
        var error by remember { mutableStateOf("") }
        var busy by remember { mutableStateOf(false) }
        Panel {
            Text(tr("Sign in", "साइन इन करें"), fontWeight = FontWeight.Bold, fontSize = 20.sp)
            Gap(8)
            OutlinedTextField(value = user, onValueChange = { user = it }, singleLine = true,
                label = { Text(tr("Username", "यूज़रनेम")) }, modifier = Modifier.fillMaxWidth())
            OutlinedTextField(value = pass, onValueChange = { pass = it }, singleLine = true,
                label = { Text(tr("Password", "पासवर्ड")) },
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                modifier = Modifier.fillMaxWidth())
            if (error.isNotBlank()) Text(error, color = Danger, modifier = Modifier.padding(top = 8.dp))
            PrimaryButton(if (busy) tr("Signing in…", "साइन इन हो रहा है…") else tr("Sign in", "साइन इन करें")) {
                if (busy) return@PrimaryButton
                busy = true
                error = ""
                lifecycleScope.launch {
                    try {
                        val r = withContext(Dispatchers.IO) {
                            Api.token = ""
                            Api.postJson("/v1/auth/login", JSONObject().put("username", user.trim()).put("password", pass))
                        }
                        val tok = r.getString("token")
                        Prefs.setToken(this@MainActivity, tok)
                        Api.token = tok
                        screen = Screen.Home
                    } catch (e: Api.AuthRequired) {
                        error = tr("Wrong username or password.", "यूज़रनेम या पासवर्ड गलत है।")
                    } catch (e: Exception) {
                        error = e.message ?: "Network error"
                    } finally {
                        busy = false
                    }
                }
            }
        }
    }

    @Composable
    private fun PermRow(label: String, ok: Boolean, onFix: () -> Unit) {
        Row(Modifier.fillMaxWidth().padding(top = 8.dp), verticalAlignment = Alignment.CenterVertically) {
            Text((if (ok) "✓  " else "•  ") + label, modifier = Modifier.weight(1f), fontSize = 16.sp,
                color = if (ok) Accent else Ink, fontWeight = if (ok) FontWeight.Normal else FontWeight.Bold)
            if (!ok) TextButton(onClick = onFix) { Text(tr("Turn on", "चालू करें")) }
        }
    }

    @Composable
    private fun ProtectionCard() {
        Panel {
            Text(tr("Background protection", "बैकग्राउंड सुरक्षा"), fontWeight = FontWeight.Bold, fontSize = 19.sp)
            Text(tr("Watches for risky moments during calls and scam messages.",
                "कॉल के दौरान जोखिम वाले पल और धोखे वाले मैसेज पहचानता है।"), color = Muted, fontSize = 14.sp)
            PermRow(tr("Message and call guard", "मैसेज और कॉल गार्ड"), notifAccess()) {
                startActivity(Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS))
            }
            PermRow(tr("Payment-app guard", "पेमेंट ऐप गार्ड"), usageAccess()) {
                startActivity(Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS))
            }
            PermRow(tr("Alerts", "अलर्ट"), canNotify()) {
                if (Build.VERSION.SDK_INT >= 33) notifPerm.launch(Manifest.permission.POST_NOTIFICATIONS)
            }
        }
    }

    @Composable
    private fun TrustedCard() {
        var name by remember { mutableStateOf(Prefs.trustedName(this)) }
        var num by remember { mutableStateOf(Prefs.trustedNumber(this)) }
        Panel {
            Text(tr("Someone you trust", "भरोसेमंद व्यक्ति"), fontWeight = FontWeight.Bold, fontSize = 17.sp)
            Text(tr("Shown as a one-tap call on every warning.", "हर चेतावनी पर एक टैप में कॉल।"), color = Muted, fontSize = 14.sp)
            OutlinedTextField(value = name, onValueChange = { name = it }, label = { Text(tr("Name", "नाम")) },
                modifier = Modifier.fillMaxWidth())
            OutlinedTextField(value = num, onValueChange = { num = it }, label = { Text(tr("Phone number", "फोन नंबर")) },
                modifier = Modifier.fillMaxWidth())
            TextButton(onClick = { Prefs.setTrusted(this@MainActivity, name.trim(), num.trim()) }) { Text(tr("Save", "सेव करें")) }
        }
    }

    @Composable
    private fun CheckScreen() {
        Panel {
            Text(tr("What did they say or send?", "उन्होंने क्या कहा या भेजा?"), fontWeight = FontWeight.Bold, fontSize = 18.sp)
            Gap(6)
            OutlinedTextField(
                value = checkText, onValueChange = { checkText = it },
                modifier = Modifier.fillMaxWidth().heightIn(min = 140.dp),
                placeholder = { Text(tr("Paste the message, or describe the call in your own words",
                    "मैसेज चिपकाएं, या कॉल के बारे में अपने शब्दों में बताएं")) }
            )
            Row(Modifier.fillMaxWidth().padding(top = 8.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = { startVoice() }, modifier = Modifier.weight(1f)) { Text(tr("Speak", "बोलिए")) }
                OutlinedButton(
                    onClick = { pickImage.launch(PickVisualMediaRequest(mediaType = ActivityResultContracts.PickVisualMedia.ImageOnly)) },
                    modifier = Modifier.weight(1f)
                ) { Text(if (attachment == null) tr("Add photo", "फोटो जोड़ें") else tr("Photo added ✓", "फोटो जुड़ी ✓")) }
            }
            PrimaryButton(tr("Check now", "अभी जांचें")) {
                val a = attachment
                attachment = null
                runCheck(checkText, a, null, "manual")
            }
            TextButton(onClick = { screen = Screen.Home }) { Text(tr("Back", "वापस")) }
        }
    }

    @Composable
    private fun BusyScreen() {
        Panel {
            Row(verticalAlignment = Alignment.CenterVertically) {
                CircularProgressIndicator(Modifier.size(28.dp))
                Spacer(Modifier.width(12.dp))
                Text(tr("Checking…", "जांच हो रही है…"), fontSize = 18.sp)
            }
        }
    }

    @Composable
    private fun ErrorScreen(msg: String) {
        Panel(borderColor = levelColor("CAUTION")) {
            Text(tr("Could not check right now", "अभी जांच नहीं हो पाई"), fontWeight = FontWeight.Bold, fontSize = 18.sp)
            Text(msg, color = Muted)
            Text(tr("If someone is asking for money, an OTP or an app install, do not do it. Hang up and call someone you trust.",
                "अगर कोई पैसे, OTP या ऐप इंस्टॉल मांग रहा है, तो न करें। फोन काटें और किसी भरोसेमंद व्यक्ति को कॉल करें।"))
            TrustedButton()
            TextButton(onClick = { screen = Screen.Home }) { Text(tr("Back", "वापस")) }
        }
    }

    @Composable
    private fun ResultScreen(v: Verdict) {
        val c = levelColor(v.level)
        Panel(borderColor = c) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(Modifier.size(14.dp).background(c, RoundedCornerShape(7.dp)))
                Spacer(Modifier.width(8.dp))
                Text(v.verdictLabel, color = c, fontSize = 24.sp, fontWeight = FontWeight.ExtraBold, modifier = Modifier.weight(1f))
                Text("${tr("Risk", "जोखिम")} ${v.score}/100", color = Muted, fontSize = 14.sp)
            }
            v.category?.let { Text(it, color = Muted, fontSize = 14.sp) }
            Gap(8)
            Text(v.summary, fontSize = 17.sp, color = Ink)
            v.seen?.let { s ->
                val col = if (s.novel) Novel else Accent
                Column(
                    Modifier.fillMaxWidth().padding(top = 10.dp)
                        .background(if (s.novel) NovelBg else Color(0xFFEEF6F5), RoundedCornerShape(12.dp))
                        .border(2.dp, col, RoundedCornerShape(12.dp)).padding(12.dp)
                ) {
                    val kicker = tr("SEEN BY OTHERS", "दूसरों ने भी देखा") + (if (s.novel) " · " + tr("NEW SCAM TYPE", "नया तरीका") else "")
                    Text(kicker, color = col, fontSize = 12.sp, fontWeight = FontWeight.Bold)
                    Text(s.title, fontWeight = FontWeight.ExtraBold, fontSize = 18.sp, color = Ink)
                    val meta = tr("Reported by ${s.reporters} people · ${s.last7d} in the last 7 days",
                        "${s.reporters} लोगों ने रिपोर्ट किया · पिछले 7 दिनों में ${s.last7d}") +
                        (if (s.demo) tr(" · demo data", " · डेमो डेटा") else "")
                    Text(meta, color = Muted, fontSize = 13.sp)
                    if (s.how.isNotBlank()) Text(s.how, fontSize = 15.sp, modifier = Modifier.padding(top = 4.dp))
                    if (s.warning.isNotBlank()) Text(s.warning, fontSize = 15.sp, fontWeight = FontWeight.Bold, modifier = Modifier.padding(top = 4.dp))
                }
            }
            if (v.doNow.isNotBlank()) {
                Column(
                    Modifier.fillMaxWidth().padding(vertical = 10.dp)
                        .background(Ink, RoundedCornerShape(12.dp)).padding(14.dp)
                ) {
                    Text(tr("DO THIS NOW", "अभी यह करें"), color = Color(0xFFBDB8AD), fontSize = 12.sp, fontWeight = FontWeight.Bold)
                    Text(v.doNow, color = Color.White, fontSize = 19.sp, fontWeight = FontWeight.Bold)
                }
            }
            if (v.flags.isNotEmpty()) {
                SectionTitle(tr("Signs I noticed", "जो संकेत दिखे"))
                v.flags.forEach { f ->
                    Column(
                        Modifier.fillMaxWidth().padding(bottom = 6.dp)
                            .border(1.dp, Line, RoundedCornerShape(10.dp)).padding(10.dp)
                    ) {
                        Text(f.label, fontWeight = FontWeight.SemiBold)
                        if (f.evidence.isNotBlank()) Text("“${f.evidence}”", color = Muted, fontStyle = FontStyle.Italic)
                    }
                }
            }
            v.fact?.let {
                SectionTitle(tr("Official fact", "सरकारी तथ्य"))
                Text(it, modifier = Modifier.fillMaxWidth().background(Color(0xFFEEF6F5), RoundedCornerShape(8.dp)).padding(10.dp))
            }
            if (v.sayThis.isNotBlank()) {
                SectionTitle(tr("Say this and end the call", "यह कहकर बात खत्म करें"))
                Text("“${v.sayThis}”", fontWeight = FontWeight.Bold)
            }
            if (v.steps.isNotEmpty()) {
                SectionTitle(tr("Steps", "कदम"))
                v.steps.forEachIndexed { i, s -> Text("${i + 1}. $s", modifier = Modifier.padding(bottom = 4.dp)) }
            }
            Gap(8)
            OutlinedButton(onClick = { speaker.speak(v.readAloud, v.lang) }, modifier = Modifier.fillMaxWidth()) {
                Text(tr("Read aloud", "सुनें"))
            }
            var reportMsg by remember(v.id) { mutableStateOf("") }
            var reporting by remember(v.id) { mutableStateOf(false) }
            OutlinedButton(onClick = {
                if (reporting || reportMsg.isNotBlank()) return@OutlinedButton
                reporting = true
                lifecycleScope.launch {
                    reportMsg = try {
                        withContext(Dispatchers.IO) {
                            Api.postJson("/v1/community/report", JSONObject()
                                .put("check_id", v.id).put("text", checkTexts[v.id].orEmpty()).put("summary", v.summary)
                                .put("lang", Prefs.ttsLang(this@MainActivity)).put("device", Prefs.device(this@MainActivity)))
                        }.optString("message")
                    } catch (e: Api.AuthRequired) {
                        screen = Screen.Login
                        ""
                    } catch (e: Exception) {
                        e.message ?: "Network error"
                    }
                    reporting = false
                }
            }, modifier = Modifier.fillMaxWidth().padding(top = 8.dp)) {
                Text(when {
                    reportMsg.isNotBlank() -> "✓"
                    reporting -> tr("Sending…", "भेज रहे हैं…")
                    else -> tr("Report to protect others", "रिपोर्ट करें, दूसरों को बचाएं")
                })
            }
            if (reportMsg.isNotBlank()) Text(reportMsg, color = Accent, fontWeight = FontWeight.SemiBold, modifier = Modifier.padding(top = 6.dp))
            TrustedButton()
            if (v.level != "LOW") {
                OutlinedButton(onClick = { screen = Screen.Paid }, modifier = Modifier.fillMaxWidth().padding(top = 8.dp)) {
                    Text(tr("I already paid", "मैंने पैसे भेज दिए"), color = Danger)
                }
            }
            TextButton(onClick = { speaker.stop(); screen = Screen.Home }) { Text(tr("Done", "ठीक है")) }
            if (v.degraded) Text(tr("Quick rules check (AI was unavailable)", "त्वरित नियम जांच (AI उपलब्ध नहीं था)"), color = Muted, fontSize = 12.sp)
        }
    }

    @Composable
    private fun AlarmScreen(a: Screen.Alarm) {
        Column(Modifier.fillMaxWidth().background(Danger, RoundedCornerShape(18.dp)).padding(20.dp)) {
            Text(a.level, color = Color.White.copy(alpha = 0.8f), fontWeight = FontWeight.Bold, fontSize = 14.sp)
            Text(a.title, color = Color.White, fontSize = 26.sp, fontWeight = FontWeight.ExtraBold)
            Gap(8)
            Text(a.message, color = Color.White, fontSize = 19.sp)
            Gap(16)
            val num = Prefs.trustedNumber(this@MainActivity)
            if (num.isNotBlank()) {
                Button(
                    onClick = { dial(num) }, modifier = Modifier.fillMaxWidth().heightIn(min = 54.dp),
                    colors = ButtonDefaults.buttonColors(containerColor = Color.White, contentColor = Danger)
                ) { Text(tr("Call ${Prefs.trustedName(this@MainActivity).ifBlank { num }}", "${Prefs.trustedName(this@MainActivity).ifBlank { num }} को कॉल करें"), fontWeight = FontWeight.Bold, fontSize = 18.sp) }
            }
            OutlinedButton(
                onClick = { speaker.speak("${a.title}. ${a.message}", Prefs.ttsLang(this@MainActivity)) },
                modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
                colors = ButtonDefaults.outlinedButtonColors(contentColor = Color.White)
            ) { Text(tr("Read aloud", "सुनें")) }
            OutlinedButton(
                onClick = { screen = Screen.Paid }, modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
                colors = ButtonDefaults.outlinedButtonColors(contentColor = Color.White)
            ) { Text(tr("I already paid", "मैंने पैसे भेज दिए")) }
            TextButton(onClick = { speaker.stop(); screen = Screen.Home }) { Text(tr("Close", "बंद करें"), color = Color.White) }
        }
    }

    @Composable
    private fun PaidScreen() {
        Panel(borderColor = Danger) {
            Text(tr("Act in the first hour", "पहले घंटे में कदम उठाएं"), fontWeight = FontWeight.ExtraBold, fontSize = 22.sp, color = Danger)
            Text(tr("Please don't worry. Calling quickly gives the best chance to freeze the money.",
                "चिंता न करें। जल्दी कॉल करने से पैसे रुकने की सबसे अच्छी संभावना है।"))
            PrimaryButton(tr("Call 1930 now", "अभी 1930 पर कॉल करें"), color = Danger) { dial("1930") }
            SectionTitle(tr("Keep ready", "तैयार रखें"))
            Text(tr("Amount, time, transaction ID (UTR), who you paid (UPI ID or account), your bank.",
                "रकम, समय, ट्रांज़ैक्शन ID (UTR), किसे भेजे (UPI ID या खाता), आपका बैंक।"))
            SectionTitle(tr("Then", "फिर"))
            listOf(
                tr("Call your bank's fraud line (number on your card or official app) and ask them to hold the money.",
                    "अपने बैंक की फ्रॉड हेल्पलाइन (कार्ड के पीछे या आधिकारिक ऐप वाला नंबर) पर कॉल कर पैसे रोकने को कहें।"),
                tr("Screenshot everything. Do not delete chats.", "सब कुछ का स्क्रीनशॉट लें। चैट डिलीट न करें।"),
                tr("File on cybercrime.gov.in within 24 hours.", "24 घंटे के अंदर cybercrime.gov.in पर शिकायत करें।"),
                tr("Never pay anyone who promises to recover your money for a fee.", "पैसे वापस दिलाने के नाम पर फीस मांगने वाले को कभी पैसे न दें।"),
            ).forEachIndexed { i, s -> Text("${i + 1}. $s", modifier = Modifier.padding(bottom = 4.dp)) }
            OutlinedButton(onClick = { openWeb("paid") }, modifier = Modifier.fillMaxWidth().padding(top = 10.dp)) {
                Text(tr("Write my complaint for me", "मेरी शिकायत लिखें"))
            }
            TrustedButton()
            TextButton(onClick = { screen = Screen.Home }) { Text(tr("Back", "वापस")) }
        }
    }
}
