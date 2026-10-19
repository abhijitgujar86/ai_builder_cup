"use strict";
const $ = (id) => document.getElementById(id);
const store = { get: (k) => { try { return localStorage.getItem(k); } catch { return null; } },
                set: (k, v) => { try { localStorage.setItem(k, v); } catch {} } };

const I18N = {
  hi: {
    tagline: "धोखेबाज़ों से आपकी खामोश ढाल।", t_check: "मैसेज, फोटो या QR जांचें", t_check_s: "लिखें, बोलें या स्क्रीनशॉट लगाएं",
    t_rec: "कॉल रिकॉर्डिंग जांचें", t_rec_s: "रिकॉर्डिंग डालें या रिकॉर्ड करें", t_pay: "पैसे भेजने से पहले", t_pay_s: "तीन आसान सवाल",
    t_lookup: "नंबर, UPI ID या लिंक", t_lookup_s: "कौन मांग रहा है, जांचें", t_guard: "फोन गार्ड", t_guard_s: "बैकग्राउंड चेतावनियां देखें (डेमो)",
    t_paid: "मैंने पैसे भेज दिए", t_paid_s: "पहले घंटे के कदम, अभी", check_label: "उन्होंने क्या कहा या भेजा?",
    check_ph: "उदाहरण: CBI अफसर वीडियो कॉल पर है। कह रहा है मेरा आधार मनी लॉन्ड्रिंग केस में है, RBI वेरिफिकेशन खाते में 5 लाख भेजो, किसी को मत बताना।",
    speak: "बोलिए", attach: "फोटो / स्क्रीनशॉट / QR लगाएं", check_btn: "अभी जांचें", rec_hint: "कॉल रिकॉर्डिंग या WhatsApp वॉइस नोट डालें। या रिकॉर्ड दबाएं और फोन को स्पीकर वाली कॉल के पास रखें।",
    choose_audio: "ऑडियो फाइल चुनें", record: "रिकॉर्ड", amount: "रकम", to_whom: "किसको", why: "पैसे क्यों भेज रहे हैं?", why_ph: "जैसे: गिफ्ट पार्सल की कस्टम फीस",
    lookup_label: "फोन नंबर, UPI ID या लिंक", lookup_ctx: "उन्होंने खुद को क्या बताया? (वैकल्पिक)", lookup_ctx_ph: "जैसे: मुंबई पुलिस, SBI, बिजली दफ्तर",
    report: "धोखा रिपोर्ट करें", guard_hint: "फोन पर Dhaal बैकग्राउंड में जोखिम वाले पल पहचानता है। स्थिति चुनें और देखें यह क्या कहेगा।",
    g_oncall: "अनजान नंबर से कॉल पर", g_type: "कॉल का प्रकार", g_mins: "कॉल पर कितने मिनट", g_pay: "बैंक / UPI ऐप खोला", g_remote_i: "AnyDesk इंस्टॉल है",
    g_remote_r: "AnyDesk चल रहा है", g_otp: "कॉल के दौरान OTP आया", g_second: "दूसरी कॉल आ रही है", g_side: "WhatsApp फाइल से ऐप इंस्टॉल हुआ", simulate: "देखें",
    call1930: "अभी 1930 पर कॉल करें", call1930_s: "राष्ट्रीय साइबर फ्रॉड हेल्पलाइन", mins_ago: "कितने मिनट पहले?", method: "कैसे भेजे?", bank: "आपका बैंक",
    txn: "ट्रांज़ैक्शन ID (UTR)", what: "क्या हुआ?", attach_pay: "पेमेंट का स्क्रीनशॉट लगाएं", paid_btn: "मेरे कदम दिखाएं",
    trusted: "भरोसेमंद व्यक्ति (सिर्फ इस फोन पर सेव)", trusted_name: "नाम, जैसे राहुल", read: "सुनें", close: "बंद करें",
    footer: "Dhaal कभी नहीं कहता कि कुछ 100% सुरक्षित है, आपकी आवाज़ सेव नहीं करता, और कभी OTP नहीं मांगता।",
    do_now: "अभी यह करें", signs: "जो संकेत दिखे", fact: "सरकारी तथ्य", say: "यह कहकर बात खत्म करें", steps: "कदम", details: "तकनीकी जानकारी",
    yes: "हाँ", no: "नहीं", checking: "जांच हो रही है…", call_t: "को कॉल करें", copy: "कॉपी करें", copied: "कॉपी हो गया",
    q1: "क्या किसी कॉल या मैसेज पर यह पेमेंट करने को कहा गया?", q2: "क्या इसे गुप्त रखने या बैंक को न बताने को कहा गया?",
    q3: "क्या यह पेमेंट पैसे पाने के लिए है (इनाम, रिफंड, नौकरी, खरीदार)?", q4: "क्या आप अभी कॉल पर हैं?", q5: "क्या इसके लिए FD तोड़ रहे हैं, लोन ले रहे हैं या सोना बेच रहे हैं?",
    open_paid: "मैंने पैसे भेज दिए", stop: "रोकें", score: "जोखिम", signout: "साइन आउट",
  },
  en: {
    do_now: "Do this now", signs: "Signs I noticed", fact: "Official fact", say: "Say this and end the call", steps: "Steps", details: "Technical details",
    yes: "Yes", no: "No", checking: "Checking…", call_t: "Call", copy: "Copy", copied: "Copied",
    q1: "Did someone on a call or message ask you to make this payment?", q2: "Were you told to keep it secret or not tell the bank?",
    q3: "Is this payment so you can receive money (prize, refund, job, buyer)?", q4: "Are you on a call right now?", q5: "Are you breaking an FD, taking a loan or selling gold for this?",
    open_paid: "I already paid", stop: "Stop", score: "Risk", read: "Read aloud",
  },
};
let LANG = store.get("sv_lang") || "en";
const t = (k) => (I18N[LANG] && I18N[LANG][k]) || I18N.en[k] || k;
const EN_DEFAULTS = {};

function applyLang() {
  document.documentElement.lang = LANG;
  document.querySelectorAll("[data-lang]").forEach((b) => b.classList.toggle("on", b.dataset.lang === LANG));
  document.querySelectorAll("[data-i18n]").forEach((el) => {
    const k = el.dataset.i18n;
    if (!(k in EN_DEFAULTS)) EN_DEFAULTS[k] = el.textContent;
    el.textContent = LANG === "en" ? EN_DEFAULTS[k] : (I18N.hi[k] || EN_DEFAULTS[k]);
  });
  document.querySelectorAll("[data-i18n-ph]").forEach((el) => {
    const k = el.dataset.i18nPh, key = "ph_" + k;
    if (!(key in EN_DEFAULTS)) EN_DEFAULTS[key] = el.placeholder;
    el.placeholder = LANG === "en" ? EN_DEFAULTS[key] : (I18N.hi[k] || EN_DEFAULTS[key]);
  });
  renderPayQs();
}
const apiLang = () => (LANG === "hi" ? "hi-IN" : "auto");

// ---------- panels ----------
function showPanel(name) {
  document.querySelectorAll(".panel").forEach((p) => (p.hidden = p.id !== "panel-" + name));
  document.querySelectorAll(".tile").forEach((b) => b.classList.toggle("active", b.dataset.panel === name));
  $("result").innerHTML = "";
  $("panel-" + name).scrollIntoView({ behavior: "smooth", block: "start" });
}
document.querySelectorAll(".tile").forEach((b) => b.addEventListener("click", () => showPanel(b.dataset.panel)));
document.querySelectorAll("[data-lang]").forEach((b) => b.addEventListener("click", () => { LANG = b.dataset.lang; store.set("sv_lang", LANG); applyLang(); }));

// ---------- helpers ----------
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
function busy(btn, on) { btn.disabled = on; if (on) { btn.dataset.label = btn.textContent; btn.textContent = t("checking"); } else if (btn.dataset.label) btn.textContent = btn.dataset.label; }
async function api(path, opts) {
  const res = await fetch(path, opts);
  if (res.status === 401) { location.href = "/login?next=" + encodeURIComponent(location.pathname + location.hash); throw new Error("Sign in required"); }
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.detail || res.statusText);
  return body;
}
const postJson = (path, data) => api(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(data) });
function speak(text, lang) {
  if (!("speechSynthesis" in window) || !text) return;
  speechSynthesis.cancel();
  const u = new SpeechSynthesisUtterance(text);
  u.lang = lang || (LANG === "hi" ? "hi-IN" : "en-IN");
  const v = speechSynthesis.getVoices().find((x) => x.lang && x.lang.toLowerCase().startsWith(u.lang.slice(0, 2).toLowerCase()));
  if (v) u.voice = v;
  u.rate = 0.92;
  speechSynthesis.speak(u);
}
function trustedButton() {
  const num = (store.get("sv_trusted_num") || "").trim();
  if (!num) return "";
  const name = store.get("sv_trusted_name") || "";
  return `<a class="ghost" href="tel:${esc(num.replace(/[^\d+]/g, ""))}">${esc(t("call_t"))} ${esc(name || num)}</a>`;
}
function showError(e) { $("result").innerHTML = `<div class="card CAUTION"><p class="err">${esc(e.message || e)}</p></div>`; }
function spinner() { $("result").innerHTML = `<div class="card LOW"><p class="spinner">${esc(t("checking"))}</p></div>`; }

// ---------- full verdict ----------
let lastCheck = null;
function renderVerdict(v) {
  const flags = (v.red_flags || []).map((f) => `<li><b>${esc(f.label)}</b>${f.evidence ? `<q>${esc(f.evidence)}</q>` : ""}${f.why ? `<div>${esc(f.why)}</div>` : ""}</li>`).join("");
  const steps = (v.next_steps && v.next_steps.length ? v.next_steps : (v.playbook ? v.playbook.steps : [])).map((s) => `<li>${esc(s)}</li>`).join("");
  const clarify = (v.clarify || []).map((q, i) => `<div class="q"><p>${esc(q)}</p><div class="seg"><button data-cq="${i}" data-ans="Yes">${esc(t("yes"))}</button><button data-cq="${i}" data-ans="No">${esc(t("no"))}</button></div></div>`).join("");
  const qr = (v.qr || []).filter((q) => q.is_pay_request).map((q) => `<div class="fact"><b>QR:</b> ${esc(`Scanning this SENDS ₹${q.amount || "?"} to ${q.payee_name || ""} (${q.payee_vpa})`)}</div>`).join("");
  const sigs = (v.signals || []).map((s) => `<li>${esc(s.source)} · ${esc(s.detail || s.name)}</li>`).join("");
  const reportable = [...(v.extracted?.phones || []).map((p) => ["number", p]), ...(v.extracted?.upi_ids || []).map((u) => ["upi", u])];
  $("result").innerHTML = `
  <div class="card ${v.level}">
    <div class="band"><p class="verdict">${esc(v.verdict_label)}</p><span class="meter">${esc(t("score"))} ${v.score}/100</span></div>
    ${v.category ? `<p class="cat">${esc(v.category.name)} · ${esc(v.category.lever_name)}</p>` : ""}
    <p>${esc(v.summary)}</p>
    ${qr}
    <div class="donow"><small>${esc(t("do_now"))}</small>${esc(v.do_now)}</div>
    ${clarify ? `<div class="yn">${clarify}</div>` : ""}
    ${flags ? `<h3>${esc(t("signs"))}</h3><ul class="flags">${flags}</ul>` : ""}
    ${v.official_fact ? `<h3>${esc(t("fact"))}</h3><p class="fact">${esc(v.official_fact.text)}</p>` : ""}
    ${v.say_this ? `<h3>${esc(t("say"))}</h3><p class="say">“${esc(v.say_this)}”</p>` : ""}
    ${steps ? `<h3>${esc(t("steps"))}</h3><ol class="steps">${steps}</ol>` : ""}
    <div class="actions">
      <button class="ghost" id="rSpeak">${esc(t("read"))}</button>
      ${trustedButton()}
      ${v.level !== "LOW" ? `<button class="ghost" id="rPaid">${esc(t("open_paid"))}</button>` : ""}
      ${reportable.length ? `<button class="ghost" id="rReport">${esc(I18N[LANG]?.report || "Report as scam")}</button>` : ""}
    </div>
    <details><summary>${esc(t("details"))}</summary><ul>${sigs}</ul>
      <p>${v.degraded ? "Rules-only answer (AI unavailable)" : `Model: ${esc(v.model)}`} · ${v.latency_ms} ms · ${esc(v.lang)}</p></details>
  </div>`;
  $("rSpeak").onclick = () => speak(v.read_aloud, v.lang);
  if ($("rPaid")) $("rPaid").onclick = () => showPanel("paid");
  if ($("rReport")) $("rReport").onclick = async () => {
    for (const [type, value] of reportable) await postJson("/v1/report", { type, value, category: v.category?.id || null });
    $("rReport").textContent = "✓"; $("rReport").disabled = true;
  };
  $("result").querySelectorAll("[data-cq]").forEach((b) => b.addEventListener("click", () => {
    if (!lastCheck) return;
    const q = v.clarify[+b.dataset.cq];
    lastCheck.context = ((lastCheck.context || "") + `\n${q} ${b.dataset.ans}`).trim();
    runCheck(lastCheck);
  }));
  $("result").scrollIntoView({ behavior: "smooth", block: "start" });
  if (v.level === "CRITICAL" || v.level === "HIGH") speak(v.read_aloud, v.lang);
}

async function runCheck(req) {
  lastCheck = req;
  const fd = new FormData();
  fd.append("text", req.text || ""); fd.append("source", req.source || "manual"); fd.append("lang", apiLang());
  if (req.context) fd.append("context", req.context);
  (req.files || []).forEach((f) => fd.append("files", f, f.name || "upload"));
  spinner();
  try { renderVerdict(await api("/v1/check", { method: "POST", body: fd })); } catch (e) { showError(e); }
}

// ---------- check panel ----------
$("checkFiles").addEventListener("change", (e) => { $("checkFileList").textContent = [...e.target.files].map((f) => f.name).join(", "); });
$("checkBtn").addEventListener("click", async (e) => {
  busy(e.target, true);
  await runCheck({ text: $("checkText").value, files: [...$("checkFiles").files], source: "manual" });
  busy(e.target, false);
});
const SR = window.SpeechRecognition || window.webkitSpeechRecognition;
if (!SR) $("micBtn").hidden = true;
$("micBtn").addEventListener("click", () => {
  const rec = new SR();
  rec.lang = LANG === "hi" ? "hi-IN" : "en-IN"; rec.interimResults = true;
  const base = $("checkText").value ? $("checkText").value + " " : "";
  $("micBtn").classList.add("rec");
  rec.onresult = (ev) => { $("checkText").value = base + [...ev.results].map((r) => r[0].transcript).join(""); };
  rec.onend = () => $("micBtn").classList.remove("rec");
  rec.start();
});

// ---------- recording panel ----------
let recordedBlob = null, mediaRec = null;
$("recFile").addEventListener("change", (e) => { recordedBlob = null; $("recInfo").textContent = e.target.files[0]?.name || ""; });
$("recBtn").addEventListener("click", async () => {
  if (mediaRec && mediaRec.state === "recording") { mediaRec.stop(); return; }
  try {
    const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
    const chunks = []; mediaRec = new MediaRecorder(stream);
    mediaRec.ondataavailable = (ev) => chunks.push(ev.data);
    mediaRec.onstop = () => {
      stream.getTracks().forEach((tr) => tr.stop());
      recordedBlob = new Blob(chunks, { type: mediaRec.mimeType || "audio/webm" });
      $("recBtn").classList.remove("rec"); $("recBtn").textContent = I18N[LANG]?.record || "Record";
      $("recInfo").textContent = `● ${Math.round(recordedBlob.size / 1024)} KB`;
    };
    mediaRec.start(); $("recBtn").classList.add("rec"); $("recBtn").textContent = "■ " + t("stop");
  } catch (e) { showError(e); }
});
$("recCheckBtn").addEventListener("click", async (e) => {
  const file = recordedBlob ? new File([recordedBlob], "recording.webm", { type: recordedBlob.type }) : $("recFile").files[0];
  if (!file) return;
  busy(e.target, true);
  await runCheck({ text: "", files: [file], source: "recording" });
  busy(e.target, false);
});

// ---------- before I pay ----------
const payAns = {};
function renderPayQs() {
  const keys = [["asked_by_caller", "q1"], ["keep_secret", "q2"], ["to_receive_money", "q3"], ["on_call_now", "q4"], ["break_fd_or_loan", "q5"]];
  $("payQs").innerHTML = keys.map(([k, q]) => `<div class="q"><p>${esc(t(q))}</p><div class="seg">
    <button data-k="${k}" data-v="1" class="${payAns[k] === true ? "on" : ""}">${esc(t("yes"))}</button>
    <button data-k="${k}" data-v="0" class="${payAns[k] === false ? "on" : ""}">${esc(t("no"))}</button></div></div>`).join("");
  $("payQs").querySelectorAll("button").forEach((b) => b.addEventListener("click", () => { payAns[b.dataset.k] = b.dataset.v === "1"; renderPayQs(); }));
}
$("payBtn").addEventListener("click", async (e) => {
  busy(e.target, true); spinner();
  try {
    renderVerdict(await postJson("/v1/before-pay", { amount: $("payAmount").value, payee: $("payPayee").value, reason: $("payReason").value, lang: apiLang(), ...payAns }));
  } catch (err) { showError(err); }
  busy(e.target, false);
});

// ---------- lookup ----------
function lookupKind(v) {
  if (/^upi:\/\//i.test(v)) return "qr";
  if (/^[\w.\-]+@[a-z]+$/i.test(v)) return "upi";
  if (/[a-z]/i.test(v) && /\./.test(v)) return "link";
  return "number";
}
function renderSimple(v) {
  const sigs = (v.signals || []).map((s) => `<li>${esc(s.detail || s.name)}</li>`).join("");
  $("result").innerHTML = `<div class="card ${v.level}">
    <div class="band"><p class="verdict">${esc(v.level)}</p><span class="meter">${esc(t("score"))} ${v.score}/100</span></div>
    <p>${esc(v.message)}</p>${v.official_fact ? `<p class="fact">${esc(v.official_fact)}</p>` : ""}
    ${sigs ? `<ul class="flags">${sigs}</ul>` : ""}
    <p class="hint">${esc(v.verify_at || "")}</p>
    <div class="actions">${trustedButton()}</div></div>`;
}
$("lookupBtn").addEventListener("click", async (e) => {
  const val = $("lookupVal").value.trim(); if (!val) return;
  busy(e.target, true); spinner();
  try { renderSimple(await postJson(`/v1/check/${lookupKind(val)}`, { value: val, context: $("lookupCtx").value, lang: LANG })); }
  catch (err) { showError(err); }
  busy(e.target, false);
});
$("reportBtn").addEventListener("click", async () => {
  const val = $("lookupVal").value.trim(); const kind = lookupKind(val);
  if (!val || kind === "qr") return;
  try { const r = await postJson("/v1/report", { type: kind === "link" ? "url" : kind, value: val }); $("reportBtn").textContent = `✓ ${r.reports}`; }
  catch (err) { showError(err); }
});

// ---------- phone guard simulator ----------
function overlay(v) {
  $("ovLevel").textContent = v.level; $("ovTitle").textContent = v.title; $("ovMsg").textContent = v.message;
  $("ovReasons").innerHTML = (v.reasons || []).map((r) => `<li>${esc(r.detail)}</li>`).join("");
  const num = (store.get("sv_trusted_num") || "").trim();
  $("ovCall").hidden = !num;
  if (num) { $("ovCall").href = "tel:" + num.replace(/[^\d+]/g, ""); $("ovCall").textContent = `${t("call_t")} ${store.get("sv_trusted_name") || num}`; }
  $("overlay").hidden = false;
  $("ovSpeak").onclick = () => speak(v.title + ". " + v.message, v.lang);
  speak(v.title + ". " + v.message, v.lang);
}
$("ovClose").addEventListener("click", () => { $("overlay").hidden = true; speechSynthesis?.cancel(); });
$("guardBtn").addEventListener("click", async (e) => {
  busy(e.target, true);
  const onCall = $("gOnCall").checked;
  const ev = {
    on_call: onCall, call_type: onCall ? $("gType").value : "none", caller_known: !onCall,
    call_secs: (+$("gMins").value || 0) * 60, payment_app_foreground: $("gPay").checked, payment_app: $("gPay").checked ? "your UPI app" : null,
    remote_apps_installed: ($("gRemoteInst").checked || $("gRemoteRun").checked) ? ["com.anydesk.anydeskandroid"] : [],
    remote_app_running: $("gRemoteRun").checked, otp_received_during_call: $("gOtp").checked,
    second_call_during_call: $("gSecond").checked, new_sideload: $("gSideload").checked, lang: LANG,
  };
  try {
    const v = await postJson("/v1/events/device", ev);
    if (v.show_fullscreen) overlay(v);
    else $("result").innerHTML = `<div class="card ${v.level}"><p class="verdict">${esc(v.title)}</p><p>${esc(v.message)}</p><p class="meter">${esc(t("score"))} ${v.score}/100</p></div>`;
  } catch (err) { showError(err); }
  busy(e.target, false);
});

// ---------- I already paid ----------
$("pdShot").addEventListener("change", (e) => { $("pdShotInfo").textContent = e.target.files[0]?.name || ""; });
$("paidBtn").addEventListener("click", async (e) => {
  busy(e.target, true); spinner();
  const fd = new FormData();
  [["amount", "pdAmount"], ["minutes_ago", "pdMins"], ["method", "pdMethod"], ["bank", "pdBank"], ["payee", "pdPayee"], ["txn_id", "pdTxn"], ["what_happened", "pdWhat"]]
    .forEach(([k, id]) => { const val = $(id).value; if (val !== "") fd.append(k, val); });
  fd.append("lang", LANG === "hi" ? "hi-IN" : "en-IN");
  if ($("pdShot").files[0]) fd.append("screenshot", $("pdShot").files[0]);
  try {
    const g = await api("/v1/paid-guide", { method: "POST", body: fd });
    const card = Object.entries(g.card).filter(([, v]) => v).map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join("");
    $("result").innerHTML = `<div class="card CRITICAL">
      <p class="urgency">${esc(g.urgency)}</p>
      <a class="call1930" href="tel:1930">${esc(I18N[LANG]?.call1930 || "Call 1930 now")}</a>
      ${card ? `<dl class="kv">${card}</dl>` : ""}
      <h3>${esc(t("steps"))}</h3><ol class="steps">${g.steps.map((s) => `<li>${esc(s)}</li>`).join("")}</ol>
      <h3>cybercrime.gov.in</h3><div class="complaint" id="complaintText">${esc(g.complaint_text)}</div>
      <div class="actions"><button class="ghost" id="copyComplaint">${esc(t("copy"))}</button><button class="ghost" id="pSpeak">${esc(t("read"))}</button>${trustedButton()}</div>
      <p class="fact">${esc(g.warning)}</p></div>`;
    $("copyComplaint").onclick = async () => { try { await navigator.clipboard.writeText(g.complaint_text); $("copyComplaint").textContent = t("copied"); } catch {} };
    $("pSpeak").onclick = () => speak(g.read_aloud);
    speak(g.read_aloud);
  } catch (err) { showError(err); }
  busy(e.target, false);
});

// ---------- trusted person ----------
$("trustedName").value = store.get("sv_trusted_name") || "";
$("trustedNum").value = store.get("sv_trusted_num") || "";
$("trustedName").addEventListener("change", (e) => store.set("sv_trusted_name", e.target.value));
$("trustedNum").addEventListener("change", (e) => store.set("sv_trusted_num", e.target.value));

applyLang();
if ("speechSynthesis" in window) speechSynthesis.getVoices();
// The Android app deep-links here, e.g. /#paid or /#pay.
const deepLink = location.hash.slice(1);
if (deepLink && $("panel-" + deepLink)) showPanel(deepLink);
