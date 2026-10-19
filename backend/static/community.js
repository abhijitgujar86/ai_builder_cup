"use strict";
// Community learning UI: "seen by others" on verdicts, one-tap report, "Scams going around" panel, new-scam banner.
// Loads after app.js and reuses its globals ($, store, LANG, esc, api, showPanel).
(() => {
  const TXT = {
    en: {
      seen: "Seen by others", new_type: "New scam type", demo: "demo data",
      reported_by: (n, w) => `Reported by ${n} people · ${w} in the last 7 days`, variant: (c) => `Variant of: ${c}`,
      report_btn: "Report to protect others", reporting: "Sending…", also: "Also report at:",
      report_note: "Only an anonymous summary is shared, never your name or number.",
      t_radar: "Scams going around", t_radar_s: "Learned from people's reports",
      radar_intro: (n) => `Dhaal learns from every report. A new scam goes live here once ${n} different people report it, and from then on Dhaal warns everyone who gets something like it.`,
      stats: (live, novel, watching, reports) => `${live} live patterns · ${novel} new scam types · ${watching} being watched · ${reports} reports`,
      first_seen: "First seen", how: "How it works", do_this: "Do this", tricks: "Warning signs",
      banner: "New scam going around:", banner_more: "See how it works", close: "Close",
      share_paid: "Also warn others: share an anonymous report of what happened",
      empty: "No live patterns yet.", loading: "Loading…", trend: "Reports per day, last 14 days",
    },
    hi: {
      seen: "दूसरों ने भी देखा", new_type: "नया तरीका", demo: "डेमो डेटा",
      reported_by: (n, w) => `${n} लोगों ने रिपोर्ट किया · पिछले 7 दिनों में ${w}`, variant: (c) => `इसका नया रूप: ${c}`,
      report_btn: "रिपोर्ट करें, दूसरों को बचाएं", reporting: "भेज रहे हैं…", also: "यहां भी रिपोर्ट करें:",
      report_note: "सिर्फ बिना नाम की जानकारी साझा होती है, आपका नाम या नंबर कभी नहीं।",
      t_radar: "आजकल चल रहे धोखे", t_radar_s: "लोगों की रिपोर्ट से सीखा",
      radar_intro: (n) => `Dhaal हर रिपोर्ट से सीखता है। जब ${n} अलग-अलग लोग किसी नए धोखे की रिपोर्ट करते हैं, वह यहां दिखने लगता है और Dhaal ऐसा कुछ पाने वाले हर व्यक्ति को सावधान करता है।`,
      stats: (live, novel, watching, reports) => `${live} सक्रिय तरीके · ${novel} नए प्रकार · ${watching} पर नज़र · ${reports} रिपोर्ट`,
      first_seen: "पहली बार दिखा", how: "कैसे होता है", do_this: "यह करें", tricks: "चेतावनी संकेत",
      banner: "नया धोखा चल रहा है:", banner_more: "कैसे होता है, देखें", close: "बंद करें",
      share_paid: "दूसरों को भी बचाएं: जो हुआ उसकी बिना नाम की रिपोर्ट साझा करें",
      empty: "अभी कोई सक्रिय तरीका नहीं।", loading: "लोड हो रहा है…", trend: "पिछले 14 दिनों में रोज़ की रिपोर्ट",
    },
  };
  const T = (k) => (TXT[LANG] && TXT[LANG][k]) || TXT.en[k];
  const langParam = () => (LANG === "hi" ? "hi-IN" : "en-IN");

  const device = (() => {
    let d = store.get("sv_device");
    if (!d || !/^[A-Za-z0-9_-]{8,64}$/.test(d)) {
      d = (crypto.randomUUID ? crypto.randomUUID() : Date.now().toString(36) + Math.random().toString(36).slice(2)).replace(/[^A-Za-z0-9_-]/g, "");
      store.set("sv_device", d);
    }
    return d;
  })();
  const report = (body) => api("/v1/community/report", {
    method: "POST", headers: { "Content-Type": "application/json", "X-Dhaal-Device": device }, body: JSON.stringify(body),
  });

  function spark(tr) {
    if (!tr || !tr.length) return "";
    const mx = Math.max(1, ...tr), w = 8, g = 3, h = 26;
    const bars = tr.map((n, i) => {
      const bh = n ? Math.max(3, Math.round((n / mx) * h)) : 2;
      return `<rect x="${i * (w + g)}" y="${h - bh}" width="${w}" height="${bh}" rx="1.5"${n ? "" : ' class="z"'}/>`;
    }).join("");
    return `<svg class="cm-spark" width="${tr.length * (w + g)}" height="${h}" viewBox="0 0 ${tr.length * (w + g)} ${h}" role="img" aria-label="${esc(T("trend"))}">${bars}</svg>`;
  }
  const kicker = (label, p) => `<p class="cm-kicker">${esc(label)}${p.novel ? ` <span class="cm-badge">${esc(T("new_type"))}</span>` : ""}${p.demo ? ` <span class="cm-demo">${esc(T("demo"))}</span>` : ""}</p>`;
  const meta = (p) => esc(T("reported_by")(p.reporters, p.last_7d)) + (p.variant_of ? " · " + esc(T("variant")(p.variant_of)) : "");

  // ---------- verdict card ----------
  let pendingText = null; // text of the check whose verdict renders next
  const baseRun = window.runCheck;
  window.runCheck = (req) => { pendingText = req.text || ""; return baseRun(req); };
  const baseError = window.showError;
  window.showError = (e) => { pendingText = null; baseError(e); };

  const baseRender = window.renderVerdict;
  window.renderVerdict = (v) => {
    const text = pendingText;
    pendingText = null;
    baseRender(v);
    const card = $("result").querySelector(".card");
    if (!card) return;
    const m = (v.community || [])[0];
    if (m) {
      const seen = document.createElement("div");
      seen.className = "cm-seen" + (m.novel ? " novel" : "");
      seen.innerHTML = `${kicker(T("seen"), m)}<p class="cm-title">${esc(m.title)}</p><p class="cm-meta">${meta(m)}</p>
        <p>${esc(m.how_it_works)}</p>${m.warning ? `<p class="cm-warn">${esc(m.warning)}</p>` : ""}${spark(m.trend)}`;
      const anchor = card.querySelector(".donow");
      anchor ? anchor.before(seen) : card.querySelector(".band").after(seen);
    }
    const old = $("rReport");
    if (old) old.remove(); // the community report also records the numbers and UPI IDs
    const btn = document.createElement("button");
    btn.className = "ghost"; btn.id = "cmReport"; btn.textContent = T("report_btn");
    card.querySelector(".actions").append(btn);
    const out = document.createElement("div");
    out.className = "cm-result";
    out.innerHTML = `<p class="cm-note">${esc(T("report_note"))}</p>`;
    card.querySelector(".actions").after(out);
    btn.onclick = async () => {
      btn.disabled = true; btn.textContent = T("reporting");
      try {
        const r = await report({ check_id: v.id, text: text || "", summary: v.summary || "", lang: langParam() });
        out.innerHTML = `<p class="cm-thanks">${esc(r.message)}</p>${r.also_report_at ? `<p class="cm-note">${esc(T("also"))} ${esc(r.also_report_at)}</p>` : ""}`;
        btn.textContent = "✓";
        if (r.promoted) loadBanner(true);
      } catch (e) {
        out.innerHTML = `<p class="err">${esc(e.message || e)}</p>`;
        btn.disabled = false; btn.textContent = T("report_btn");
      }
    };
  };

  // ---------- "Scams going around" ----------
  const tile = document.createElement("button");
  tile.className = "tile"; tile.dataset.panel = "radar";
  tile.innerHTML = "<b></b><span></span>";
  document.querySelector(".tiles").insertBefore(tile, document.querySelector(".tile.danger"));
  const panel = document.createElement("section");
  panel.id = "panel-radar"; panel.className = "panel"; panel.hidden = true;
  panel.innerHTML = `<h2></h2><p class="hint" id="cmIntro"></p><p class="cm-stats" id="cmStats"></p><div class="cm-list" id="cmList"></div>`;
  $("panel-paid").after(panel);
  let radar = null;

  const patternCard = (p) => `<article class="cm-pattern${p.novel ? " novel" : ""}">
    ${kicker(p.novel ? T("new_type") : (p.variant_of ? T("variant")(p.variant_of) : ""), { ...p, novel: false })}
    <h3>${esc(p.title)}</h3><p class="cm-meta">${esc(T("reported_by")(p.reporters, p.last_7d))} · ${esc(T("first_seen"))} ${esc(p.first_seen)}</p>${spark(p.trend)}
    <small>${esc(T("how"))}</small><p>${esc(p.how_it_works)}</p>
    ${p.warning ? `<p class="cm-warn">${esc(p.warning)}</p>` : ""}
    ${p.do_now ? `<small>${esc(T("do_this"))}</small><p>${esc(p.do_now)}</p>` : ""}
    ${(p.flags || []).length || (p.new_tactics || []).length ? `<small>${esc(T("tricks"))}</small><ul class="cm-chips">${[...(p.new_tactics || []), ...(p.flags || [])].map((f) => `<li>${esc(f)}</li>`).join("")}</ul>` : ""}
  </article>`;
  function renderRadar() {
    if (!radar) return;
    $("cmIntro").textContent = T("radar_intro")(radar.promote_after);
    $("cmStats").textContent = T("stats")(radar.live, radar.novel, radar.watching, radar.reports);
    $("cmList").innerHTML = radar.patterns.length ? radar.patterns.map(patternCard).join("") : `<p class="hint">${esc(T("empty"))}</p>`;
  }
  async function loadRadar() {
    $("cmList").innerHTML = `<p class="spinner">${esc(T("loading"))}</p>`;
    try { radar = await api("/v1/community/patterns?lang=" + LANG); renderRadar(); }
    catch (e) { $("cmList").innerHTML = `<p class="err">${esc(e.message || e)}</p>`; }
  }
  tile.addEventListener("click", () => { showPanel("radar"); loadRadar(); });

  // ---------- new-scam banner: a pattern that went live in the last 72 hours ----------
  const seenKey = "sv_cm_dismissed";
  const dismissed = () => { try { return JSON.parse(store.get(seenKey) || "[]"); } catch { return []; } };
  let bannerPattern = null;
  async function loadBanner(force) {
    try {
      const d = await api("/v1/community/patterns?lang=" + LANG);
      const fresh = d.patterns.filter((p) => p.activated_at && Date.now() - Date.parse(p.activated_at) < 72 * 3600e3);
      bannerPattern = fresh.find((p) => force || !dismissed().includes(p.id)) || null;
      paintBanner();
    } catch {}
  }
  function paintBanner() {
    let b = $("cmBanner");
    if (!bannerPattern) { if (b) b.remove(); return; }
    if (!b) { b = document.createElement("div"); b.id = "cmBanner"; b.className = "cm-banner"; b.setAttribute("role", "status"); document.querySelector("main").prepend(b); }
    b.innerHTML = `<p><b>${esc(T("banner"))}</b> ${esc(bannerPattern.title)}. ${esc(bannerPattern.warning || "")}</p>
      <button type="button" id="cmBannerMore">${esc(T("banner_more"))}</button><button type="button" class="x" id="cmBannerX">${esc(T("close"))}</button>`;
    $("cmBannerMore").onclick = () => { showPanel("radar"); loadRadar(); };
    $("cmBannerX").onclick = () => { store.set(seenKey, JSON.stringify([...dismissed(), bannerPattern.id].slice(-50))); bannerPattern = null; paintBanner(); };
  }

  // ---------- "I already paid": confirmed victims teach Dhaal the most ----------
  const share = document.createElement("label");
  share.className = "cm-share";
  share.innerHTML = `<input type="checkbox" id="cmSharePaid"><span></span>`; // opt-in: the account may hold bank details
  $("paidBtn").before(share);
  let lastShared = "";
  $("paidBtn").addEventListener("click", () => {
    const what = $("pdWhat").value.trim();
    if (!$("cmSharePaid").checked || what.length < 12 || what === lastShared) return;
    lastShared = what;
    report({ text: what, lang: langParam() }).catch(() => { lastShared = ""; });
  });

  function paint() {
    tile.querySelector("b").innerHTML = `<span class="cm-live" aria-hidden="true"></span>${esc(T("t_radar"))}`;
    tile.querySelector("span").textContent = T("t_radar_s");
    panel.querySelector("h2").textContent = T("t_radar");
    share.querySelector("span").textContent = T("share_paid");
    const r = $("cmReport"); if (r && !r.disabled) r.textContent = T("report_btn");
    if (!panel.hidden) loadRadar();
    if (bannerPattern) loadBanner(false);
  }
  document.querySelectorAll("[data-lang]").forEach((b) => b.addEventListener("click", paint));
  paint();
  loadBanner(false);
  if (location.hash === "#radar") { showPanel("radar"); loadRadar(); }
})();
