#!/usr/bin/env python3
# app.py — OSINT-Web + Discord Token Login (alles in einer Datei)
# Install:  pip install flask requests dnspython phonenumbers exifread
# Start:    python app.py  →  http://127.0.0.1:5000

import hashlib, math, os, re, socket, string, subprocess, json
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote
import requests
from flask import Flask, request, jsonify, session, render_template_string, redirect, url_for

app = Flask(__name__)
app.secret_key = os.getenv("SECRET", "dev-secret-change-me")
S = requests.Session()
S.headers.update({"User-Agent": "Mozilla/5.0 (compatible; osintweb/1.0)"})
HIBP_KEY = os.environ.get("HIBP_API_KEY", "")
TIMEOUT = 12
DAPI = "https://discord.com/api/v10"
NITRO = {0: "kein Nitro", 1: "Nitro Classic", 2: "Nitro", 3: "Nitro Basic"}

# ────────────────────────── OSINT-Module ──────────────────────────

def fetch(url, **kw):
    try: return S.get(url, timeout=kw.pop("timeout", TIMEOUT), **kw)
    except requests.RequestException: return None

def dns_q(name, rtype):
    try:
        import dns.resolver
        return sorted(str(x).strip('"') for x in dns.resolver.resolve(name, rtype))
    except Exception: return []

def p_github(r):
    d = r.json()
    return {"name": d.get("name"), "bio": d.get("bio"), "ort": d.get("location"),
            "firma": d.get("company"), "blog": d.get("blog"), "email": d.get("email"),
            "twitter": d.get("twitter_username"), "erstellt": (d.get("created_at") or "")[:10],
            "repos": d.get("public_repos"), "follower": d.get("followers")} if "login" in (d or {}) else None

def p_reddit(r):
    d = r.json().get("data", {})
    return {"karma": d.get("total_karma"), "erstellt":
            datetime.fromtimestamp(d.get("created_utc", 0), timezone.utc).strftime("%Y-%m-%d")} if d.get("name") else None

def p_hn(r):
    d = r.json()
    return {"karma": d.get("karma"), "erstellt": (d.get("created_at") or "")[:10]} if d.get("username") else None

def p_keybase(r):
    d = r.json()
    them = (d.get("them") or []) if d.get("status", {}).get("code") == 0 else []
    if not them: return None
    return {"name": (them[0].get("profile") or {}).get("full_name"),
            "ort": (them[0].get("profile") or {}).get("location")}

def p_chess(r):
    d = r.json()
    return {"name": d.get("name"), "land": d.get("country"), "beitritt": (d.get("joined") or "")[:10]} if d.get("username") else None

def p_lichess(r):
    d = r.json()
    return {"titel": d.get("title"), "erstellt": (d.get("createdAt") or "")[:10]} if "username" in (d or {}) else None

def p_mastodon(r):
    d = r.json()
    return {"name": d.get("display_name"), "follower": d.get("followers_count"),
            "erstellt": (d.get("created_at") or "")[:10]} if "username" in (d or {}) else None

def p_steam(r):
    m = re.search(r"<steamID><!\[CDATA\[(.+?)\]\]>", r.text)
    return {"steamid": m.group(1)} if m else None

def p_telegram(r):
    if 'class="tgme_page_title"' not in r.text: return None
    t = re.search(r'class="tgme_page_title"[^>]*>(.*?)</span>', r.text, re.S)
    return {"titel": re.sub("<[^>]+>", "", t.group(1)).strip() if t else "?"}

def p_tiktok(r):
    d = r.json()
    return {"autor": d.get("author_name")} if d.get("author_name") else None

def p_generic(r):
    if r.status_code != 200 or len(r.text) < 500: return None
    if re.search(r"not found|nicht gefunden|page missing", r.text[:3000], re.I): return None
    return {"status": 200}

PLATFORMS = [
    ("GitHub",      "https://api.github.com/users/{u}",                              p_github),
    ("GitLab",      "https://gitlab.com/api/v4/users?username={u}",                  lambda r: ({"name": r.json()[0].get("name")} if isinstance(r.json(), list) and r.json() else None)),
    ("Reddit",      "https://www.reddit.com/user/{u}/about.json",                    p_reddit),
    ("HackerNews",  "https://hn.algolia.com/api/v1/users/{u}",                       p_hn),
    ("Keybase",     "https://keybase.io/_/api/1.0/user/lookup.json?usernames={u}",   p_keybase),
    ("Lichess",     "https://lichess.org/api/user/{u}",                              p_lichess),
    ("Chess.com",   "https://api.chess.com/pub/player/{u}",                          p_chess),
    ("Codeberg",    "https://codeberg.org/api/v1/users/{u}",                         p_github),
    ("Mastodon",    "https://mastodon.social/api/v1/accounts/lookup?acct={u}",       p_mastodon),
    ("DockerHub",   "https://hub.docker.com/v2/users/{u}/",                          p_github),
    ("npm",         "https://registry.npmjs.org/-/user/org.couchdb.user:{u}",        p_github),
    ("Bitbucket",   "https://api.bitbucket.org/2.0/users/{u}",                       p_github),
    ("Steam",       "https://steamcommunity.com/id/{u}?xml=1",                       p_steam),
    ("Telegram",    "https://t.me/{u}",                                              p_telegram),
    ("TikTok",      "https://www.tiktok.com/oembed?url=https://www.tiktok.com/@{u}", p_tiktok),
    ("Twitch",      "https://www.twitch.tv/{u}",                                     p_generic),
    ("SoundCloud",  "https://soundcloud.com/{u}",                                    p_generic),
    ("Pinterest",   "https://www.pinterest.com/{u}/",                                p_generic),
    ("Medium",      "https://medium.com/@{u}",                                       p_generic),
    ("DeviantArt",  "https://{u}.deviantart.com",                                    p_generic),
]

def username_sweep(u):
    def run(p):
        name, url, check = p
        r = fetch(url.format(u=quote(u)))
        info = None
        if r is not None:
            try: info = check(r)
            except Exception: info = None
        return {"plattform": name, "gefunden": bool(info), "daten": info or {},
                "url": url.format(u=quote(u))}
    with ThreadPoolExecutor(max_workers=10) as ex:
        return list(ex.map(run, PLATFORMS))

def scan_email(email):
    dom = email.split("@")[-1]
    gh = hashlib.md5(email.strip().lower().encode()).hexdigest()
    gr = fetch(f"https://gravatar.com/avatar/{gh}?d=404")
    kb = fetch(f"https://keybase.io/_/api/1.0/user/lookup.json?emails={quote(email)}")
    kb_hit = None
    them = ((kb.json() or {}).get("them") or []) if kb is not None else []
    if them:
        kb_hit = {"user": them[0].get("basics", {}).get("username"),
                  "name": (them[0].get("profile") or {}).get("full_name")}
    breaches = {"hinweis": "HIBP_API_KEY setzen für Leak-Daten"}
    if HIBP_KEY:
        r = fetch(f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(email)}",
                  headers={"hibp-api-key": HIBP_KEY})
        breaches = ([{"name": b["Name"], "jahr": b["BreachDate"][:4], "daten": b["DataClasses"]}
                     for b in r.json()] if r is not None and r.status_code == 200
                    else [] if r is not None and r.status_code == 404 else {"fehler": r.status_code if r else "timeout"})
    return {"syntax": bool(re.fullmatch(r"[^@\s]+@[^@\s]+\.[A-Za-z]{2,}", email)),
            "MX": dns_q(dom, "MX"),
            "SPF": [t for t in dns_q(dom, "TXT") if t.lower().startswith("v=spf1")],
            "gravatar": bool(gr is not None and gr.status_code == 200),
            "gravatar_url": f"https://gravatar.com/avatar/{gh}",
            "keybase": kb_hit, "leaks": breaches}

def scan_domain(dom):
    r = fetch(f"https://crt.sh/?q=%25.{dom}&output=json", timeout=40)
    subs = sorted({n.strip().lstrip("*.").lower()
                   for e in (r.json() if r is not None and r.status_code == 200 else [])
                   for n in (e.get("name_value") or "").split("\n")
                   if n.strip().lower().endswith(dom)})[:60]
    try:
        raw = subprocess.run(["whois", dom], capture_output=True, text=True, timeout=25).stdout
        who = {}
        for line in raw.splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                if any(t in k.lower() for t in ("registrar", "creation", "created", "expiry",
                        "name server", "country")) and v.strip():
                    who.setdefault(k.strip(), v.strip())
    except Exception:
        who = {"hinweis": "whois nicht installiert"}
    r2 = fetch(f"https://urlscan.io/api/v1/search/?q=domain:{quote(dom)}&size=50")
    ips, servers = set(), set()
    for it in ((r2.json() if r2 is not None else {}).get("results") or []):
        pg = it.get("page") or {}
        if pg.get("ip"): ips.add(pg["ip"])
        if pg.get("server"): servers.add(pg["server"])
    return {"DNS": {t: dns_q(dom, t) for t in ("A", "AAAA", "MX", "NS", "TXT")},
            "WHOIS": who, "subdomains": subs,
            "urlscan_ips": sorted(ips)[:15], "urlscan_server": sorted(servers)[:8]}

def scan_ip(ip):
    r = fetch(f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,"
              f"lat,lon,timezone,isp,org,as,reverse,proxy,hosting,mobile")
    d = r.json() if r is not None else {}
    try: ptr = socket.gethostbyaddr(ip)[0]
    except Exception: ptr = None
    return {"geo": d, "PTR": ptr}

def scan_phone(nr):
    try:
        import phonenumbers as P
        from phonenumbers import geocoder, carrier, number_type, PhoneNumberType
    except ImportError:
        return {"hinweis": "pip install phonenumbers"}
    try: n = P.parse(nr, None)
    except Exception as e: return {"fehler": str(e)}
    t = {PhoneNumberType.MOBILE: "mobil", PhoneNumberType.FIXED_LINE: "festnetz",
         PhoneNumberType.VOIP: "voip", PhoneNumberType.TOLL_FREE: "service"}
    return {"gueltig": P.is_valid_number(n),
            "E164": P.format_number(n, P.PhoneNumberFormat.E164),
            "land": P.region_code_for_number(n),
            "region": geocoder.description_for_number(n, "de"),
            "anbieter": carrier.name_for_number(n, "de") or None,
            "typ": t.get(number_type(n), "unbekannt")}

def scan_password(pw):
    sha1 = hashlib.sha1(pw.encode()).hexdigest().upper()
    r = fetch(f"https://api.pwnedpasswords.com/range/{sha1[:5]}")
    count = 0
    if r is not None and r.status_code == 200:
        for line in r.text.splitlines():
            h, c = line.split(":", 1)
            if h.strip() == sha1[5:]: count = int(c); break
    pool = sum([26 if any(c in string.ascii_lowercase for c in pw) else 0,
                26 if any(c in string.ascii_uppercase for c in pw) else 0,
                10 if any(c.isdigit() for c in pw) else 0,
                30 if any(c in "!@#$%^&*()-_=+[]{};:,.<>?/|~ " for c in pw) else 0])
    bits = len(pw) * math.log2(pool) if pool else 0
    return {"laenge": len(pw), "entropie_bits": round(bits, 1),
            "bewertung": "sehr schwach" if bits < 40 else "schwach" if bits < 60
                         else "mittel" if bits < 80 else "stark",
            "in_leaks": count > 0, "leak_vorkommen": count}

# ────────────────────────── Discord ──────────────────────────

def dapi(token, path):
    r = S.get(f"{DAPI}{path}", timeout=10, headers={"Authorization": token})
    return r.status_code, (r.json() if r.content else None)

def discord_profile(token):
    """Validiert User-Token und liefert Profil + Server. Kein 'Bot '-Präfix."""
    token = token.strip().strip('"').strip("'")
    status, me = dapi(token, "/users/@me")
    if status != 200:
        return None, f"Token ungültig (HTTP {status})"
    _, guilds = dapi(token, "/users/@me/guilds?with_counts=true")
    guilds = sorted(guilds or [], key=lambda g: -(g.get("approximate_member_count") or 0))
    ts = ((int(me["id"]) >> 22) + 1420070400000) / 1000
    return {
        "id": me["id"], "username": me["username"],
        "display": me.get("global_name") or me["username"],
        "email": me.get("email"), "phone": me.get("phone"),
        "mfa": me.get("mfa_enabled"), "verified": me.get("verified"),
        "nitro": NITRO.get(me.get("premium_type", 0), me.get("premium_type")),
        "created": datetime.fromtimestamp(ts, timezone.utc).strftime("%d.%m.%Y %H:%M UTC"),
        "avatar": (f"https://cdn.discordapp.com/avatars/{me['id']}/{me['avatar']}.png?size=128"
                   if me.get("avatar") else "https://cdn.discordapp.com/embed/avatars/0.png"),
        "guilds": [{"name": g["name"], "id": g["id"], "owner": g.get("owner"),
                    "mitglieder": g.get("approximate_member_count"),
                    "admin": bool(int(g.get("permissions", 0)) & 0x8)} for g in guilds[:15]],
        "guild_count": len(guilds),
    }, None

# ────────────────────────── API ──────────────────────────

def detect(t):
    if re.fullmatch(r"[^@\s]+@[^@\s]+\.[A-Za-z]{2,}", t): return "email"
    if re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", t): return "ip"
    if re.fullmatch(r"\+?\d[\d\s\-()]{6,}", t): return "phone"
    if re.fullmatch(r"(?:[a-z0-9-]+\.)+[a-z]{2,}", t, re.I): return "domain"
    return "user"

@app.post("/api/scan")
def api_scan():
    data = request.get_json(force=True)
    target = (data.get("target") or "").strip()
    mode = data.get("mode") or "auto"
    if not target:
        return jsonify({"error": "Kein Ziel angegeben"}), 400
    kind = detect(target) if mode == "auto" else mode
    try:
        if kind == "email":    res = scan_email(target)
        elif kind == "domain": res = scan_domain(target)
        elif kind == "ip":     res = scan_ip(target)
        elif kind == "phone":  res = scan_phone(target)
        elif kind == "password": res = scan_password(target)
        else:                  res = {"treffer": username_sweep(target)}
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    res["ziel"] = target; res["typ"] = kind
    res["zeit"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    return jsonify(res)

@app.post("/api/discord/login")
def discord_login():
    token = (request.get_json(force=True).get("token") or "").strip()
    if not token:
        return jsonify({"error": "Kein Token angegeben"}), 400
    profile, err = discord_profile(token)
    if err:
        return jsonify({"error": err}), 401
    session["dc_token"] = token
    return jsonify(profile)

@app.post("/api/discord/refresh")
def discord_refresh():
    token = session.get("dc_token")
    if not token:
        return jsonify({"error": "nicht eingeloggt"}), 401
    profile, err = discord_profile(token)
    if err:
        session.pop("dc_token", None)
        return jsonify({"error": err}), 401
    return jsonify(profile)

@app.post("/api/discord/logout")
def discord_logout():
    session.pop("dc_token", None)
    return jsonify({"ok": True})

@app.get("/api/export")
def api_export():
    payload = json.loads(request.args.get("d", "{}"))
    return Response(json.dumps(payload, indent=2, ensure_ascii=False),
                    mimetype="application/json",
                    headers={"Content-Disposition": "attachment; filename=osint-report.json"})

# ────────────────────────── UI ──────────────────────────


PAGE = r"""<!DOCTYPE html>
<html lang="de">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>OSINT Web</title>
<style>
:root {
  --bg: #05080d;
  --panel: #0b111b;
  --panel2: #101927;
  --border: #1c2938;
  --blue: #1677ff;
  --text: #e8eef7;
  --muted: #8391a5;
  --green: #20d6a1;
}
* {
  box-sizing: border-box;
}
body {
  margin: 0;
  background: var(--bg);
  color: var(--text);
  font-family: Inter, Arial, sans-serif;
}
.layout {
  display: flex;
  min-height: 100vh;
}
.sidebar {
  width: 245px;
  background: #080d14;
  border-right: 1px solid var(--border);
  padding: 25px 16px;
}
.logo {
  font-size: 22px;
  font-weight: 800;
  margin-bottom: 35px;
}
.logo span {
  color: var(--blue);
}
.nav-title {
  color: var(--muted);
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: 1.5px;
  margin: 25px 10px 12px;
}
.nav-item {
  padding: 12px;
  border-radius: 9px;
  margin-bottom: 5px;
  color: var(--muted);
  cursor: pointer;
}
.nav-item.active {
  color: white;
  background: #122644;
  border: 1px solid #1b3e6d;
}
.main {
  flex: 1;
  padding: 35px;
  max-width: 1500px;
}
.topbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 40px;
}
.status {
  display: flex;
  align-items: center;
  gap: 8px;
  color: var(--green);
  font-size: 13px;
}
.statusdot {
  width: 8px;
  height: 8px;
  background: var(--green);
  border-radius: 50%;
  box-shadow: 0 0 9px var(--green);
}
.hero h1 {
  font-size: 34px;
  margin: 0 0 12px;
}
.hero p {
  color: var(--muted);
  margin: 0 0 30px;
}
.searchbox {
  display: flex;
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 14px;
  padding: 10px;
  max-width: 850px;
  gap: 10px;
}
.searchbox input {
  flex: 1;
  min-width: 0;
  background: transparent;
  color: white;
  border: none;
  outline: none;
  padding: 14px;
  font-size: 15px;
}
.searchbox button {
  background: var(--blue);
  color: white;
  border: 0;
  border-radius: 9px;
  padding: 0 24px;
  cursor: pointer;
  font-weight: 700;
}
.section-title {
  margin: 40px 0 18px;
  font-size: 18px;
}
.tools {
  display: grid;
  grid-template-columns: repeat(auto-fit,minmax(210px,1fr));
  gap: 15px;
}
.tool {
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 14px;
  padding: 20px;
  cursor: pointer;
  transition: .2s;
}
.tool:hover {
  border-color: var(--blue);
  transform: translateY(-2px);
}
.tool-icon {
  font-size: 23px;
  margin-bottom: 15px;
}
.tool h3 {
  margin: 0 0 8px;
  font-size: 15px;
}
.tool p {
  color: var(--muted);
  font-size: 13px;
  line-height: 1.5;
  margin: 0;
}
.results {
  margin-top: 30px;
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 14px;
  padding: 22px;
  min-height: 100px;
}
.results h2 {
  font-size: 17px;
  margin-top: 0;
}
@media(max-width:800px) {
  .sidebar {
    display: none;
  }
  .main {
    padding: 20px;
  }
  .hero h1 {
    font-size: 27px;
  }
}
</style>
</head>
<body>
<div class="layout">
<aside class="sidebar">
  <div class="logo">OSINT<span>WEB</span></div>
  <div class="nav-title">Workspace</div>
  <div class="nav-item active">◈ Dashboard</div>
  <div class="nav-item">⌕ Search</div>
  <div class="nav-title">Tools</div>
  <div class="nav-item">◎ Username</div>
  <div class="nav-item">✉ Email</div>
  <div class="nav-item">⌘ Domain</div>
  <div class="nav-item">⌁ IP Address</div>
  <div class="nav-item">♧ Phone</div>
</aside>
<main class="main">
<header class="topbar">
  <strong>Workspace / Dashboard</strong>
  <div class="status"><span class="statusdot"></span> System online</div>
</header>
<section class="hero">
  <h1>OSINT Dashboard</h1>
  <p>Open-source intelligence tools in one workspace.</p>
  <div class="searchbox">
    <input id="target" placeholder="Enter username, email, domain, IP or phone..." />
    <button onclick="runScan()">Analyze</button>
  </div>
</section>
<h2 class="section-title">Investigation tools</h2>
<div class="tools">
  <div class="tool" onclick="setMode('username')">
    <div class="tool-icon">◎</div>
    <h3>Username Search</h3>
    <p>Search for public username profiles.</p>
  </div>
  <div class="tool" onclick="setMode('email')">
    <div class="tool-icon">✉</div>
    <h3>Email Lookup</h3>
    <p>Review publicly available email signals.</p>
  </div>
  <div class="tool" onclick="setMode('domain')">
    <div class="tool-icon">⌘</div>
    <h3>Domain Scan</h3>
    <p>DNS, registration and public subdomains.</p>
  </div>
  <div class="tool" onclick="setMode('ip')">
    <div class="tool-icon">⌁</div>
    <h3>IP Lookup</h3>
    <p>Review public IP information.</p>
  </div>
  <div class="tool" onclick="setMode('phone')">
    <div class="tool-icon">♧</div>
    <h3>Phone Lookup</h3>
    <p>Basic phone number information.</p>
  </div>
</div>
<div class="results" id="results">
  <h2>Results</h2>
  <p style="color:var(--muted)">Your analysis results will appear here.</p>
</div>
</main>
</div>

<script>
let mode = "username";

function setMode(m) {
  mode = m;

  document.querySelectorAll(".tool").forEach(el => {
    el.classList.remove("selected");
  });

  const input = document.getElementById("target");
  input.placeholder = "Enter target for " + m + " search...";
  input.focus();

  input.style.borderColor = "#1677ff";
  input.style.boxShadow = "0 0 12px rgba(22,119,255,.2)";
}
async function runScan() {
  const target = document.getElementById("target").value.trim();
  const results = document.getElementById("results");

  if (!target) {
    results.innerHTML = "<h2>Results</h2><p>Please enter a search target.</p>";
    return;
  }

  results.innerHTML = "<h2>Results</h2><p>Analyzing...</p>";

  try {
    const response = await fetch("/api/scan", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        mode: mode,
        target: target
      })
    });

    const data = await response.json();

    results.innerHTML = "<h2>Results</h2>";

    if (!response.ok) {
      results.innerHTML += "<p>Request failed.</p>";
      return;
    }

    results.innerHTML +=
      "<pre style='white-space:pre-wrap;overflow-wrap:anywhere'>" +
      JSON.stringify(data, null, 2) +
      "</pre>";

  } catch (error) {
    results.innerHTML =
      "<h2>Results</h2><p>Connection error: " +
      error.message +
      "</p>";
  }
}
</script>
</body>
</html>
"""


@app.get("/")
def index():
    return render_template_string(PAGE)

if __name__ == "__main__":
    print("→ http://127.0.0.1:5000  (HIBP optional: export HIBP_API_KEY=...)")
    app.run(host="127.0.0.1", port=5000, debug=False)
