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

PAGE = r"""<!doctype html><html lang="de"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>OSINT-Web — passives Recon</title>
<style>
:root{--bg:#0d1117;--card:#161b22;--border:#30363d;--txt:#e6edf3;--dim:#8b949e;
--acc:#5865f2;--ok:#3fb950;--bad:#f85149;--warn:#d29922}
*{box-sizing:border-box}body{background:var(--bg);color:var(--txt);font-family:system-ui;margin:0;min-height:100vh}
.wrap{max-width:960px;margin:0 auto;padding:32px 20px}
.top{display:flex;justify-content:space-between;align-items:flex-start;gap:16px}
h1{font-size:28px;margin:0 0 4px}h1 span{color:var(--acc)}
.sub{color:var(--dim);margin:0 0 24px;font-size:14px}
#dcbtn{padding:10px 18px;background:var(--acc);border:0;border-radius:8px;color:#fff;
font-weight:700;cursor:pointer;white-space:nowrap}
#dcbtn.out{background:var(--card);border:1px solid var(--border);color:var(--dim)}
.dcchip{display:flex;align-items:center;gap:10px;background:var(--card);border:1px solid var(--border);
border-radius:10px;padding:8px 14px}
.dcchip img{width:32px;height:32px;border-radius:50%}
.dcchip b{font-size:14px}.dcchip small{color:var(--dim);display:block}
.search{display:flex;gap:8px}
.search input{flex:1;padding:14px 16px;background:var(--card);border:1px solid var(--border);
border-radius:10px;color:var(--txt);font-size:16px;outline:none}
.search input:focus{border-color:var(--acc)}
.search button{padding:14px 28px;background:var(--acc);border:0;border-radius:10px;
color:#fff;font-weight:700;font-size:15px;cursor:pointer}
.search button:disabled{opacity:.5;cursor:wait}
.tabs{display:flex;gap:6px;margin:14px 0 20px;flex-wrap:wrap}
.tab{padding:6px 14px;border:1px solid var(--border);border-radius:20px;background:none;
color:var(--dim);font-size:13px;cursor:pointer}
.tab.on{background:var(--acc);border-color:var(--acc);color:#fff}
.spin{display:none;text-align:center;padding:40px;color:var(--dim)}
.spin.on{display:block}
.dot{width:10px;height:10px;background:var(--acc);border-radius:50%;display:inline-block;
animation:b 1s infinite alternate}@keyframes b{to{opacity:.2}}
.res{margin-top:10px}
.card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:18px 20px;margin-bottom:14px}
.card h3{margin:0 0 10px;font-size:14px;text-transform:uppercase;letter-spacing:.5px;color:var(--dim)}
.kv{display:grid;grid-template-columns:180px 1fr;gap:4px 12px;font-size:14px}
.kv b{color:var(--dim);font-weight:500}
.ok{color:var(--ok)} .bad{color:var(--bad)} .warn{color:var(--warn)}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(210px,1fr));gap:8px}
.plat{background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:10px 12px;font-size:13px}
.plat b{display:block;margin-bottom:2px}
.plat a{color:var(--acc);text-decoration:none;font-size:12px}
.bar{height:8px;background:var(--bg);border-radius:4px;overflow:hidden;margin-top:6px}
.bar i{display:block;height:100%;background:var(--ok)}
.foot{margin-top:30px;color:var(--dim);font-size:12px;text-align:center}
.btn{margin-top:10px;padding:8px 16px;border:1px solid var(--border);border-radius:8px;
background:none;color:var(--txt);cursor:pointer;font-size:13px}
/* Modal */
#modal{position:fixed;inset:0;background:rgba(0,0,0,.7);display:none;place-items:center;z-index:9}
#modal.on{display:grid}
#modal .box{background:var(--card);border:1px solid var(--border);border-radius:14px;
padding:28px;width:360px;max-width:92vw}
#modal h2{margin:0 0 6px;font-size:18px}
#modal p{color:var(--dim);font-size:12px;margin:0 0 14px}
#modal input{width:100%;padding:11px;margin-bottom:12px;background:var(--bg);
border:1px solid var(--border);color:var(--txt);border-radius:8px;outline:none}
#modal .row{display:flex;gap:8px}
#modal button{flex:1;padding:10px;border:0;border-radius:8px;font-weight:600;cursor:pointer}
#modal .go{background:var(--acc);color:#fff}
#modal .no{background:none;border:1px solid var(--border);color:var(--dim)}
#modal .err{color:var(--bad);font-size:12px;margin:0 0 10px;display:none}
/* Discord-Karte */
.dcgrid{display:grid;grid-template-columns:1fr 1fr;gap:12px}
@media(max-width:700px){.dcgrid{grid-template-columns:1fr}}
.badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:11px;
border:1px solid var(--border);color:var(--dim);margin:1px}
</style></head><body><div class="wrap">

<div class="top">
 <div><h1>OSINT<span>·</span>Web</h1>
 <p class="sub">Passives Recon — nur öffentliche APIs &amp; Datenbanken. Kein Profil-Footprint.</p></div>
 <div id="dctop"><button id="dcbtn" onclick="openModal()">Discord Login</button></div>
</div>

<div class="tabs" id="tabs">
<button class="tab on" data-m="auto">Auto</button>
<button class="tab" data-m="user">Username</button>
<button class="tab" data-m="email">E-Mail</button>
<button class="tab" data-m="domain">Domain</button>
<button class="tab" data-m="ip">IP</button>
<button class="tab" data-m="phone">Telefon</button>
<button class="tab" data-m="password">Passwort</button>
</div>

<div class="search">
<input id="t" placeholder="Username, E-Mail, Domain, IP, +49…, Passwort" autofocus>
<button id="go" onclick="run()">Scannen</button>
</div>

<div class="spin" id="spin"><span class="dot"></span>&nbsp; Abfrage läuft …</div>
<div class="res" id="res"></div>

<p class="foot">Quellen: GitHub · Reddit · Keybase · crt.sh · urlscan.io · HIBP · ip-api — nur öffentliche Daten. Gesetze beachten.</p>
</div>

<!-- Discord Login Modal -->
<div id="modal" onclick="if(event.target===this)closeModal()">
<div class="box"><h2>Discord User-Token</h2>
<p>Nur für deinen eigenen Account. Token wird im Session-Cookie behalten, nicht gespeichert.</p>
<div class="err" id="dcerr"></div>
<input id="dctok" type="password" placeholder="MTIz..." autofocus>
<div class="row"><button class="go" onclick="dcLogin()">Einloggen</button>
<button class="no" onclick="closeModal()">Abbrechen</button></div></div></div>

<script>
const esc=s=>String(s??"—").replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
let MODE="auto";

/* ── Discord ── */
function openModal(){document.getElementById("modal").classList.add("on");
 const i=document.getElementById("dctok");i.value="";i.focus()}
function closeModal(){document.getElementById("modal").classList.remove("on");
 document.getElementById("dcerr").style.display="none"}
async function dcLogin(){
 const tok=document.getElementById("dctok").value.trim();
 const err=document.getElementById("dcerr");
 if(!tok)return;
 const r=await fetch("/api/discord/login",{method:"POST",
  headers:{"Content-Type":"application/json"},body:JSON.stringify({token:tok})});
 const d=await r.json();
 if(!r.ok){err.textContent=d.error||"Fehler";err.style.display="block";return}
 closeModal();renderDiscord(d);
}
async function dcLogout(){
 await fetch("/api/discord/logout",{method:"POST"});
 document.getElementById("dctop").innerHTML=
  `<button id="dcbtn" onclick="openModal()">Discord Login</button>`;
 const c=document.getElementById("dccard");if(c)c.remove();
}
function renderDiscord(p){
 document.getElementById("dctop").innerHTML=
  `<div class="dcchip"><img src="${esc(p.avatar)}"><div><b>${esc(p.display)}</b>
   <small>@${esc(p.username)} · Logout</small></div>
   <button class="btn" style="margin:0;padding:6px 12px" onclick="dcLogout()">✕</button></div>`;
 const badge=t=>t?`<span class="badge">${esc(t)}</span>`:"";
 const gcard=card("Discord — "+p.display,`
  <div style="display:flex;gap:16px;align-items:center;margin-bottom:14px">
   <img src="${esc(p.avatar)}" style="width:64px;height:64px;border-radius:50%">
   <div class="kv" style="flex:1">
    <b>Username</b><span>@${esc(p.username)} (${esc(p.id)})</span>
    <b>E-Mail</b><span>${esc(p.email||"—")} ${p.verified?'<span class="ok">✓ verifiziert</span>':""}</span>
    <b>Telefon</b><span>${esc(p.phone||"—")}</span>
    <b>MFA / Nitro</b><span>${p.mfa?'<span class="ok">aktiv</span>':'<span class="bad">aus</span>'} · ${esc(p.nitro)}</span>
    <b>Erstellt</b><span>${esc(p.created)} (Snowflake)</span>
    <b>Server</b><span>${p.guild_count}</span>
   </div></div>
  <div class="dcgrid"><div><b style="font-size:13px">Top-Server</b>
   ${p.guilds.map(g=>`<div class="plat" style="margin-top:6px"><b>${esc(g.name)}</b>
    ${g.mitglieder??"?"} Mitglieder ${g.owner?'<span class="warn">Owner</span>':""}${g.admin?'<span class="warn">Admin</span>':""}</div>`).join("")}
  </div><div><b style="font-size:13px">Badges/Rohdaten</b>
   ${badge("ID "+p.id)}${badge(p.nitro)}${p.mfa?badge("2FA"):badge("kein 2FA")}
   ${p.email?badge("E-Mail vorhanden"):""}${p.phone?badge("Telefon vorhanden"):""}
   ${badge(p.created)}</div></div>`);
 const anchor=document.createElement("div");anchor.id="dccard";anchor.innerHTML=gcard;
 document.getElementById("res").prepend(anchor);
}
/* beim Laden prüfen ob Session aktiv */
fetch("/api/discord/refresh",{method:"POST"})
 .then(r=>r.ok?r.json():null).then(d=>{if(d)renderDiscord(d)});

/* ── OSINT ── */
document.getElementById("tabs").addEventListener("click",e=>{
 if(!e.target.classList.contains("tab"))return;
 document.querySelectorAll(".tab").forEach(t=>t.classList.remove("on"));
 e.target.classList.add("on");MODE=e.target.dataset.m;
});
document.getElementById("t").addEventListener("keydown",e=>{if(e.key==="Enter")run()});
async function run(){
 const t=document.getElementById("t").value.trim();if(!t)return;
 const go=document.getElementById("go"),sp=document.getElementById("spin"),res=document.getElementById("res");
 go.disabled=true;sp.classList.add("on");res.innerHTML="";
 try{
  const r=await fetch("/api/scan",{method:"POST",
   headers:{"Content-Type":"application/json"},body:JSON.stringify({target:t,mode:MODE})});
  const d=await r.json();
  if(d.error)res.innerHTML=`<div class="card bad">Fehler: ${esc(d.error)}</div>`;else render(d);
 }catch(e){res.innerHTML=`<div class="card bad">Netzwerkfehler: ${esc(e)}</div>`}
 go.disabled=false;sp.classList.remove("on");
}
function card(h,body){return `<div class="card"><h3>${h}</h3>${body}</div>`}
function kv(o){return `<div class="kv">`+Object.entries(o).map(([k,v])=>
 `<b>${esc(k)}</b><span>${typeof v==="boolean"?(v?'<span class="ok">ja</span>':'<span class="bad">nein</span>'):esc(v)}</span>`).join("")+`</div>`}
function list(a){return a&&a.length?`<div class="grid">`+a.map(x=>`<div class="plat">${esc(x)}</div>`).join("")+`</div>`:"—"}
function render(d){
 let h="";
 if(d.typ==="user"){
  const hits=d.treffer.filter(x=>x.gefunden),miss=d.treffer.filter(x=>!x.gefunden);
  h+=card(`Username — ${hits.length}/${d.treffer.length} Treffer`,
   `<div class="grid">`+hits.map(x=>`<div class="plat"><b class="ok">${esc(x.plattform)}</b>`+
    Object.entries(x.daten).filter(([k,v])=>v).slice(0,3).map(([k,v])=>`${esc(k)}: ${esc(String(v).slice(0,40))}`).join(" · ")+
    `<br><a href="${esc(x.url)}" target="_blank" rel="noopener">öffnen ↗</a></div>`).join("")+`</div>`+
   (miss.length?`<p style="color:var(--dim);font-size:12px;margin:12px 0 0">nicht gefunden: ${esc(miss.map(m=>m.plattform).join(", "))}</p>`:""));
 }
 else if(d.typ==="email"){
  const leaks=d.leaks;
  h+=card("E-Mail",kv({Syntax:d.syntax,"Mailserver (MX)":(d.MX||[]).join(", ")||"keine",
   SPF:(d.SPF||[]).join(" ")||"keine",Gravatar:d.gravatar,
   Keybase:d.keybase?d.keybase.user||d.keybase.name:"nicht gefunden"}));
  h+=card("Leak-Datenbank (HIBP)",
   Array.isArray(leaks)?(leaks.length?`<div class="grid">`+leaks.map(l=>
    `<div class="plat"><b class="warn">${esc(l.name)}</b>${esc(l.jahr)} · ${esc((l.daten||[]).join(", "))}</div>`).join("")+`</div>`
    :`<span class="ok">keine bekannten Leaks</span>`):`<span class="dim">${esc(leaks.hinweis||leaks.fehler||"—")}</span>`);
  if(d.gravatar)h+=card("Avatar",`<img src="${esc(d.gravatar_url)}?s=96" style="border-radius:50%">`);
 }
 else if(d.typ==="domain"){
  h+=card("DNS",kv(Object.fromEntries(Object.entries(d.DNS||{}).map(([k,v])=>[k,(v||[]).join(", ")||"—"]))));
  h+=card("WHOIS",kv(d.WHOIS||{}));
  h+=card(`Subdomains (${(d.subdomains||[]).length})`,list(d.subdomains));
  h+=card("Historie (urlscan)",kv({"bekannte IPs":(d.urlscan_ips||[]).join(", ")||"—",
   "Server":(d.urlscan_server||[]).join(", ")||"—"}));
 }
 else if(d.typ==="ip"){
  const g=d.geo||{};
  h+=card("IP-Geolokation",kv({Land:g.country,Region:g.regionName,Stadt:g.city,
   Koordinaten:g.lat!=null?`${g.lat}, ${g.lon}`:"—",ISP:g.isp,Org:g.org,AS:g.as,
   ReverseDNS:d.PTR||"—",Proxy:g.proxy,Hosting:g.hosting}));
  if(g.lat)h+=card("Karte",`<a href="https://www.openstreetmap.org/?mlat=${g.lat}&mlon=${g.lon}#map=11/${g.lat}/${g.lon}" target="_blank" rel="noopener">OpenStreetMap öffnen ↗</a>`);
 }
 else if(d.typ==="phone")h+=card("Telefon",kv(d));
 else if(d.typ==="password"){
  const b=d.bewertung,col=b.includes("schwach")?"bad":b==="mittel"?"warn":"ok";
  h+=card("Passwort-Analyse",kv({Länge:d.laenge,
   Bewertung:`<span class="${col}">${esc(b)}</span>`,
   "In Leaks":d.in_leaks?`<span class="bad">ja — ${d.leak_vorkommen}× gefunden</span>`:'<span class="ok">nein</span>'})+
   `<div class="bar"><i style="width:${Math.min(100,d.entropie_bits)}%"></i></div>
   <p style="color:var(--dim);font-size:12px">Entropie: ${d.entropie_bits} bits — geprüft via k-Anonymity, das Passwort selbst verlässt den Rechner nie.</p>`);
 }
 h+=`<button class="btn" onclick="dl()">⬇ JSON-Report</button>`;
 document.getElementById("res").innerHTML=h;window._last=d;
}
function dl(){
 const a=document.createElement("a");
 a.href="/api/export?d="+encodeURIComponent(JSON.stringify(window._last||{}));
 a.download="osint-report.json";a.click();
}
</script></body></html>"""

@app.get("/")
def index():
    return render_template_string(PAGE)

if __name__ == "__main__":
    print("→ http://127.0.0.1:5000  (HIBP optional: export HIBP_API_KEY=...)")
    app.run(host="127.0.0.1", port=5000, debug=False)
