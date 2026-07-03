#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NyxTraceScam — Recon via un lien (scénario "anti-brouteur")

BUT
---
Montrer l'intelligence qu'on peut LEGALEMENT récupérer sur quelqu'un qui clique
notre lien (IP -> géoloc/FAI/VPN, empreinte appareil), pour l'identifier et le
SIGNALER (Pharos, cybermalveillance.gouv.fr).

Interface : thème "hacker" (démo de sensibilisation). La page affiche au visiteur
ce qui a été lu sur son appareil -> prise de conscience.

RAPPEL DES LIMITES (à énoncer dans le rapport)
  - Un lien NE lit PAS contacts/SMS/photos/fichiers (bac à sable navigateur).
  - Le GPS précis exige une popup non contournable (imposée par l'OS).
  - Piéger/pirater le tél d'un tiers, même un escroc, est ILLEGAL (art. 226-1,
    323-1 s. du Code pénal). La contre-attaque légale = collecter + signaler.

A UTILISER sur ton appareil / en labo autorisé.
"""

import os
import json
import secrets
import datetime
import ipaddress
import urllib.request
from pathlib import Path
from flask import Flask, request, render_template_string, jsonify

app = Flask(__name__)

CAPTURES_DIR = Path(__file__).parent / "captures"
CAPTURES_DIR.mkdir(exist_ok=True)
JOURNAL = CAPTURES_DIR / "journal.jsonl"   # tout au même endroit, 1 ligne/visite

# Jeton protégeant /admin. Fixe-le via la variable d'env ADMIN_TOKEN, sinon un
# jeton aléatoire est généré à chaque démarrage et affiché dans le terminal.
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN") or secrets.token_urlsafe(9)


class C:
    RESET = "\033[0m"; BOLD = "\033[1m"
    RED = "\033[91m"; GREEN = "\033[92m"; YELLOW = "\033[93m"
    BLUE = "\033[94m"; CYAN = "\033[96m"; MAG = "\033[95m"


def vraie_ip():
    """Derrière un tunnel, l'IP réelle du visiteur est dans X-Forwarded-For."""
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr


def geoloc_ip(ip):
    """Géoloc PAR IP (automatique, sans permission). Précision : ville/FAI.
    Détecte VPN/proxy/hébergement -> utile pour repérer un masquage."""
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_private or addr.is_loopback:
            return {"note": "IP privée/locale — teste via le tunnel"}
    except ValueError:
        return {}
    try:
        champs = ("status,country,regionName,city,zip,lat,lon,"
                  "isp,org,as,mobile,proxy,hosting,query")
        url = f"http://ip-api.com/json/{ip}?fields={champs}&lang=fr"
        with urllib.request.urlopen(url, timeout=4) as r:
            d = json.loads(r.read().decode())
        if d.get("status") != "success":
            return {"note": "géoloc IP indisponible"}
        return {
            "pays": d.get("country"), "region": d.get("regionName"),
            "ville": d.get("city"), "code_postal": d.get("zip") or "-",
            "coordonnees_IP": f'{d.get("lat")}, {d.get("lon")}',
            "FAI": d.get("isp"), "operateur": d.get("org") or "-", "AS": d.get("as"),
            "reseau_mobile": "oui" if d.get("mobile") else "non",
            "VPN_proxy": "OUI ⚠️" if d.get("proxy") else "non",
            "hebergement_datacenter": "OUI ⚠️" if d.get("hosting") else "non",
        }
    except Exception as e:
        return {"erreur": str(e)}


# ---------------------------------------------------------------------------
# PAGE visiteur — thème "hacker" (démo de sensibilisation).
# Collecte identique : uniquement ce que le navigateur expose de lui-même.
# Servie en texte brut (pas de template) : les accolades CSS/JS restent littérales.
# ---------------------------------------------------------------------------
PAGE = '''
<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>root@target:~#</title>
<style>
  * { box-sizing: border-box; }
  html, body { margin:0; padding:0; background:#000; }
  body { font-family:'Courier New', Courier, monospace; color:#00ff41;
         min-height:100vh; overflow-x:hidden; }
  #matrix { position:fixed; inset:0; z-index:0; opacity:0.22; }
  .wrap { position:relative; z-index:1; max-width:760px; margin:0 auto; padding:22px 16px 60px; }
  .skull { color:#00ff41; font-size:10px; line-height:1.02; text-align:center;
           text-shadow:0 0 8px #00ff41; white-space:pre; overflow-x:auto; margin:4px 0; }
  .title { text-align:center; font-size:clamp(2rem,11vw,3.6rem); font-weight:bold;
           letter-spacing:.22em; margin:8px 0 2px; position:relative; color:#00ff41;
           text-shadow:0 0 12px #00ff41; }
  .title::before, .title::after { content:attr(data-text); position:absolute; left:0; top:0; width:100%; }
  .title::before { color:#ff003c; animation:gl1 1.6s infinite linear alternate; z-index:-1; }
  .title::after  { color:#00e5ff; animation:gl2 2.2s infinite linear alternate; z-index:-2; }
  @keyframes gl1 { 0% { transform:translate(-2px,-1px) } 100% { transform:translate(2px,1px) } }
  @keyframes gl2 { 0% { transform:translate(2px,1px) } 100% { transform:translate(-2px,-1px) } }
  .access { text-align:center; color:#adff2f; font-size:1rem; margin:6px 0 20px;
            min-height:1.3em; text-shadow:0 0 6px #00ff41; }
  .cursor { animation:blink 1s steps(1) infinite; }
  @keyframes blink { 50% { opacity:0 } }
  .term { border:1px solid #00ff4155; background:rgba(0,26,5,0.66); border-radius:6px;
          padding:14px 16px; box-shadow:inset 0 0 22px #00ff4126; }
  .term h2 { color:#adff2f; font-size:.82rem; letter-spacing:.14em; margin:16px 0 6px;
             border-bottom:1px dashed #00ff4144; padding-bottom:4px; }
  .term h2:first-of-type { margin-top:2px; }
  .line { font-size:.85rem; padding:3px 0; word-break:break-word; }
  .line .val { color:#eaffea; }
  .line.warn { color:#ff003c; text-shadow:0 0 6px #ff003c; }
  .line.warn .val { color:#ff5c78; }
  .foot { margin-top:22px; text-align:center; font-size:.72rem; color:#00ff4199; line-height:1.65; }
  .foot b { color:#adff2f; letter-spacing:.08em; }
</style>
</head>
<body>
<canvas id="matrix"></canvas>
<div class="wrap">
  <pre class="skull">
                 uuuuuuu
             uu$$$$$$$$$$$uu
          uu$$$$$$$$$$$$$$$$$uu
         u$$$$$$$$$$$$$$$$$$$$$u
        u$$$$$$$$$$$$$$$$$$$$$$$u
        u$$$$$$$$$$$$$$$$$$$$$$$u
        u$$$$$$"   "$$$"   "$$$$$$u
        "$$$$"      u$u       $$$$"
         $$$u       u$u       u$$$
         $$$u      u$$$u      u$$$
          "$$$$uu$$$   $$$uu$$$$"
           "$$$$$$$"   "$$$$$$$"
             u$$$$$$$u$$$$$$$u
              u$"$"$"$"$"$"$u
   uuu        $$u$ $ $ $ $u$$       uuu
  u$$$$        $$$$$u$u$u$$$       u$$$$
   $$$$$uu      "$$$$$$$$$"     uu$$$$$$
 u$$$$$$$$$$$uu    """""    uuuu$$$$$$$$$$
 $$$$"""$$$$$$$$$$uuu   uu$$$$$$$$$"""$$$"
  """      ""$$$$$$$$$$$uu ""$"""
            uuuu ""$$$$$$$$$$uuu
   u$$$uuu$$$$$$$$$uu ""$$$$$$$$$$$uuu$$$
   $$$$$$$$$$""""           ""$$$$$$$$$$$"
    "$$$$$"                      ""$$$$""
      $$$"                         $$$$"
  </pre>
  <div class="title" data-text="I GOT IT">I GOT IT</div>
  <div class="access" id="access"></div>
  <div class="term">
    <div class="line">&gt; établissement de la liaison... <span style="color:#adff2f">OK</span></div>
    <div class="line">&gt; extraction des données de la cible...</div>
    <h2>[ LOCALISATION / IP ]</h2>
    <div id="geo"><div class="line">&gt; scan...</div></div>
    <h2>[ EMPREINTE DE L'APPAREIL ]</h2>
    <div id="infos"><div class="line">&gt; scan...</div></div>
  </div>
  <div class="foot">
    <b>// DÉMONSTRATION DE SENSIBILISATION — TP CYBER</b><br>
    Un simple lien a pu lire tout ceci sur votre appareil. Aucune magie : c'est ce que
    votre navigateur expose. Restez vigilant face aux liens inconnus.
  </div>
</div>
<script>
/* ---- Pluie "Matrix" ---- */
(function(){
  var cv=document.getElementById('matrix'), ctx=cv.getContext('2d');
  function rs(){ cv.width=window.innerWidth; cv.height=window.innerHeight; }
  rs(); window.addEventListener('resize', rs);
  var chars="01アイウエオカキクケコサシabcdef$#%&".split('');
  var fs=14, cols=Math.floor(window.innerWidth/fs), drops=[];
  for(var i=0;i<cols;i++){ drops[i]=Math.random()*-50; }
  setInterval(function(){
    ctx.fillStyle='rgba(0,0,0,0.09)'; ctx.fillRect(0,0,cv.width,cv.height);
    ctx.fillStyle='#00ff41'; ctx.font=fs+'px monospace';
    for(var i=0;i<drops.length;i++){
      var t=chars[Math.floor(Math.random()*chars.length)];
      ctx.fillText(t, i*fs, drops[i]*fs);
      if(drops[i]*fs>cv.height && Math.random()>0.975){ drops[i]=0; }
      drops[i]++;
    }
  },55);
})();

/* ---- Effet machine à écrire ---- */
(function(){
  var el=document.getElementById('access'), txt="root@target:~# ACCESS GRANTED", i=0;
  (function tick(){
    if(i<=txt.length){ el.innerHTML=txt.slice(0,i)+'<span class="cursor">█</span>'; i++; setTimeout(tick,55); }
    else { el.innerHTML=txt+' <span class="cursor">█</span>'; }
  })();
})();

/* ---- Collecte (uniquement ce que le navigateur expose) ---- */
function getGPU(){try{var c=document.createElement('canvas');var g=c.getContext('webgl')||c.getContext('experimental-webgl');if(!g)return"?";var d=g.getExtension('WEBGL_debug_renderer_info');return d?g.getParameter(d.UNMASKED_RENDERER_WEBGL):(g.getParameter(g.RENDERER)||"?");}catch(e){return"?";}}
function getBatterie(){return new Promise(function(res){try{if(!navigator.getBattery)return res(null);navigator.getBattery().then(function(b){res(Math.round(b.level*100)+"%"+(b.charging?" (en charge)":""));});}catch(e){res(null);}});}
function collecte(){var n=navigator,s=screen,c=n.connection||{};return{
  userAgent:n.userAgent, plateforme:n.platform||"?", GPU:getGPU(),
  langues:(n.languages||[n.language]).join(", "), coeurs_CPU:n.hardwareConcurrency||"?",
  memoire_Go:n.deviceMemory||"inconnu", ecran:s.width+" x "+s.height+" @"+(window.devicePixelRatio||1)+"x",
  tactile:(n.maxTouchPoints>0)?"oui ("+n.maxTouchPoints+" pts)":"non",
  fuseau_horaire:Intl.DateTimeFormat().resolvedOptions().timeZone,
  connexion:c.effectiveType?(c.effectiveType+(c.downlink?", "+c.downlink+" Mb/s":"")):"?",
  cookies:n.cookieEnabled?"actifs":"inactifs"};}
var L={userAgent:"appareil",plateforme:"plateforme",GPU:"gpu",langues:"langues",coeurs_CPU:"coeurs_cpu",memoire_Go:"memoire_go",ecran:"ecran",tactile:"tactile",fuseau_horaire:"fuseau",connexion:"connexion",cookies:"cookies",batterie:"batterie",pays:"pays",region:"region",ville:"ville",code_postal:"code_postal",coordonnees_IP:"coords_ip",FAI:"fai",operateur:"operateur",AS:"as",reseau_mobile:"mobile",VPN_proxy:"vpn_proxy",hebergement_datacenter:"datacenter",note:"info",erreur:"erreur"};
function afficher(id,o){var h="";for(var k in o){if(o[k]==null)continue;var v=String(o[k]);var warn=v.indexOf("⚠️")>=0;h+='<div class="line'+(warn?" warn":"")+'">&gt; '+(L[k]||k)+' : <span class="val">'+v+'</span></div>';}document.getElementById(id).innerHTML=h;}
function main(){var d=collecte();getBatterie().then(function(b){if(b)d.batterie=b;afficher("infos",d);
  fetch("/collect",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(d)}).then(function(r){return r.json();}).then(function(r){if(r&&r.geoloc_ip)afficher("geo",r.geoloc_ip);}).catch(function(){afficher("geo",{erreur:"liaison interrompue"});});});}
main();
</script>
</body>
</html>
'''

# --- Page /admin : tableau de bord des captures (protégé par jeton) ---
ADMIN_PAGE = """
<!doctype html>
<html lang="fr"><head>
  <meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Admin — captures</title>
  <style>
    :root { color-scheme: dark; }
    body { font-family: 'Courier New', monospace; margin: 0; background: #000; color: #00ff41; }
    .wrap { max-width: 900px; margin: 0 auto; padding: 22px 16px 60px; }
    h1 { font-size: 1.3rem; margin: 0 0 2px; text-shadow:0 0 8px #00ff41; }
    .sub { color: #00ff4199; font-size: .85rem; margin: 0 0 18px; }
    .card { background: rgba(0,26,5,0.6); border: 1px solid #00ff4144; border-radius: 8px; padding: 12px 16px; margin: 12px 0; }
    .hd { font-size: .95rem; margin-bottom: 8px; border-bottom: 1px solid #00ff4133; padding-bottom: 6px; }
    .flag { background:#b91c1c; color:#fff; font-size:.68rem; padding:2px 7px; border-radius:5px; margin-left:6px; }
    .cols { display: flex; flex-wrap: wrap; gap: 18px; }
    .col { flex: 1 1 300px; min-width: 0; }
    h3 { font-size: .72rem; letter-spacing: .1em; color: #adff2f; margin: 4px 0 6px; }
    .row { display: flex; justify-content: space-between; gap: 10px; padding: 4px 0; border-bottom: 1px solid #00ff411a; font-size: .82rem; }
    .k { color: #00ff4199; } .v { text-align: right; word-break: break-word; color:#eaffea; } .warn { color: #ff5c78; font-weight: 600; }
    .empty { color: #00ff4166; }
  </style></head>
<body><div class="wrap">
  <h1>🗂️ Tableau de bord — {{ total }} visite(s)</h1>
  <p class="sub">Journal consolidé des captures. Accès protégé par jeton.</p>
  {% for r in rows %}
  {% set vp = (r.geoloc_ip or {}).get('VPN_proxy','') %}
  {% set hz = (r.geoloc_ip or {}).get('hebergement_datacenter','') %}
  <div class="card">
    <div class="hd">🕓 {{ r.horodatage }} &nbsp; IP <b>{{ r.ip }}</b>
      {% if '⚠️' in vp %}<span class="flag">VPN/PROXY</span>{% endif %}
      {% if '⚠️' in hz %}<span class="flag">DATACENTER</span>{% endif %}
    </div>
    <div class="cols">
      <div class="col"><h3>📍 Géoloc IP</h3>
        {% for k, v in (r.geoloc_ip or {}).items() %}
        <div class="row"><span class="k">{{ k }}</span><span class="{{ 'v warn' if '⚠️' in (v|string) else 'v' }}">{{ v }}</span></div>
        {% endfor %}
      </div>
      <div class="col"><h3>📱 Appareil</h3>
        {% for k, v in (r.appareil_client or {}).items() %}
        <div class="row"><span class="k">{{ k }}</span><span class="v">{{ v }}</span></div>
        {% endfor %}
      </div>
    </div>
  </div>
  {% else %}
  <p class="empty">Aucune capture pour l'instant. Ouvre le lien sur un appareil de test.</p>
  {% endfor %}
</div></body></html>
"""


@app.route("/")
def index():
    ip = vraie_ip()
    print(f"\n{C.YELLOW}{C.BOLD}[VISITE] {datetime.datetime.now():%H:%M:%S}"
          f"  IP {C.GREEN}{ip}{C.RESET}")
    print(f"  {C.CYAN}User-Agent :{C.RESET} {request.headers.get('User-Agent', '?')}")
    return PAGE


@app.route("/collect", methods=["POST"])
def collect():
    client = request.get_json(silent=True) or {}
    ip = vraie_ip()
    horodatage = datetime.datetime.now().isoformat(timespec="seconds")
    geo = geoloc_ip(ip)

    dossier = {
        "horodatage": horodatage, "ip": ip, "geoloc_ip": geo,
        "en_tetes_http": {
            "user_agent": request.headers.get("User-Agent", "?"),
            "accept_language": request.headers.get("Accept-Language", "?"),
            "referer": request.headers.get("Referer", "-"),
        },
        "appareil_client": client,
    }

    nom = horodatage.replace(":", "-") + "_" + ip.replace(":", "_") + ".json"
    (CAPTURES_DIR / nom).write_text(
        json.dumps(dossier, indent=2, ensure_ascii=False), encoding="utf-8")
    with JOURNAL.open("a", encoding="utf-8") as f:
        f.write(json.dumps(dossier, ensure_ascii=False) + "\n")

    print(f"\n{C.MAG}{C.BOLD}[GÉOLOC IP] {ip}{C.RESET}")
    for k, v in geo.items():
        marque = f"{C.RED}⚠️ {C.RESET}" if "⚠️" in str(v) else "  "
        print(f"  {marque}{C.CYAN}{k:22}:{C.RESET} {v}")
    print(f"{C.BLUE}{C.BOLD}[APPAREIL]{C.RESET}")
    for k, v in client.items():
        print(f"  {C.CYAN}{k:22}:{C.RESET} {v}")
    print(f"  {C.GREEN}→ captures/{nom}  (+ journal.jsonl){C.RESET}")

    return jsonify({"ok": True, "geoloc_ip": geo})


@app.route("/admin")
def admin():
    if not secrets.compare_digest(request.args.get("token", ""), ADMIN_TOKEN):
        return ("<h1>403 — accès refusé</h1><p>Ajoute <code>?token=...</code> à l'URL.</p>", 403)
    rows = []
    if JOURNAL.exists():
        for ligne in JOURNAL.read_text(encoding="utf-8").splitlines():
            ligne = ligne.strip()
            if ligne:
                try:
                    rows.append(json.loads(ligne))
                except json.JSONDecodeError:
                    pass
    rows.reverse()
    return render_template_string(ADMIN_PAGE, rows=rows, total=len(rows))


if __name__ == "__main__":
    print(f"{C.BOLD}{C.GREEN}\n{'='*60}")
    print("  NyxTraceScam — recon + tableau de bord (légal)")
    print(f"{'='*60}{C.RESET}\n")
    print(f"  Local    : {C.CYAN}http://127.0.0.1:8080{C.RESET}")
    print(f"  Admin    : {C.CYAN}http://127.0.0.1:8080/admin?token={ADMIN_TOKEN}{C.RESET}")
    print(f"  {C.YELLOW}Jeton admin : {ADMIN_TOKEN}{C.RESET}")
    print(f"  Journal  : {JOURNAL}")
    print(f"  Via tunnel : https://<ton-url>.lhr.life/admin?token={ADMIN_TOKEN}\n")
    app.run(host="0.0.0.0", port=8080, debug=False)
