#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TP Cybersécurité — Recon via un lien (scénario "anti-brouteur")

BUT
---
Montrer l'intelligence qu'on peut LEGALEMENT récupérer sur quelqu'un qui clique
notre lien (IP -> géoloc/FAI/VPN, empreinte appareil), pour l'identifier et le
SIGNALER (Pharos, cybermalveillance.gouv.fr).

Cette version ajoute :
  - un JOURNAL consolidé (captures/journal.jsonl : 1 visite par ligne) ;
  - une page /admin (tableau de bord) protégée par un JETON d'accès.

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


# --- Page visiteur : tout est collecté automatiquement, transparente (démo) ---
PAGE = """
<!doctype html>
<html lang="fr"><head>
  <meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Analyse de votre appareil</title>
  <style>
    :root { color-scheme: light dark; }
    body { font-family: system-ui, sans-serif; margin: 0; background: #0f172a; color: #e2e8f0; }
    .wrap { max-width: 640px; margin: 0 auto; padding: 24px 18px 60px; }
    h1 { font-size: 1.35rem; margin: 0 0 4px; }
    h2 { font-size: .8rem; text-transform: uppercase; letter-spacing: .05em; color: #38bdf8; margin: 22px 0 8px; }
    .sub { color: #94a3b8; font-size: .9rem; }
    .card { background: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 8px 16px; margin: 6px 0; }
    .row { display: flex; justify-content: space-between; gap: 12px; padding: 7px 0; border-bottom: 1px solid #33415577; font-size: .88rem; }
    .row:last-child { border-bottom: 0; }
    .k { color: #94a3b8; } .v { text-align: right; word-break: break-word; } .warn { color: #fca5a5; }
    .tag { background:#0891b2; color:#fff; font-size:.7rem; padding:2px 8px; border-radius:6px; }
    .note { font-size: .78rem; color: #64748b; margin-top: 18px; }
  </style></head>
<body><div class="wrap">
  <h1>🔎 Analyse de votre appareil <span class="tag">TP CYBER</span></h1>
  <p class="sub">Informations lues automatiquement par ce lien (démo pédagogique).</p>
  <h2>📍 Localisation par IP</h2>
  <div class="card" id="geo"><div class="row"><span class="k">Chargement…</span></div></div>
  <h2>📱 Appareil</h2>
  <div class="card" id="infos"><div class="row"><span class="k">Chargement…</span></div></div>
  <p class="note">Démonstration. Données aussi envoyées au serveur du TP. Le GPS précis
     n'est pas demandé (il exigerait une popup et votre accord explicite).</p>
</div>
<script>
function getGPU(){try{const c=document.createElement('canvas');const g=c.getContext('webgl')||c.getContext('experimental-webgl');if(!g)return"?";const d=g.getExtension('WEBGL_debug_renderer_info');return d?g.getParameter(d.UNMASKED_RENDERER_WEBGL):(g.getParameter(g.RENDERER)||"?");}catch(e){return"?";}}
async function getBatterie(){try{if(!navigator.getBattery)return null;const b=await navigator.getBattery();return Math.round(b.level*100)+"%"+(b.charging?" (en charge)":"");}catch(e){return null;}}
function collecte(){const n=navigator,s=screen,c=n.connection||{};return{
  userAgent:n.userAgent, plateforme:n.platform||"?", GPU:getGPU(),
  langues:(n.languages||[n.language]).join(", "), coeurs_CPU:n.hardwareConcurrency||"?",
  memoire_Go:n.deviceMemory||"inconnu", ecran:s.width+" x "+s.height+" @"+(window.devicePixelRatio||1)+"x",
  tactile:(n.maxTouchPoints>0)?"oui ("+n.maxTouchPoints+" pts)":"non",
  fuseau_horaire:Intl.DateTimeFormat().resolvedOptions().timeZone,
  connexion:c.effectiveType?(c.effectiveType+(c.downlink?", "+c.downlink+" Mb/s":"")):"?",
  cookies:n.cookieEnabled?"activés":"désactivés"};}
const L={userAgent:"Appareil/Navigateur",plateforme:"Plateforme",GPU:"GPU",langues:"Langues",coeurs_CPU:"Coeurs CPU",memoire_Go:"Mémoire (Go)",ecran:"Écran",tactile:"Tactile",fuseau_horaire:"Fuseau horaire",connexion:"Connexion",cookies:"Cookies",batterie:"Batterie",pays:"Pays",region:"Région",ville:"Ville",code_postal:"Code postal",coordonnees_IP:"Coordonnées (IP)",FAI:"FAI",operateur:"Opérateur",AS:"AS",reseau_mobile:"Réseau mobile",VPN_proxy:"VPN/Proxy",hebergement_datacenter:"Datacenter",note:"Info",erreur:"Erreur"};
function afficher(id,o){let h="";for(const k in o){if(o[k]==null)continue;const v=String(o[k]);h+='<div class="row"><span class="k">'+(L[k]||k)+'</span><span class="'+(v.includes("⚠️")?"v warn":"v")+'">'+v+'</span></div>';}document.getElementById(id).innerHTML=h;}
async function main(){const d=collecte();const b=await getBatterie();if(b)d.batterie=b;afficher("infos",d);
  try{const r=await fetch("/collect",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(d)}).then(x=>x.json());if(r&&r.geoloc_ip)afficher("geo",r.geoloc_ip);}catch(e){afficher("geo",{erreur:"envoi impossible"});}}
main();
</script></body></html>
"""

# --- Page /admin : tableau de bord des captures (protégé par jeton) ---
ADMIN_PAGE = """
<!doctype html>
<html lang="fr"><head>
  <meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Admin — captures</title>
  <style>
    :root { color-scheme: light dark; }
    body { font-family: system-ui, sans-serif; margin: 0; background: #0b1220; color: #e2e8f0; }
    .wrap { max-width: 900px; margin: 0 auto; padding: 22px 16px 60px; }
    h1 { font-size: 1.3rem; margin: 0 0 2px; }
    .sub { color: #94a3b8; font-size: .85rem; margin: 0 0 18px; }
    .card { background: #111c33; border: 1px solid #263349; border-radius: 12px; padding: 12px 16px; margin: 12px 0; }
    .hd { font-size: .95rem; margin-bottom: 8px; border-bottom: 1px solid #263349; padding-bottom: 6px; }
    .flag { background:#b91c1c; color:#fff; font-size:.68rem; padding:2px 7px; border-radius:5px; margin-left:6px; }
    .cols { display: flex; flex-wrap: wrap; gap: 18px; }
    .col { flex: 1 1 300px; min-width: 0; }
    h3 { font-size: .72rem; text-transform: uppercase; letter-spacing: .05em; color: #38bdf8; margin: 4px 0 6px; }
    .row { display: flex; justify-content: space-between; gap: 10px; padding: 4px 0; border-bottom: 1px solid #1e293b; font-size: .82rem; }
    .k { color: #8595ad; } .v { text-align: right; word-break: break-word; } .warn { color: #fca5a5; font-weight: 600; }
    .empty { color: #64748b; }
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
    return render_template_string(PAGE)


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

    # 1) fichier individuel par visite
    nom = horodatage.replace(":", "-") + "_" + ip.replace(":", "_") + ".json"
    (CAPTURES_DIR / nom).write_text(
        json.dumps(dossier, indent=2, ensure_ascii=False), encoding="utf-8")
    # 2) journal consolidé : TOUT au même endroit, 1 ligne JSON par visite
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
    # Contrôle d'accès : sans le bon jeton, pas de tableau de bord.
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
    rows.reverse()  # plus récent en premier
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
