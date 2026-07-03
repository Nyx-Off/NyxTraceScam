# 🔎 NyxTraceScam

> Démonstration pédagogique : **ce qu'un simple lien web peut apprendre sur l'appareil qui le visite** — et pourquoi ça ne permet *pas* de « pirater un téléphone ».

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Flask](https://img.shields.io/badge/flask-3.x-black)
![License](https://img.shields.io/badge/license-MIT-green)
![Usage](https://img.shields.io/badge/usage-%C3%A9ducatif%20uniquement-orange)

NyxTraceScam est un mini-serveur Flask conçu pour un **TP de cybersécurité**. Il illustre,
de façon **transparente**, le fonctionnement des liens de traçage / *reconnaissance*
(famille *Seeker*, *Grabify*, *IP-Logger*) : collecte passive de l'IP → géolocalisation,
détection VPN/proxy, et empreinte du navigateur. Il inclut un tableau de bord et un
générateur de **fiches de signalement** pour la démarche légale « anti-brouteur »
(collecter des preuves puis **signaler**, jamais contre-attaquer).

---

## ⚠️ Avertissement

> **À usage éducatif uniquement.** Utilise cet outil **exclusivement** sur **tes propres
> appareils** ou dans un **laboratoire autorisé**. Collecter des données sur une personne
> à son insu est illégal (France : art. **226-1** et **323-1** et suivants du Code pénal ;
> **RGPD**). Le *hacking-back* (pirater un attaquant en retour) est illégal pour un
> particulier, **même contre un escroc**. L'auteur et les contributeurs déclinent toute
> responsabilité en cas d'usage abusif.

---

## Sommaire

- [Fonctionnalités](#fonctionnalités)
- [Ce que l'outil collecte — et ne collecte pas](#ce-que-loutil-collecte--et-ne-collecte-pas)
- [Prérequis](#prérequis)
- [Installation](#installation)
- [Utilisation](#utilisation)
- [Structure du projet](#structure-du-projet)
- [Comment ça marche](#comment-ça-marche)
- [Cadre légal & éthique](#cadre-légal--éthique)
- [Méthodologie « anti-brouteur »](#méthodologie-anti-brouteur)
- [Licence](#licence)

## Fonctionnalités

- 📍 **Géolocalisation par IP** automatique (ville, FAI, AS) — sans aucune permission.
- 🚩 **Détection VPN / proxy / datacenter** (repère les tentatives de masquage).
- 📱 **Empreinte du navigateur** : modèle/OS, GPU (WebGL), écran, CPU/RAM, batterie,
  fuseau horaire, langues, type de connexion.
- 🗂️ **Journal consolidé** (`captures/journal.jsonl`) + un fichier JSON par visite.
- 🖥️ **Tableau de bord `/admin`** protégé par jeton, avec surlignage des VPN/proxy.
- 📝 **Générateur de fiches de signalement** prêtes pour Pharos / cybermalveillance.gouv.fr.
- 🌍 **Accès externe** via un tunnel SSH (`localhost.run`) — aucune installation, aucun compte.

## Ce que l'outil collecte — et ne collecte pas

| ✅ Accessible via un lien (bac à sable navigateur) | ❌ **Impossible** via un lien |
|---|---|
| IP → pays, ville, FAI, AS | Contacts, SMS, journaux d'appels |
| User-Agent (modèle, OS, navigateur) | Photos, fichiers, apps installées |
| GPU, écran, CPU, RAM, batterie | IMEI, numéro de téléphone |
| Fuseau horaire, langues, connexion | Caméra / micro **sans** accord explicite |
| Flags VPN / proxy / datacenter | Accès au système (sans exploit ni app malveillante) |

> La **géolocalisation GPS précise** exige une popup de permission **non contournable**
> imposée par l'OS ; NyxTraceScam ne la demande donc pas automatiquement. La localisation
> « sans popup » est la géoloc **par IP** (précision : ville).

## Prérequis

- Python **3.10+**
- `ssh` (présent par défaut sur Linux/macOS/WSL) pour le tunnel externe
- Connexion Internet (l'API de géoloc IP est [ip-api.com](https://ip-api.com))

## Installation

```bash
git clone https://github.com/Nyx-Off/NyxTraceScam.git
cd NyxTraceScam
python3 -m venv .venv && source .venv/bin/activate   # optionnel
pip install -r requirements.txt
```

## Utilisation

**1. Lancer le serveur** (terminal 1) :
```bash
python3 app.py
# Le jeton admin s'affiche au démarrage. Pour le fixer :
# ADMIN_TOKEN="mon-secret" python3 app.py
```

**2. Ouvrir un accès externe** (terminal 2) — aucune install, aucun compte :
```bash
ssh -o StrictHostKeyChecking=accept-new -R 80:localhost:8080 nokey@localhost.run
```
Une **URL HTTPS publique** s'affiche (ex. `https://xxxxx.lhr.life`) avec un QR code.
> Le HTTPS est nécessaire pour les API sensibles ; l'URL gratuite **change à chaque relance**.

**3. Tester** : ouvre l'URL sur **ton** appareil de test. Le terminal affiche la géoloc IP
et l'empreinte en direct ; chaque visite est enregistrée dans `captures/`.

**4. Tableau de bord** :
```
http://127.0.0.1:8080/admin?token=LE_JETON
```

**5. Générer les fiches de signalement** à partir du journal :
```bash
python3 fiche_signalement.py
# -> captures/signalement_<ip>.txt
```

## Structure du projet

```
NyxTraceScam/
├── app.py                          # serveur Flask (page + /collect + /admin)
├── fiche_signalement.py            # génère les fiches .txt pour un signalement
├── requirements.txt
├── README.md
├── DEFENSE-permissions-android.md  # fiche de cours : permissions web sur Android
├── .gitignore                      # exclut captures/ (données personnelles)
└── captures/                       # généré à l'exécution (ignoré par git)
    ├── journal.jsonl               # journal consolidé (1 visite/ligne)
    ├── <horodatage>_<ip>.json      # une capture par visite
    └── signalement_<ip>.txt        # fiches de signalement
```

## Comment ça marche

```
   Visiteur (mobile)                Tunnel HTTPS            Ton PC (Kali/WSL)
  ┌────────────────┐   requête    ┌──────────────┐  :8080  ┌───────────────┐
  │  navigateur    │ ───────────▶ │ localhost.run│ ──────▶ │  Flask app.py │
  │  ouvre le lien │              │  (HTTPS)     │         │               │
  └────────────────┘ ◀─────────── └──────────────┘ ◀────── │ géoloc IP +   │
        JS collecte l'empreinte,          l'IP réelle est   │ empreinte →   │
        POST /collect                     dans X-Forwarded  │ captures/*.json│
                                                            └───────────────┘
```

1. Le visiteur ouvre le lien → le serveur lit l'**IP** (`X-Forwarded-For`) et la géolocalise.
2. Un script **JavaScript** lit l'empreinte du navigateur et l'envoie à `/collect`.
3. Tout est journalisé (terminal + `captures/`) et consultable via `/admin`.

## Cadre légal & éthique

- **Consentement / autorisation obligatoires** : uniquement tes appareils ou un labo autorisé.
- **France** : art. 226-1 (atteinte à la vie privée), 323-1 et s. (accès frauduleux à un
  STAD), **RGPD** (consentement spécifique, éclairé, libre — des CGU noyées ne suffisent pas).
- **Pas de hacking-back** : on ne pirate pas un attaquant en retour. La réponse légale est
  le **signalement** (voir ci-dessous).
- Ne laisse pas le tunnel ouvert plus longtemps que nécessaire (l'URL est publique).

## Méthodologie « anti-brouteur »

La vraie contre-mesure = **renseignement + signalement**, pas intrusion.

1. L'IP + la géoloc + le flag **VPN/proxy** révèlent les incohérences (position réelle vs
   prétendue). Un VPN masque l'IP **mais pas** le fuseau/la langue de l'appareil — et une
   seule connexion sans VPN peut révéler la vraie IP.
2. On **signale** avec ces éléments :
   - [Pharos](https://www.internet-signalement.gouv.fr)
   - [cybermalveillance.gouv.fr](https://www.cybermalveillance.gouv.fr)
   - La plateforme concernée + l'`abuse@` de l'hébergeur
3. Seule une autorité peut légalement transformer une IP en identité (réquisition FAI/VPN).

Voir [`DEFENSE-permissions-android.md`](DEFENSE-permissions-android.md) pour le volet
défensif (permissions Android, détection, contre-mesures).

## Licence

Distribué sous licence **MIT**. Voir [`LICENSE`](LICENSE).

---

<sub>Projet réalisé dans un cadre pédagogique. L'usage de cet outil engage la seule
responsabilité de l'utilisateur.</sub>
