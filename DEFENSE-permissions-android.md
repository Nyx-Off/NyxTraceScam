# Fiche de cours — Permissions web sur Android : attaque, limites, défense

Support pour le rapport de TP. Objectif : comprendre ce qu'un site web peut
*demander* à un Android, pourquoi le modèle de consentement limite les abus, et
comment **détecter / se défendre**. (Volet défensif = celui qui rapporte des points.)

## 1. Ce qu'un site peut DEMANDER à un Android

Toutes ces API exigent un **contexte sécurisé (HTTPS)** *et* déclenchent un
**prompt natif du navigateur** que le code du site **ne peut pas supprimer** :

| Permission | API navigateur | Ce que ça donne |
|---|---|---|
| Géolocalisation | `navigator.geolocation.getCurrentPosition()` | position GPS précise |
| Caméra / micro | `navigator.mediaDevices.getUserMedia()` | flux vidéo/audio |
| Notifications | `Notification.requestPermission()` | envoi de notifs |
| Presse-papier | `navigator.clipboard.readText()` | lecture du presse-papier |
| Capteurs mouvement | `DeviceMotionEvent` | accéléromètre/gyroscope |
| Bluetooth / USB | `navigator.bluetooth`, `navigator.usb` | + sélecteur d'appareil obligatoire |

**Sans permission** (lu automatiquement, cf. l'outil du TP) : IP → géoloc ville/FAI,
User-Agent, GPU (WebGL), écran, CPU/RAM, batterie, fuseau, langue.

**Jamais accessible par un site**, quelle que soit la permission : contacts, SMS,
photos, fichiers, apps installées, IMEI. → il faut une **app/RAT** installée, pas un lien.

## 2. Pourquoi le « camouflage » de la permission ne marche pas vraiment

Un faux bouton « Accepter les cookies » qui appelle `getCurrentPosition()` :

1. Le clic fournit bien le **geste utilisateur** requis…
2. …mais le **navigateur affiche QUAND MÊME sa propre popup** : « *ce_site* souhaite
   connaître votre position — Autoriser / Bloquer ». Impossible à masquer.
3. Pour caméra/micro, Android ajoute un **indicateur permanent** (point/pastille
   verte dans la barre d'état) tant que le capteur est actif.

➡️ La faille exploitée est donc **humaine** (le réflexe de re-cliquer « autoriser »),
pas technique. C'est le message de sensibilisation clé.

## 3. Garde-fous du modèle Android (à citer)

- **Contexte sécurisé obligatoire** : en HTTP simple, ces API sont désactivées.
- **Permissions par site** : accordées à un domaine précis, pas globalement.
- **Révocables** à tout moment : *Chrome → Paramètres du site → Autorisations*.
- **Indicateurs visuels** caméra/micro (point vert) + accès rapide pour couper.
- **Prompts non contournables** et **non déclenchables sans geste utilisateur**
  (les navigateurs bloquent les demandes automatiques au chargement).

## 4. Détection / défense (blue team)

- **Côté utilisateur** : lire ce que dit *vraiment* la popup (pas le bandeau autour) ;
  refuser par défaut ; auditer *Paramètres du site → Autorisations* ; surveiller le
  point vert caméra/micro ; garder Chrome/WebView à jour.
- **Côté analyse** : inspecter le JS d'une page suspecte (recherche d'appels
  `getUserMedia`, `getCurrentPosition`, `clipboard.readText` déclenchés par un
  élément déguisé) ; un CSP strict et des extensions anti-tracking réduisent la surface.
- **Réseau** : un DNS filtrant / Pi-hole bloque les domaines de collecte connus.

## 5. Lien avec le scénario « anti-brouteur »

La démarche **légale** ne cherche pas à pirater le tél de l'arnaqueur : elle
**recoupe et signale**.
- L'IP + géoloc + flag VPN/proxy (collectés sans permission par l'outil du TP)
  suffisent à établir des **incohérences** (position réelle vs prétendue, fuseau).
- On **signale** avec ces éléments : Pharos (internet-signalement.gouv.fr),
  cybermalveillance.gouv.fr, la plateforme, l'`abuse@` de l'hébergeur.

## Références
- MDN — Permissions API, Geolocation API, MediaDevices.getUserMedia
- web.dev — « Secure contexts », bonnes pratiques de demande de permission
- Chrome for Developers — indicateurs caméra/micro, réglages par site
