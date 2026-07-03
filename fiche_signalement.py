#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Génère des fiches de SIGNALEMENT (.txt) à partir de captures/journal.jsonl.

Usage légal : documenter un arnaqueur qui a cliqué TON lien, pour un dépôt
Pharos / cybermalveillance.gouv.fr. Ce script ne pirate rien : il met en forme
l'intel déjà collectée passivement (IP, géoloc, flags VPN/proxy, empreinte
navigateur). Aucun accès au contenu du téléphone.
"""
import json
from pathlib import Path
from collections import defaultdict
from datetime import datetime

BASE = Path(__file__).parent
JOURNAL = BASE / "captures" / "journal.jsonl"
OUT = BASE / "captures"


def charger():
    visites = []
    if JOURNAL.exists():
        for ligne in JOURNAL.read_text(encoding="utf-8").splitlines():
            ligne = ligne.strip()
            if ligne:
                try:
                    visites.append(json.loads(ligne))
                except json.JSONDecodeError:
                    pass
    return visites


def fiche(ip, visites):
    geo = {}
    for v in visites:                      # dernière géoloc non vide
        if v.get("geoloc_ip"):
            geo = v["geoloc_ip"]
    dernier = visites[-1]
    app = dernier.get("appareil_client", {})
    http = dernier.get("en_tetes_http", {})
    hors = [v.get("horodatage", "?") for v in visites]

    L = ["=" * 60,
         "  FICHE DE SIGNALEMENT — activité suspecte",
         "  généré le " + datetime.now().strftime("%Y-%m-%d %H:%M"),
         "=" * 60, "",
         f"ADRESSE IP           : {ip}",
         f"Nombre de connexions : {len(visites)}",
         f"Horodatages          : {', '.join(hors)}", "",
         "-- LOCALISATION (par IP) --"]
    for k in ("pays", "region", "ville", "code_postal", "coordonnees_IP", "FAI",
              "operateur", "AS", "reseau_mobile", "VPN_proxy", "hebergement_datacenter"):
        if k in geo:
            L.append(f"  {k:22}: {geo[k]}")

    L += ["", "-- APPAREIL (via le navigateur) --"]
    for k in ("userAgent", "plateforme", "GPU", "ecran", "fuseau_horaire",
              "langues", "connexion", "batterie"):
        if k in app:
            L.append(f"  {k:22}: {app[k]}")

    L += ["", "-- EN-TÊTES HTTP --"]
    for k, v in http.items():
        L.append(f"  {k:22}: {v}")

    L += ["", "-- POINTS À VÉRIFIER / INCOHÉRENCES --"]
    flags = []
    if "⚠️" in str(geo.get("VPN_proxy", "")):
        flags.append("VPN/proxy détecté : la géoloc IP n'est PAS la position réelle.")
    if "⚠️" in str(geo.get("hebergement_datacenter", "")):
        flags.append("IP de datacenter/hébergeur : connexion probablement relayée.")
    tz, pays, langs = app.get("fuseau_horaire", ""), geo.get("pays", ""), app.get("langues", "")
    if tz and pays:
        flags.append(f"Cohérence à vérifier : fuseau appareil ({tz}) vs pays géolocalisé ({pays}).")
    if langs and pays:
        flags.append(f"Cohérence à vérifier : langues navigateur ({langs}) vs pays ({pays}).")
    if not flags:
        flags.append("Aucun signal automatique ; vérification manuelle recommandée.")
    for f in flags:
        L.append(f"  - {f}")

    L += ["", "-- OÙ SIGNALER --",
          "  - Pharos            : https://www.internet-signalement.gouv.fr",
          "  - Cybermalveillance : https://www.cybermalveillance.gouv.fr",
          "  - La plateforme utilisée par l'arnaqueur (bouton « Signaler »)",
          "  - Hébergeur du site frauduleux : e-mail abuse@<hébergeur>", "",
          "Note : intelligence collectée passivement (IP + navigateur), aucun accès",
          "au contenu du téléphone. À joindre à un dépôt de plainte / signalement."]
    return "\n".join(L)


def main():
    visites = charger()
    if not visites:
        print("journal.jsonl vide — ouvre d'abord le lien sur un appareil de test.")
        return
    par_ip = defaultdict(list)
    for v in visites:
        par_ip[v.get("ip", "?")].append(v)
    for ip, vs in par_ip.items():
        nom = "signalement_" + ip.replace(":", "_").replace(".", "-") + ".txt"
        (OUT / nom).write_text(fiche(ip, vs), encoding="utf-8")
        print(f"→ captures/{nom}  ({len(vs)} visite(s))")
    print(f"Terminé : {len(par_ip)} fiche(s) générée(s).")


if __name__ == "__main__":
    main()
