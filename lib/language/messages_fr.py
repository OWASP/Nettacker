#!/usr/bin/env python
# -*- coding: utf-8 -*-


def all_messages():
    """
    keep all messages in fr

    Returns:
        all messages in JSON
    """
    return \
        {
            "0": "Le moteur de Nettacker a commencé ...\n\n",
            "1": "python nettacker.py [options]",
            "2": "Afficher le menu Aide de Nettacker",
            "3": "Veuillez lire la licence et les accords https://github.com/viraintel/OWASP-Nettacker\n",
            "4": "Moteur",
            "5": "Options d'entrée du moteur",
            "6": "sélectionnez une langue {0}",
            "7": "analyser toutes les adresses IP de la gamme",
            "8": "trouver et analyser des sous-domaines",
            "9": "numéros de thread pour les connexions à un hôte",
            "10": "numéros de thread pour les hôtes de scan",
            "11": "enregistrer tous les journaux dans le fichier (results.txt, results.html, results.json)",
            "12": "Cible",
            "13": "Cibler les options de saisie",
            "14": "cible (s), séparez-les par \",\"",
            "15": "lire les cibles du fichier",
            "16": "Options de la méthode de scan",
            "17": "choisissez la méthode de scan {0}",
            "18": "choisissez la méthode de scan pour exclure {0}",
            "19": "nom d'utilisateur (s), séparez-les par \",\"",
            "20": "lire le (s) nom (s) d'utilisateur du fichier",
            "21": "mot de passe (s), séparez-les par \",\"",
            "22": "lire les mots de passe du fichier",
            "23": "port (s), séparez-les par \",\"",
            "24": "lire le ou les mots de passe du fichier",
            "25": "le temps de dormir entre chaque demande",
            "26": "Impossible de spécifier la (les) cible (s)",
            "27": "Impossible de spécifier la cible (s), impossible d'ouvrir le fichier: {0}",
            "28": "il vaut mieux utiliser un nombre de fils inférieur à 100, BTW nous continuons ...",
            "29": "définissez le délai d'expiration sur {0} secondes, c'est trop gros, n'est-ce pas? "
                  "par la façon dont nous continuons ...",
            "30": "ce module de scan [{0}] introuvable!",
            "31": "ce module de scan [{0}] introuvable!",
            "32": "vous ne pouvez pas exclure toutes les méthodes d'analyse",
            "33": "vous ne pouvez pas exclure toutes les méthodes d'analyse",
            "34": "le module {0} que vous avez choisi d'exclure n'a pas été trouvé!",
            "35": "enter methods inputs, example: \"ftp_brute_users=test,admin&ftp_brute_passwds=read_from_file"
                  ":/tmp/pass.txt&ftp_brute_port=21\"",
            "36": "Impossible de lire le fichier {0}",
            "37": "Impossible d'indiquer le nom d'utilisateur (s), impossible d'ouvrir le fichier: {0}",
            "38": "",
            "39": "Impossible de spécifier le ou les mots de passe, impossible d'ouvrir le fichier: {0}",
            "40": "le fichier \"{0}\" n'est pas accessible en écriture!",
            "41": "veuillez choisir votre méthode de scan!",
            "42": "enlever les fichiers temporaires!",
            "43": "tri des résultats!",
            "44": "terminé!",
            "45": "commencez à attaquer {0}, {1} sur {2}",
            "46": "ce module \"{0}\" n'est pas disponible",
            "47": "Malheureusement, cette version du logiciel pourrait être exécutée sur linux/osx/windows.",
            "48": "Votre version Python n'est pas supportée!",
            "49": "Ignorer la cible dupliquée (certains sous-domaines / domaines peuvent avoir la même IP"
                  " et les mêmes plages)",
            "50": "type inconnu de cible [{0}]",
            "51": "vérification de la plage {0} ...",
            "52": "vérification de {0} ...",
            "53": "HÔTE",
            "54": "NOM D'UTILISATEUR",
            "55": "MOT DE PASSE",
            "56": "PORT",
            "57": "TYPE",
            "58": "DESCRIPTION",
            "59": "niveau de mode verbeux (0-5) (0 par défaut)",
            "60": "afficher la version du logiciel",
            "61": "vérifier la mise à jour",
            "62": "",
            "63": "",
            "64": "Tentatives lorsque le délai de connexion (par défaut 3)",
            "65": "ftp à {0}: {1} timeout, en ignorant {2}: {3}",
            "66": "CONNECTÉ AVEC SUCCÈS!",
            "67": "CONNECTÉ AVEC SUCCÈS, AUTORISATION PERMISE POUR COMMANDEMENT DE LISTE!",
            "68": "la connexion ftp à {0}: {1} a échoué, sauter toute l'étape [processus {2} de {3}]! "
                  "passer à l'étape suivante",
            "69": "la cible d'entrée pour le module {0} doit être DOMAIN, HTTP ou SINGLE_IPv4, en ignorant {1}",
            "70": "utilisateur: {0} passe: {1} hôte: {2} port: {3} trouvé!",
            "71": "(PAS DE PERMISSION POUR LES FICHIERS DE LISTE)",
            "72": "en essayant {0} de {1} dans le processus {2} de {3} {4}: {5}",
            "73": "connexion smtp à {0}: {1} délai d'attente, en ignorant {2}: {3}",
            "74": "La connexion smtp à {0}: {1} a échoué, sautant toute l'étape [process {2} of {3}]! "
                  "passer à l'étape suivante",
            "75": "la cible d'entrée pour le module {0} doit être HTTP, en ignorant {1}",
            "76": "connexion ssh à {0}: {1} timeout, en ignorant {2}: {3}",
            "77": "La connexion ssh à {0}: {1} a échoué, sauter toute l'étape [process {2} of {3}]! "
                  "passer à l'étape suivante",
            "78": "connexion ssh à% s:% s a échoué, sauter toute l'étape [processus% s de% s]! passer "
                  "à l'étape suivante",
            "79": "PORT OUVERT",
            "80": "hôte: {0} port: {1} trouvé!",
            "81": "target {0} soumis!",
            "82": "Impossible d'ouvrir le fichier de liste de proxies: {0}",
            "83": "ne peut pas trouver le fichier de liste de proxy: {0}",
            "84": "vous exécutez la version {0} {1} {2} {6} d'OWASP Nettacker avec le nom de code {3} {4} {5}",
            "85": "cette fonctionnalité n'est pas encore disponible! veuillez exécuter \"git clone"
                  " https://github.com/viraintel/OWASP-Nettacker.git\" ou \"pip installer -U OWASP-Nettacker\" "
                  "pour obtenir la dernière version.",
            "86": "construire un graphique de toutes les activités et informations, vous devez utiliser "
                  "la sortie HTML. graphiques disponibles: {0}",
            "87": "pour utiliser la fonction graphique, votre nom de fichier de sortie doit se "
                  "terminer par \".html\" ou \".htm\"!",
            "88": "graphique de construction ...",
            "89": "terminer la construction graphique!",
            "90": "Graphiques de test de pénétration",
            "91": "Ce graphique a été créé par OWASP Nettacker. Le graphique contient toutes les "
                  "activités des modules, la carte réseau et les informations sensibles. Veuillez ne "
                  "partager ce fichier avec personne si ce n'est pas fiable.",
            "92": "OWASP Nettacker Report",
            "93": "Détails du logiciel: OWASP Nettacker version {0} [{1}] dans {2}",
            "94": "pas de ports ouverts trouvés!",
            "95": "aucun utilisateur / mot de passe trouvé!",
            "96": "{0} modules chargés ...",
            "97": "ce module graphique n'a pas été trouvé: {0}",
            "98": "ce module graphique \"{0}\" n'est pas disponible",
            "99": "ping avant de scanner l'hôte",
            "100": "en sautant la cible entière {0} et la méthode d'analyse {1} à cause de "
                   "--ping-before-scan est vrai et n'a pas répondu!",
            "101": "vous n'utilisez pas la dernière version de OWASP Nettacker, veuillez mettre à jour.",
            "102": "ne peut pas vérifier la mise à jour, s'il vous plaît vérifier votre connexion Internet.",
            "103": "Vous utilisez la dernière version d'OWASP Nettacker ...",
            "104": "liste de répertoires trouvée dans {0}",
            "105": "s'il vous plaît insérer le port à travers le commutateur -g ou --methods-args au lieu de l'URL",
            "106": "http connection {0} timeout!",
            "107": "",
            "108": "aucun répertoire ou fichier trouvé pour {0} dans le port {1}",
            "109": "impossible d'ouvrir {0}",
            "110": "La valeur dir_scan_http_method doit être GET ou HEAD, définie par défaut sur GET.",
            "111": "liste toutes les méthodes args",
            "112": "cannot get {0} module args",
            "113": "",
            "114": "",
            "115": "",
            "116": "",
            "117": ""
        }
