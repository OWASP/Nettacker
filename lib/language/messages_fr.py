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
            "scan_started": "Moteur Nettacker a commencé ...",
            "options": "python nettacker.py [options]",
            "help_menu": "Afficher le menu d'aide de Nettacker",
            "license": "S'il vous plaît lire la licence et les accords https://github.com/zdresearch/OWASP-Nettacker",
            "engine": "Moteur",
            "engine_input": "Options de saisie du moteur",
            "select_language": "sélectionner une langue {0}",
            "range": "analyser toutes les adresses IP de la plage",
            "subdomains": "Rechercher et analyser des sous-domaines",
            "thread_number_connections": "numéros de thread pour les connexions à un hôte",
            "thread_number_hosts": "numéros de thread pour les hôtes d'analyse",
            "save_logs": "enregistrer tous les journaux dans le fichier (results.txt, results.html, results.json)",
            "target": "Cible",
            "target_input": "Options de saisie cible",
            "target_list": "liste (s) cible (s), séparée par \",\"",
            "read_target": "lire la (les) cible (s) à partir du fichier",
            "scan_method_options": "Options de méthode de numérisation",
            "choose_scan_method": "choisissez la méthode de scan {0}",
            "exclude_scan_method": "choisissez la méthode de scan pour exclure {0}",
            "username_list": "nom d'utilisateur (s), séparé par \",\"",
            "username_from_file": "lire le (s) nom (s) d'utilisateur à partir du fichier",
            "password_seperator": "mot de passe (s), séparé par \",\"",
            "read_passwords": "lire le (s) mot de passe (s) du fichier",
            "port_seperator": "port (s) list, séparé par \",\"",
            "time_to_sleep": "le temps de dormir entre chaque demande",
            "error_target": "Impossible de spécifier la ou les cibles",
            "error_target_file": "Impossible de spécifier la (les) cible (s), impossible d'ouvrir le fichier: {0}",
            "thread_number_warning": "il est préférable d'utiliser le numéro de fil"
                                     " inférieur à 100, BTW nous continuons ...",
            "set_timeout": "mettre timeout à {0} secondes, c'est trop gros, n'est-ce pas?"
                           " par la façon dont nous continuons ...",
            "scan_module_not_found": "ce module de scan [{0}] n'a pas été trouvé!",
            "error_exclude_all": "vous ne pouvez pas exclure toutes les méthodes de scan",
            "exclude_module_error": "le module {0} que vous avez sélectionné pour exclure non trouvé!",
            "method_inputs": "Entrez les entrées des méthodes, par exemple: ftp_brute_users ="
                             " test, admin & ftp_brute_passwds = read_from_file: /tmp/pass.txt&ftp_brute_port=21",
            "error_reading_file": "Impossible de lire le fichier {0}",
            "error_username": "Impossible de spécifier le (s) nom (s) d'utilisateur, "
                              "impossible d'ouvrir le fichier: {0}",
            "found": "{0} trouvé ({1}: {2})",
            "error_password_file": "Impossible de spécifier le (s) mot (s) de passe, impossible "
                                   "d'ouvrir le fichier: {0}",
            "file_write_error": "le fichier \"{0}\" n'est pas accessible en écriture!",
            "scan_method_select": "veuillez choisir votre méthode de scan!",
            "remove_temp": "enlever les fichiers temporaires!",
            "sorting_results": "tri des résultats!",
            "done": "terminé!",
            "start_attack": "commencer à attaquer {0}, {1} sur {2}",
            "module_not_available": "ce module \"{0}\" n'est pas disponible",
            "error_platform": "Malheureusement, cette version du logiciel pourrait simplement être exécutée"
                              " sous linux / osx / windows.",
            "python_version_error": "Votre version de Python n'est pas supportée!",
            "skip_duplicate_target": "ignorer la cible en double (certains sous-domaines / domaines peuvent"
                                     " avoir la même adresse IP et les mêmes plages)",
            "unknown_target": "type de cible inconnu [{0}]",
            "checking_range": "vérifier la plage {0} ...",
            "checking": "vérification {0} ...",
            "HOST": "HÔTE",
            "USERNAME": "NOM D'UTILISATEUR",
            "PASSWORD": "MOT DE PASSE",
            "PORT": "PORT",
            "TYPE": "TYPE",
            "DESCRIPTION": "LA DESCRIPTION",
            "verbose_level": "niveau de mode verbeux (0-5) (par défaut 0)",
            "software_version": "afficher la version du logiciel",
            "check_updates": "vérifier la mise à jour",
            "outgoing_proxy": "connexions sortantes proxy (chaussettes). exemple socks5: 127.0.0.1:9050,"
                              " chaussettes: //127.0.0.1: 9050 socks5: //127.0.0.1: 9050 ou socks4:"
                              " socks4: //127.0.0.1: 9050, authentification: socks: // nom d'utilisateur: "
                              "mot de passe @ 127.0.0.1, socks4: // nom d'utilisateur: password@127.0.0.1, "
                              "socks5: // nom d'utilisateur: password@127.0.0.1",
            "valid_socks_address": "s'il vous plaît entrer l'adresse de chaussettes valide et le port. "
                                   "exemple socks5: 127.0.0.1:9050, socks: //127.0.0.1: 9050,"
                                   " socks5: //127.0.0.1: 9050 ou socks4: socks4: //127.0.0.1: 9050,"
                                   " authentification: socks: // nom d'utilisateur: mot de passe @ 127.0.0.1, "
                                   "socks4: // nom d'utilisateur: password@127.0.0.1, socks5: // nom d'utilisateur:"
                                   " password@127.0.0.1",
            "connection_retries": "Réessaie lorsque le délai d'attente de connexion (par défaut 3)",
            "ftp_connection_timeout": "connexion ftp à {0}: {1} délai d'expiration, ignorant {2}: {3}",
            "login_successful": "CONNECTÉ AVEC SUCCÈS!",
            "login_list_error": "CONNUS EN SUCCÈS, PERMISSION REFUSÉE POUR LA COMMANDE DE LISTE!",
            "ftp_connection_failed": "La connexion ftp à {0}: {1} a échoué, ignorant l'étape entière [processus "
                                     "{2} de {3}]! aller à la prochaine étape",
            "input_target_error": "La cible d'entrée pour le module {0} doit être DOMAIN, HTTP ou SINGLE_IPv4,"
                                  " en ignorant {1}",
            "user_pass_found": "utilisateur: {0} passer: {1} hôte: {2} port: {3} trouvé!",
            "file_listing_error": "(PAS DE PERMISSION POUR LES FICHIERS DE LISTE)",
            "trying_message": "essayer {0} sur {1} dans le processus {2} de {3} {4}: {5} ({6})",
            "smtp_connection_timeout": "Connexion smtp à {0}: {1} timeout, ignorez {2}: {3}",
            "smtp_connection_failed": "La connexion smtp à {0}: {1} a échoué, en sautant l'étape entière [processus "
                                      "{2} de {3}]! aller à la prochaine étape",
            "ssh_connection_timeout": "Connexion ssh à {0}: {1} timeout, ignorez {2}: {3}",
            "ssh_connection_failed": "La connexion ssh à {0}: {1} a échoué, en ignorant l'étape entière"
                                     " [processus {2} de {3}]! aller à la prochaine étape",
            "port/type": "{0} / {1}",
            "port_found": "hôte: {0} port: {1} ({2}) trouvé!",
            "target_submitted": "cible {0} soumise!",
            "current_version": "vous utilisez la version OWASP Nettacker {0} {1} {2} {6} avec le "
                               "nom de code {3} {4} {5}",
            "feature_unavailable": "cette fonctionnalité n'est pas encore disponible! S'il vous plaît exécuter"
                                   " \"git clone https://github.com/zdresearch/OWASP-Nettacker.git ou pip "
                                   "installer -U OWASP-Nettacker pour obtenir la dernière version.",
            "available_graph": "construire un graphique de toutes les activités et informations, vous devez"
                               " utiliser la sortie HTML. graphiques disponibles: {0}",
            "graph_output": "Pour utiliser la fonction graphique, votre nom de fichier de sortie doit se "
                            "terminer par \".html\" ou \".htm\"!",
            "build_graph": "graphique de construction ...",
            "finish_build_graph": "terminer le graphique de construction!",
            "pentest_graphs": "Graphiques de test de pénétration",
            "graph_message": "Ce graphique créé par OWASP Nettacker. Le graphique contient toutes les activités "
                             "des modules, la carte du réseau et les informations sensibles. Veuillez ne pas"
                             " partager ce fichier avec qui que ce soit s'il n'est pas fiable.",
            "nettacker_report": "Rapport OWASP Nettacker",
            "nettacker_version_details": "Détails sur le logiciel: OWASP Nettacker version {0} [{1}] dans {2}",
            "no_open_ports": "aucun port ouvert trouvé!",
            "no_user_passwords": "aucun utilisateur / mot de passe trouvé!",
            "loaded_modules": "{0} modules chargés ...",
            "graph_module_404": "ce module graphique n'est pas trouvé: {0}",
            "graph_module_unavailable": "ce module graphique \"{0}\" n'est pas disponible",
            "ping_before_scan": "ping avant de scanner l'hôte",
            "skipping_target": "ignorer la cible entière {0} et la méthode de scan {1} à cause de --ping-before-scan "
                               "est vrai et n'a pas répondu!",
            "not_last_version": "vous n'utilisez pas la dernière version d'OWASP Nettacker, veuillez mettre à jour.",
            "cannot_update": "ne peut pas vérifier la mise à jour, s'il vous plaît vérifier votre connexion Internet.",
            "last_version": "Vous utilisez la dernière version de OWASP Nettacker ...",
            "directoy_listing": "liste de répertoires trouvée dans {0}",
            "insert_port_message": "s'il vous plaît insérer le port à travers le commutateur -g ou --methods-args "
                                   "au lieu de l'URL",
            "http_connection_timeout": "Connexion http {0} timeout!",
            "wizard_mode": "démarrer le mode assistant",
            "directory_file_404": "aucun répertoire ou fichier trouvé pour {0} dans le port {1}",
            "open_error": "impossible d'ouvrir {0}",
            "dir_scan_get": "La valeur dir_scan_http_method doit être GET ou HEAD, définie par défaut sur GET.",
            "list_methods": "liste toutes les méthodes args",
            "module_args_error": "impossible d'obtenir les arguments du module {0}",
            "trying_process": "essayer {0} sur {1} dans le processus {2} de {3} sur {4} ({5})",
            "domain_found": "domaine trouvé: {0}",
            "TIME": "TEMPS",
            "CATEGORY": "CATÉGORIE",
            "module_pattern_404": "ne trouve aucun module avec le modèle {0}!",
            "enter_default": "veuillez entrer {0} | Par défaut [{1}]>",
            "enter_choices_default": "veuillez entrer {0} | choix [{1}] | Par défaut [{2}]>",
            "all_targets": "les cibles",
            "all_thread_numbers": "le numéro de fil",
            "out_file": "le nom du fichier de sortie",
            "all_scan_methods": "les méthodes de scan",
            "all_scan_methods_exclude": "les méthodes d'analyse pour exclure",
            "all_usernames": "les noms d'utilisateur",
            "all_passwords": "les mots de passe",
            "timeout_seconds": "les secondes d'expiration",
            "all_ports": "les numéros de port",
            "all_verbose_level": "le niveau verbeux",
            "all_socks_proxy": "le proxy des chaussettes",
            "retries_number": "le nombre de tentatives",
            "graph": "un graphique",
            "subdomain_found": "sous-domaine trouvé: {0}",
            "select_profile": "sélectionnez le profil {0}",
            "profile_404": "le profil \"{0}\" n'a pas été trouvé!",
            "waiting": "en attente de {0}",
            "vulnerable": "vulnérable à {0}",
            "target_vulnerable": "target {0}: {1} est vulnérable à {2}!",
            "no_vulnerability_found": "aucune vulnérabilité trouvée! ({0})",
            "Method": "Méthode",
            "API": "API",
            "API_options": "Options d'API",
            "start_API": "démarrer le service API",
            "API_host": "Adresse hôte de l'API",
            "API_port": "Numéro de port API",
            "API_debug": "Mode de débogage de l'API",
            "API_access_key": "Clé d'accès à l'API",
            "white_list_API": "autorisez simplement les hôtes de la liste blanche à se connecter à l'API",
            "define_whie_list": "définir des hôtes de liste blanche, séparés par, (exemples: 127.0.0.1, 192.168.0.1/24,"
                                " 10.0.0.1-10.0.0.255)",
            "gen_API_access_log": "générer un journal d'accès à l'API",
            "API_access_log_file": "Nom du fichier journal de l'accès API",
            "API_port_int": "Le port de l'API doit être un entier!",
            "unknown_ip_input": "Type d'entrée inconnu, les types acceptés sont SINGLE_IPv4, RANGE_IPv4, CIDR_IPv4",
            "API_key": "* Clé de l'API: {0}",
            "ports_int": "les ports doivent être des entiers! (par exemple 80 || 80,1080 || 80,1080"
                         "-1300,9000,12000-15000)",
            "through_API": "Grâce à l'API OWASP Nettacker",
            "API_invalid": "clé API non valide",
            "unauthorized_IP": "votre adresse IP n'est pas autorisée",
            "not_found": "Pas trouvé!",
            "no_subdomain_found": "subdomain_scan: aucun sous-domaine créé!",
            "viewdns_domain_404": "viewdns_reverse_ip_lookup_scan: aucun domaine trouvé!",
            "browser_session_valid": "votre session de navigateur est valide",
            "browser_session_killed": "votre session de navigateur a été tuée",
            "updating_database": "mettre à jour la base de données ...",
            "database_connect_fail": "Impossible de se connecter à la base de données!",
            "inserting_report_db": "insertion de rapport dans la base de données",
            "inserting_logs_db": "insertion de journaux dans la base de données",
            "removing_logs_db": "enlever les vieux logs de db",
            "len_subdomain_found": "{0} sous-domaine (s) trouvé (s)!",
            "len_domain_found": "{0} domaine (s) trouvé (s)!",
            "phpmyadmin_dir_404": "pas de répertoire phpmyadmin trouvé!",
            "DOS_send": "envoi de paquets DoS à {0}",
            "host_up": "{0} est en hausse! Le temps nécessaire pour effectuer un ping est de {1}",
            "host_down": "Impossible de pinguer {0}!",
            "root_required": "cela doit être exécuté en tant que root",
            "admin_scan_get": "La valeur admin_scan_http_method doit être GET ou HEAD, définie par défaut sur GET.",
            "telnet_connection_timeout": "Connexion telnet à {0}: {1} délai d'expiration, ignorant {2}: {3}",
            "telnet_connection_failed": "La connexion telnet à {0}: {1} a échoué, en sautant l'étape entière "
                                        "[processus {2} de {3}]! aller à la prochaine étape",
            "http_auth_success": "Succès de l'authentification de base http - hôte: {2}: {3}, utilisateur: {0}, "
                                 "réussite: {1} trouvé!",
            "http_auth_failed": "Échec de l'authentification de base HTTP à {0}: {3} utilisation de {1}: {2}",
            "http_form_auth_success": "Succès d'authentification du formulaire http - hôte: {2}: {3}, utilisateur: "
                                      "{0}, réussite: {1} trouvée!",
            "http_form_auth_failed": "Échec de l'authentification du formulaire http à {0}: {3} à l'aide de {1}: {2}",
            "http_ntlm_success": "Succès de l'authentification http ntlm - hôte: {2}: {3}, utilisateur: {0}, "
                                 "réussite: {1} trouvée!",
            "http_ntlm_failed": "Échec de l'authentification http ntlm à {0}: {3} à l'aide de {1}: {2}",
            "no_response": "ne peut pas obtenir de réponse de la cible",
            "category_framework": "catégorie: {0}, frameworks: {1} trouvé!",
            "nothing_found": "rien trouvé sur {0} dans {1}!",
            "no_auth": "Aucune autorisation trouvée sur {0}: {1}"
        }
