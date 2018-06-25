#!/usr/bin/env python
# -*- coding: utf-8 -*-


def all_messages():
    """
    keep all messages in de

    Returns:
        all messages in JSON
    """
    return \
        {
            "scan_started": "Nettacker Motor gestartet ...",
            "options": "python nettacker.py [Optionen]",
            "help_menu": "Zeige Nettacker Hilfe-Menü",
            "license": "Bitte lesen Sie die Lizenz und die Vereinbarungen https://github.com/zdresearch/OWASP-Nettacker",
            "engine": "Motor",
            "engine_input": "Motoreingangsoptionen",
            "select_language": "wähle eine Sprache {0}",
            "range": "scanne alle IPs im Bereich",
            "subdomains": "Subdomains finden und scannen",
            "thread_number_connections": "Thread-Nummern für Verbindungen zu einem Host",
            "thread_number_hosts": "Thread-Nummern für Scan-Hosts",
            "save_logs": "Speichern Sie alle Logs in der Datei (results.txt, results.html, results.json)",
            "target": "Ziel",
            "target_input": "Zieleingabeoptionen",
            "target_list": "Ziel (e) Liste, getrennt mit \",\"",
            "read_target": "Lese Ziel (e) aus Datei",
            "scan_method_options": "Scan-Methodenoptionen",
            "choose_scan_method": "Suchmethode {0} auswählen",
            "exclude_scan_method": "Suchmethode auswählen, um {0} auszuschließen",
            "username_list": "Benutzername (s) Liste, getrennt mit \",\"",
            "username_from_file": "Lese den Benutzernamen aus der Datei",
            "password_seperator": "Passwort (s) Liste, getrennt mit \",\"",
            "read_passwords": "Lies das Passwort aus der Datei",
            "port_seperator": "Port (s) Liste, getrennt mit \",\"",
            "time_to_sleep": "Zeit zwischen jeder Anfrage zu schlafen",
            "error_target": "Das Ziel (die Ziele) kann nicht angegeben werden",
            "error_target_file": "Die Ziele können nicht angegeben werden, Datei kann nicht geöffnet werden: {0}",
            "thread_number_warning": "Es ist besser, die Thread-Nummer niedriger als 100 zu verwenden, "
                                     "BTW wir fahren fort ...",
            "set_timeout": "Setzen Sie Timeout auf {0} Sekunden, es ist zu groß, oder? Übrigens machen wir weiter ...",
            "scan_module_not_found": "Dieses Scanmodul [{0}] wurde nicht gefunden!",
            "error_exclude_all": "Sie können nicht alle Scanmethoden ausschließen",
            "exclude_module_error": "Das Modul {0}, das Sie zum Ausschluss ausgewählt haben, wurde nicht gefunden!",
            "method_inputs": "Geben Sie Methodeneingaben ein, zum Beispiel: ftp_brute_users = test, admin & "
                             "ftp_brute_passwds = read_from_file: /tmp/pass.txt&ftp_brute_port=21",
            "error_reading_file": "kann die Datei {0} nicht lesen",
            "error_username": "Kann den Benutzernamen nicht angeben, Datei kann nicht geöffnet werden: {0}",
            "found": "{0} gefunden! ({1}: {2})",
            "error_password_file": "Kann das / die Passwort (e) nicht angeben, Datei kann nicht geöffnet werden: {0}",
            "file_write_error": "Datei \"{0}\" ist nicht beschreibbar!",
            "scan_method_select": "Bitte wählen Sie Ihre Scan-Methode!",
            "remove_temp": "Entfernen von temporären Dateien!",
            "sorting_results": "Ergebnisse sortieren!",
            "done": "erledigt!",
            "start_attack": "fange an, {0}, {1} von {2} anzugreifen",
            "module_not_available": "Dieses Modul \"{0}\" ist nicht verfügbar",
            "error_platform": "Leider konnte diese Version der Software nur unter Linux / Osx / Windows "
                              "ausgeführt werden.",
            "python_version_error": "Ihre Python-Version wird nicht unterstützt!",
            "skip_duplicate_target": "Doppeltes Ziel überspringen (einige Subdomains / Domains können dieselbe "
                                     "IP und dieselben Bereiche haben)",
            "unknown_target": "unbekannter Zieltyp [{0}]",
            "checking_range": "Überprüfung des Bereichs {0} ...",
            "checking": "Überprüfung von {0} ...",
            "HOST": "GASTGEBER",
            "USERNAME": "NUTZERNAME",
            "PASSWORD": "PASSWORT",
            "PORT": "HAFEN",
            "TYPE": "ART",
            "DESCRIPTION": "BESCHREIBUNG",
            "verbose_level": "Ausführlicher Modus (0-5) (Standard 0)",
            "software_version": "Softwareversion anzeigen",
            "check_updates": "auf Update überprüfen",
            "outgoing_proxy": "Proxy für ausgehende Verbindungen (Socks). Beispiel socks5: 127.0.0.1:9050, "
                              "Socken: //127.0.0.1: 9050 Socken5: //127.0.0.1: 9050 oder socks4: socks4: //"
                              "127.0.0.1: 9050, Authentifizierung: socks: // Benutzername: Passwort @ 127.0.0.1,"
                              " socks4: // Benutzername: password@127.0.0.1, socks5: //"
                              " Benutzername: password@127.0.0.1",
            "valid_socks_address": "Bitte geben Sie eine gültige Socken Adresse und Port ein. Beispiel socks5:"
                                   " 127.0.0.1:9050, socks: //127.0.0.1: 9050, socks5: //127.0.0.1: 9050 oder"
                                   " socks4: socks4: //127.0.0.1: 9050, authentication: socks: // username: "
                                   "password @ 127.0.0.1, socks4: // Benutzername: password@127.0.0.1, socks5: "
                                   "// Benutzername: password@127.0.0.1",
            "connection_retries": "Wiederholt, wenn das Verbindungstimeout abgelaufen ist (Standard 3)",
            "ftp_connection_timeout": "FTP-Verbindung zu {0}: {1} Zeitüberschreitung, Überspringen von {2}: {3}",
            "login_successful": "ERFOLGREICH EINGELOGGT!",
            "login_list_error": "ERFOLGREICH ERFOLGT, ERLAUBNIS FÜR LISTENBEFEHLE VERPFLICHTET!",
            "ftp_connection_failed": "ftp-Verbindung zu {0}: {1} ist fehlgeschlagen und hat den gesamten Schritt "
                                     "[Prozess {2} von {3}] übersprungen! gehe zum nächsten Schritt",
            "input_target_error": "Das Eingabeziel für das Modul {0} muss DOMAIN, HTTP oder SINGLE_IPv4 lauten, "
                                  "wobei {1} übersprungen wird.",
            "user_pass_found": "Benutzer: {0} Pass: {1} Host: {2} Port: {3} gefunden!",
            "file_listing_error": "(KEINE ERLAUBNIS FÜR LISTENDATEIEN)",
            "trying_message": "{0} von {1} im Prozess {2} von {3} {4} versuchen: {5} ({6})",
            "smtp_connection_timeout": "SMTP-Verbindung zu {0}: {1} Zeitüberschreitung, Überspringen von {2}: {3}",
            "smtp_connection_failed": "Die SMTP-Verbindung zu {0}: {1} ist fehlgeschlagen. Der gesamte Schritt "
                                      "[Prozess {2} von {3}] wurde übersprungen! gehe zum nächsten Schritt",
            "ssh_connection_timeout": "ssh-Verbindung zu {0}: {1} Zeitüberschreitung, Überspringen von {2}: {3}",
            "ssh_connection_failed": "ssh-Verbindung zu {0}: {1} ist fehlgeschlagen und hat den gesamten Schritt "
                                     "[Prozess {2} von {3}] übersprungen! gehe zum nächsten Schritt",
            "port/type": "{0} / {1}",
            "port_found": "host: {0} port: {1} ({2}) gefunden!",
            "target_submitted": "Ziel {0} gesendet!",
            "current_version": "Sie führen die OWASP Nettacker-Version {0} {1} {2} {6} mit dem Codenamen {3} {4} {5}",
            "feature_unavailable": "Diese Funktion ist noch nicht verfügbar! bitte starte \"git "
                                   "clone https://github.com/zdresearch/OWASP-Nettacker.git oder pip install -U "
                                   "OWASP-Nettacker um die letzte Version zu erhalten.",
            "available_graph": "Erstellen Sie ein Diagramm aller Aktivitäten und Informationen, Sie müssen "
                               "HTML-Ausgabe verwenden. verfügbare Diagramme: {0}",
            "graph_output": "Um die Graphenfunktion zu verwenden, muss der Ausgabedateiname mit \".html\" oder "
                            "\".htm\" enden!",
            "build_graph": "Baudiagramm ...",
            "finish_build_graph": "Baugraph fertigstellen!",
            "pentest_graphs": "Penetration Testing Graphs",
            "graph_message": "Diese Grafik wurde von OWASP Nettacker erstellt. Diagramm enthält alle Modulaktivitäten,"
                             " Netzwerkkarte und vertrauliche Informationen. Bitte teilen Sie diese Datei nicht mit"
                             " anderen, wenn sie nicht zuverlässig ist.",
            "nettacker_report": "OWASP Nettacker Bericht",
            "nettacker_version_details": "Softwaredetails: OWASP Nettacker Version {0} [{1}] in {2}",
            "no_open_ports": "Keine offenen Ports gefunden!",
            "no_user_passwords": "kein Benutzer / Passwort gefunden!",
            "loaded_modules": "{0} Module geladen ...",
            "graph_module_404": "Dieses Grafikmodul wurde nicht gefunden: {0}",
            "graph_module_unavailable": "Dieses Grafikmodul \"{0}\" ist nicht verfügbar",
            "ping_before_scan": "ping vor dem Host scannen",
            "skipping_target": "Das ganze Ziel {0} und die Scanmethode {1} werden ignoriert, da --ping-before-scan "
                               "wahr ist und nicht reagiert hat!",
            "not_last_version": "Du verwendest nicht die letzte Version von OWASP Nettacker, bitte update.",
            "cannot_update": "kann nicht nach Updates suchen, überprüfen Sie bitte Ihre Internetverbindung.",
            "last_version": "Sie benutzen die letzte Version von OWASP Nettacker ...",
            "directoy_listing": "Verzeichnisliste in {0} gefunden",
            "insert_port_message": "Bitte geben Sie den Port über den Schalter -g "
                                   "oder --methods-args anstelle der URL ein",
            "http_connection_timeout": "http Verbindung {0} Zeitüberschreitung!",
            "wizard_mode": "Starten Sie den Assistentenmodus",
            "directory_file_404": "Kein Verzeichnis oder keine Datei für {0} in Port {1} gefunden",
            "open_error": "{0} kann nicht geöffnet werden",
            "dir_scan_get": "dir_scan_http_method Wert muss GET oder HEAD sein, setzen Sie den Standardwert auf GET.",
            "list_methods": "listet alle Methoden args auf",
            "module_args_error": "Modulargumente {0} können nicht abgerufen werden",
            "trying_process": "{0} von {1} im Prozess {2} von {3} auf {4} ({5}) versuchen",
            "domain_found": "Domäne gefunden: {0}",
            "TIME": "ZEIT",
            "CATEGORY": "KATEGORIE",
            "module_pattern_404": "kann kein Modul mit {0} -Muster finden!",
            "enter_default": "Bitte geben Sie {0} | ein Standard [{1}]>",
            "enter_choices_default": "Bitte geben Sie {0} | ein Auswahl [{1}] | Standard [{2}]>",
            "all_targets": "die Ziele",
            "all_thread_numbers": "die Thread-Nummer",
            "out_file": "der Ausgabedateiname",
            "all_scan_methods": "die Scan-Methoden",
            "all_scan_methods_exclude": "die auszuschließenden Scan-Methoden",
            "all_usernames": "die Benutzernamen",
            "all_passwords": "die Passwörter",
            "timeout_seconds": "die Zeitüberschreitung Sekunden",
            "all_ports": "die Portnummern",
            "all_verbose_level": "die ausführliche Ebene",
            "all_socks_proxy": "der Socken-Proxy",
            "retries_number": "die Wiederholungsnummer",
            "graph": "ein Graph",
            "subdomain_found": "Subdomain gefunden: {0}",
            "select_profile": "wähle Profil {0}",
            "profile_404": "das Profil \"{0}\" wurde nicht gefunden!",
            "waiting": "Warten auf {0}",
            "vulnerable": "anfällig für {0}",
            "target_vulnerable": "Ziel {0}: {1} ist anfällig für {2}!",
            "no_vulnerability_found": "keine Verwundbarkeit gefunden! ({0})",
            "Method": "Methode",
            "API": "API",
            "API_options": "API-Optionen",
            "start_API": "Starten Sie den API-Dienst",
            "API_host": "API-Hostadresse",
            "API_port": "API-Portnummer",
            "API_debug": "API-Debugmodus",
            "API_access_key": "API-Zugriffsschlüssel",
            "white_list_API": "erlauben Sie Whitelist-Hosts nur, sich mit der API zu verbinden",
            "define_whie_list": "Definieren Sie Whitelist-Hosts, getrennt mit, (Beispiele: 127.0.0.1, "
                                "192.168.0.1/24, 10.0.0.1-10.0.0.255)",
            "gen_API_access_log": "API-Zugriffsprotokoll generieren",
            "API_access_log_file": "API-Zugriffsprotokolldateiname",
            "API_port_int": "API-Port muss eine Ganzzahl sein!",
            "unknown_ip_input": "unbekannter Eingangstyp, akzeptierte Typen sind SINGLE_IPv4, RANGE_IPv4, CIDR_IPv4",
            "API_key": "* API-Schlüssel: {0}",
            "ports_int": "Ports müssen Ganzzahlen sein! (z. B. 80 || 80,1080 || 80,1080-1300,9000,12000-15000)",
            "through_API": "Durch die OWASP Nettacker API",
            "API_invalid": "ungültiger API-Schlüssel",
            "unauthorized_IP": "Ihre IP nicht autorisiert",
            "not_found": "Nicht gefunden!",
            "no_subdomain_found": "subdomain_scan: Keine Subdomain gegründet!",
            "viewdns_domain_404": "viewdns_reverse_ip_lookup_scan: keine Domain gefunden!",
            "browser_session_valid": "Ihre Browsersitzung ist gültig",
            "browser_session_killed": "Ihre Browsersitzung wurde beendet",
            "updating_database": "Aktualisierung der Datenbank ...",
            "database_connect_fail": "Verbindung mit der Datenbank fehlgeschlagen!",
            "inserting_report_db": "Bericht in die Datenbank einfügen",
            "inserting_logs_db": "Einfügen von Protokollen in die Datenbank",
            "removing_logs_db": "Entfernen alter Protokolle aus db",
            "len_subdomain_found": "{0} Subdomain (s) gefunden!",
            "len_domain_found": "{0} Domain (s) gefunden!",
            "phpmyadmin_dir_404": "kein phpmyadmin Verzeichnis gefunden!",
            "DOS_send": "Senden von DoS-Paketen an {0}",
            "host_up": "{0} ist abgelaufen! Die Zeit bis zum Zurücksenden ist {1}",
            "host_down": "Kann nicht {0} pingen!",
            "root_required": "Dies muss als root ausgeführt werden",
            "admin_scan_get": "admin_scan_http_method Wert muss GET oder HEAD sein, setzen Sie"
                              " den Standardwert auf GET.",
            "telnet_connection_timeout": "Telnet-Verbindung zu {0}: {1} Zeitüberschreitung, Überspringen von {2}: {3}",
            "telnet_connection_failed": "Die Telnet-Verbindung zu {0}: {1} ist fehlgeschlagen. Der ganze "
                                        "Schritt [Prozess {2} von {3}] wurde übersprungen! gehe zum "
                                        "nächsten Schritt",
            "http_auth_success": "HTTP-Basisauthentifizierung erfolgreich - Host: {2}: {3}, Benutzer: {0}, "
                                 "übergeben: {1} gefunden!",
            "http_auth_failed": "HTTP-Basisauthentifizierung fehlgeschlagen an {0}: {3} mit {1}: {2}",
            "http_form_auth_success": "HTTP-Authentifizierungserfolg - Host: {2}: {3}, Benutzer: "
                                      "{0}, Pass: {1} gefunden!",
            "http_form_auth_failed": "http-Formularauthentifizierung fehlgeschlagen an {0}: {3} mit {1}: {2}",
            "http_ntlm_success": "http ntlm Authentifizierungserfolg - Host: {2}: {3}, Benutzer: {0},"
                                 " Pass: {1} gefunden!",
            "http_ntlm_failed": "Die http-ntlm-Authentifizierung ist mit {0}: {3} mit {1} fehlgeschlagen: {2}",
            "no_response": "kann keine Antwort vom Ziel erhalten",
            "category_framework": "Kategorie: {0}, Frameworks: {1} gefunden!",
            "nothing_found": "Nichts gefunden auf {0} in {1}!",
            "no_auth": "Keine Authentifizierung in {0} gefunden: {1}"
        }
