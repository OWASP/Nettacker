#!/usr/bin/env python
# -*- coding: utf-8 -*-


def all_messages():
    """
    keep all messages in it

    Returns:
        all messages in JSON
    """
    return \
        {
            "scan_started": "Il motore Nettacker ha iniziato ...",
            "options": "python nettacker.py [opzioni]",
            "help_menu": "Mostra il menu Aiuto di Nettacker",
            "license": "Si prega di leggere la licenza e gli accordi https://github.com/zdresearch/OWASP-Nettacker",
            "engine": "Motore",
            "engine_input": "Opzioni di input del motore",
            "select_language": "seleziona una lingua {0}",
            "range": "scansiona tutti gli IP nell'intervallo",
            "subdomains": "trova e scansiona sottodomini",
            "thread_number_connections": "numeri di thread per le connessioni a un host",
            "thread_number_hosts": "numeri di thread per gli host di scansione",
            "save_logs": "salva tutti i registri nel file (results.txt, results.html, results.json)",
            "target": "Bersaglio",
            "target_input": "Opzioni di input target",
            "target_list": "elenco target (s), separare con \",\"",
            "read_target": "legge il / i bersaglio / i dal file",
            "scan_method_options": "Opzioni del metodo di scansione",
            "choose_scan_method": "scegli il metodo di scansione {0}",
            "exclude_scan_method": "scegli il metodo di scansione per escludere {0}",
            "username_list": "nome utente (s), separare con \",\"",
            "username_from_file": "leggi username (s) dal file",
            "password_seperator": "lista password (s), separare con \",\"",
            "read_passwords": "leggere password (s) dal file",
            "port_seperator": "elenco port (s), separare con \",\"",
            "time_to_sleep": "tempo di dormire tra ogni richiesta",
            "error_target": "Non è possibile specificare il / i target / i",
            "error_target_file": "Impossibile specificare il / i target / i, impossibile aprire il file: {0}",
            "thread_number_warning": "è meglio usare il numero di thread inferiore a 100, BTW stiamo continuando ...",
            "set_timeout": "imposta il timeout su {0} secondi, è troppo grande, non è vero? dal modo in "
                           "cui stiamo continuando ...",
            "scan_module_not_found": "questo modulo di scansione [{0}] non trovato!",
            "error_exclude_all": "non è possibile escludere tutti i metodi di scansione",
            "exclude_module_error": "il modulo {0} che hai selezionato per escludere non trovato!",
            "method_inputs": "inserisci i metodi input, esempio: ftp_brute_users = test, admin e ftp_brute_passwds ="
                             " read_from_file: /tmp/pass.txt&ftp_brute_port=21",
            "error_reading_file": "impossibile leggere il file {0}",
            "error_username": "Impossibile specificare il nome utente, impossibile aprire il file: {0}",
            "found": "{0} trovato! ({1}: {2})",
            "error_password_file": "Impossibile specificare le password, impossibile aprire il file: {0}",
            "file_write_error": "il file \"{0}\" non è scrivibile!",
            "scan_method_select": "per favore scegli il tuo metodo di scansione!",
            "remove_temp": "rimuovendo i file temporanei!",
            "sorting_results": "risultati di ordinamento!",
            "done": "fatto!",
            "start_attack": "inizia ad attaccare {0}, {1} di {2}",
            "module_not_available": "questo modulo \"{0}\" non è disponibile",
            "error_platform": "sfortunatamente questa versione del software potrebbe essere eseguita solo su linux "
                              "/ osx / windows.",
            "python_version_error": "La tua versione di Python non è supportata!",
            "skip_duplicate_target": "saltare la destinazione duplicata (alcuni sottodomini / domini possono avere"
                                     " lo stesso IP e gli intervalli)",
            "unknown_target": "tipo di obiettivo sconosciuto [{0}]",
            "checking_range": "controllando l'intervallo {0} ...",
            "checking": "controllando {0} ...",
            "HOST": "OSPITE",
            "USERNAME": "NOME UTENTE",
            "PASSWORD": "PAROLA D'ORDINE",
            "PORT": "PORTA",
            "TYPE": "GENERE",
            "DESCRIPTION": "DESCRIZIONE",
            "verbose_level": "livello di modalità verbose (0-5) (predefinito 0)",
            "software_version": "mostra la versione del software",
            "check_updates": "ricerca aggiornamenti",
            "outgoing_proxy": "proxy delle connessioni in uscita (calze). esempio socks5: 127.0.0.1:9050, socks: "
                              "//127.0.0.1: 9050 socks5: //127.0.0.1: 9050 o socks4: socks4: //127.0.0.1: 9050, "
                              "autenticazione: socks: // nome utente: password @ 127.0.0.1, socks4: // nomeutente:"
                              " password@127.0.0.1, socks5: // nome utente: password@127.0.0.1",
            "valid_socks_address": "inserisci l'indirizzo e la porta dei calzini validi. esempio socks5: "
                                   "127.0.0.1:9050, socks: //127.0.0.1: 9050, socks5: //127.0.0.1: 9050 o "
                                   "socks4: socks4: //127.0.0.1: 9050, autenticazione: socks: // nome utente:"
                                   " password @ 127.0.0.1, socks4: // nomeutente: password@127.0.0.1, socks5: "
                                   "// nome utente: password@127.0.0.1",
            "connection_retries": "Riprova quando il timeout della connessione (default 3)",
            "ftp_connection_timeout": "connessione ftp a {0}: timeout {1}, saltando {2}: {3}",
            "login_successful": "LOGGED IN SUCCESSFULLY!",
            "login_list_error": "LOGGED IN SUCCESSIVAMENTE, PERMESSO NEGATO PER COMANDO DI LISTA!",
            "ftp_connection_failed": "connessione ftp a {0}: {1} non riuscita, saltando l'intero passaggio"
                                     " [processo {2} di {3}]! andando al prossimo passo",
            "input_target_error": "l'obiettivo di input per il modulo {0} deve essere DOMAIN, HTTP o SINGLE_IPv4,"
                                  " ignorando {1}",
            "user_pass_found": "utente: {0} pass: {1} host: {2} porta: {3} trovato!",
            "file_listing_error": "(NO PERMESSO PER I FILE DELLA LISTA)",
            "trying_message": "prova {0} di {1} nel processo {2} di {3} {4}: {5} ({6})",
            "smtp_connection_timeout": "connessione smtp a {0}: timeout {1}, saltando {2}: {3}",
            "smtp_connection_failed": "connessione smtp a {0}: {1} non riuscita, saltando l'intero passaggio "
                                      "[processo {2} di {3}]! andando al prossimo passo",
            "ssh_connection_timeout": "connessione ssh a {0}: {1} timeout, saltando {2}: {3}",
            "ssh_connection_failed": "connessione ssh a {0}: {1} non riuscita, saltando l'intero passaggio "
                                     "[processo {2} di {3}]! andando al prossimo passo",
            "port/type": "{0} / {1}",
            "port_found": "host: {0} port: {1} ({2}) trovato!",
            "target_submitted": "target {0} inviato!",
            "current_version": "stai eseguendo la versione di OWASP Nettacker {0} {1} {2} {6} con il nome in codice"
                               " {3} {4} {5}",
            "feature_unavailable": "questa funzione non è ancora disponibile! per favore lancia \"git clone "
                                   "https://github.com/zdresearch/OWASP-Nettacker.git o pip install -U OWASP-Nettacker "
                                   "per ottenere l'ultima versione.",
            "available_graph": "costruire un grafico di tutte le attività e le informazioni, è necessario utilizzare"
                               " l'output HTML. grafici disponibili: {0}",
            "graph_output": "per usare la funzione grafica il tuo nome file deve terminare con \".html\" o \".htm\"!",
            "build_graph": "grafico di costruzione ...",
            "finish_build_graph": "finisci di costruire il grafico!",
            "pentest_graphs": "Grafici di prova di penetrazione",
            "graph_message": "Questo grafico creato da OWASP Nettacker. Il grafico contiene tutte le attività dei"
                             " moduli, la mappa della rete e le informazioni sensibili, per favore non condividere"
                             " questo file con nessuno se non è affidabile.",
            "nettacker_report": "Rapporto OWASP Nettacker",
            "nettacker_version_details": "Dettagli software: versione OWASP Nettacker {0} [{1}] in {2}",
            "no_open_ports": "nessuna porta aperta trovata!",
            "no_user_passwords": "nessun utente / password trovata!",
            "loaded_modules": "{0} moduli caricati ...",
            "graph_module_404": "questo modulo grafico non trovato: {0}",
            "graph_module_unavailable": "questo modulo grafico \"{0}\" non è disponibile",
            "ping_before_scan": "ping prima di eseguire la scansione dell'host",
            "skipping_target": "saltare l'intero target {0} e il metodo di scansione {1} a causa di --ping-before-scan"
                               " è vero e non ha risposto!",
            "not_last_version": "non stai usando l'ultima versione di OWASP Nettacker, per favore aggiorna.",
            "cannot_update": "non è possibile verificare l'aggiornamento, si prega di"
                             " controllare la connessione internet.",
            "last_version": "Stai usando l'ultima versione di OWASP Nettacker ...",
            "directoy_listing": "elenco di directory trovato in {0}",
            "insert_port_message": "per favore inserisci la porta attraverso l'opzione -g"
                                   " o --methods-args invece di url",
            "http_connection_timeout": "timeout della connessione http {0}!",
            "wizard_mode": "avviare la modalità guidata",
            "directory_file_404": "nessuna directory o file trovato per {0} nella porta {1}",
            "open_error": "impossibile aprire {0}",
            "dir_scan_get": "Il valore dir_scan_http_method deve essere GET o HEAD, impostare il "
                            "valore predefinito su GET.",
            "list_methods": "elenca tutti i metodi args",
            "module_args_error": "impossibile ottenere {0} argomenti del modulo",
            "trying_process": "prova {0} di {1} nel processo {2} di {3} su {4} ({5})",
            "domain_found": "dominio trovato: {0}",
            "TIME": "TEMPO",
            "CATEGORY": "CATEGORIA",
            "module_pattern_404": "non riesco a trovare nessun modulo con il pattern {0}!",
            "enter_default": "inserisci {0} | Predefinito [{1}]>",
            "enter_choices_default": "inserisci {0} | scelte [{1}] | Predefinito [{2}]>",
            "all_targets": "gli obiettivi",
            "all_thread_numbers": "il numero del filo",
            "out_file": "il nome file di output",
            "all_scan_methods": "i metodi di scansione",
            "all_scan_methods_exclude": "i metodi di scansione da escludere",
            "all_usernames": "i nomi utente",
            "all_passwords": "le password",
            "timeout_seconds": "i secondi di timeout",
            "all_ports": "i numeri di porta",
            "all_verbose_level": "il livello dettagliato",
            "all_socks_proxy": "il proxy dei calzini",
            "retries_number": "il numero di tentativi",
            "graph": "un grafico",
            "subdomain_found": "sottodominio trovato: {0}",
            "select_profile": "seleziona il profilo {0}",
            "profile_404": "il profilo \"{0}\" non trovato!",
            "waiting": "aspettando {0}",
            "vulnerable": "vulnerabile a {0}",
            "target_vulnerable": "target {0}: {1} è vulnerabile a {2}!",
            "no_vulnerability_found": "nessuna vulnerabilità trovata! ({0})",
            "Method": "Metodo",
            "API": "API",
            "API_options": "Opzioni API",
            "start_API": "avvia il servizio API",
            "API_host": "Indirizzo host API",
            "API_port": "Numero di porta API",
            "API_debug": "Modalità di debug API",
            "API_access_key": "Chiave di accesso API",
            "white_list_API": "solo consentire agli host della lista bianca di connettersi all'API",
            "define_whie_list": "definire gli host della lista bianca, separati con, (esempi: 127.0.0.1,"
                                " 192.168.0.1/24, 10.0.0.1-10.0.0.255)",
            "gen_API_access_log": "generare un log di accesso API",
            "API_access_log_file": "Nome file registro accessi API",
            "API_port_int": "La porta API deve essere un numero intero!",
            "unknown_ip_input": "tipo di input sconosciuto, i tipi accettati sono SINGLE_IPv4, RANGE_IPv4, CIDR_IPv4",
            "API_key": "* Chiave API: {0}",
            "ports_int": "le porte devono essere numeri interi! (ad esempio 80 || 80,1080 || "
                         "80,1080-1300,9000,12000-15000)",
            "through_API": "Attraverso l'API Nettacker di OWASP",
            "API_invalid": "chiave API non valida",
            "unauthorized_IP": "il tuo IP non è autorizzato",
            "not_found": "Non trovato!",
            "no_subdomain_found": "sottodominio_scan: nessun sottodominio fondato!",
            "viewdns_domain_404": "viewdns_reverse_ip_lookup_scan: nessun dominio trovato!",
            "browser_session_valid": "la tua sessione del browser è valida",
            "browser_session_killed": "la sessione del browser è stata interrotta",
            "updating_database": "aggiornamento del database ...",
            "database_connect_fail": "impossibile connettersi al database!",
            "inserting_report_db": "inserimento del report nel database",
            "inserting_logs_db": "inserimento dei registri nel database",
            "removing_logs_db": "rimozione dei vecchi registri da db",
            "len_subdomain_found": "{0} trovato sottodominio!",
            "len_domain_found": "{0} domini trovati!",
            "phpmyadmin_dir_404": "nessuna directory phpmyadmin trovata!",
            "DOS_send": "invio di pacchetti DoS a {0}",
            "host_up": "{0} è attivo! Il tempo impiegato per eseguire il ping è {1}",
            "host_down": "Impossibile eseguire il ping {0}!",
            "root_required": "questo deve essere eseguito come root",
            "admin_scan_get": "Il valore admin_scan_http_method deve essere GET o HEAD, impostare il "
                              "valore predefinito su GET.",
            "telnet_connection_timeout": "connessione telnet a {0}: timeout {1}, saltando {2}: {3}",
            "telnet_connection_failed": "Connessione telnet a {0}: {1} non riuscita, saltando l'intero"
                                        " passaggio [processo {2} di {3}]! andando al prossimo passo",
            "http_auth_success": "autenticazione di base http successo: host: {2}: {3},"
                                 " utente: {0}, pass: {1} trovato!",
            "http_auth_failed": "autenticazione di base http non riuscita a {0}: {3} utilizzando {1}: {2}",
            "http_form_auth_success": "autenticazione modulo http: successo: host: {2}: {3}, utente: {0},"
                                      " pass: {1} trovato!",
            "http_form_auth_failed": "autenticazione del modulo http non riuscita a {0}: {3} utilizzando {1}: {2}",
            "http_ntlm_success": "autenticazione http ntlm riuscita - host: {2}: {3}, utente: {0}, pass: {1} trovato!",
            "http_ntlm_failed": "Autenticazione http ntlm non riuscita a {0}: {3} utilizzando {1}: {2}",
            "no_response": "non può ottenere risposta dall'obiettivo",
            "category_framework": "categoria: {0}, framework: {1} trovato!",
            "nothing_found": "nulla trovato su {0} in {1}!",
            "no_auth": "Nessuna autenticazione trovata su {0}: {1}"
        }
