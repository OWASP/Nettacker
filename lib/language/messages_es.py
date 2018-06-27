#!/usr/bin/env python
# -*- coding: utf-8 -*-


def all_messages():
    """
    keep all messages in es

    Returns:
        all messages in JSON
    """
    return \
        {
            "scan_started": "El motor Nettacker comenzó ...",
            "options": "python nettacker.py [opciones]",
            "help_menu": "Mostrar el menú de ayuda de Nettacker",
            "license": "Lea la licencia y los acuerdos https://github.com/zdresearch/OWASP-Nettacker",
            "engine": "Motor",
            "engine_input": "Opciones de entrada del motor",
            "select_language": "seleccione un idioma {0}",
            "range": "escanear todos los IP en el rango",
            "subdomains": "buscar y escanear subdominios",
            "thread_number_connections": "números de hilo para las conexiones a un host",
            "thread_number_hosts": "números de hilo para los hosts de escaneo",
            "save_logs": "guardar todos los registros en el archivo (results.txt, results.html, results.json)",
            "target": "Objetivo",
            "target_input": "Opciones de entrada de destino",
            "target_list": "lista (s) de destino (s), separe con \",\"",
            "read_target": "leer objetivo (s) del archivo",
            "scan_method_options": "Opciones de método de escaneo",
            "choose_scan_method": "elija el método de escaneo {0}",
            "exclude_scan_method": "elija el método de escaneo para excluir {0}",
            "username_list": "nombre de usuario (s) list, separe con \",\"",
            "username_from_file": "leer nombre (s) de usuario del archivo",
            "password_seperator": "lista de contraseña (s), separe con \",\"",
            "read_passwords": "leer contraseña (s) del archivo",
            "port_seperator": "lista (s) de puerto (s), separarse con \",\"",
            "time_to_sleep": "tiempo para dormir entre cada solicitud",
            "error_target": "No se puede especificar el objetivo (s)",
            "error_target_file": "No se puede especificar el (los) objetivo (s), no se puede abrir el archivo: {0}",
            "thread_number_warning": "es mejor usar un número de hilo inferior a 100, por cierto, continuamos ...",
            "set_timeout": "establece el tiempo de espera en {0} segundos, es demasiado grande, ¿no?"
                           " por cierto, continuamos ...",
            "scan_module_not_found": "este módulo de exploración [{0}] no se encuentra!",
            "error_exclude_all": "no puedes excluir todos los métodos de escaneo",
            "exclude_module_error": "el módulo {0} que seleccionó para excluir no encontrado!",
            "method_inputs": "ingrese las entradas de métodos, ejemplo: ftp_brute_users = test, admin & "
                             "ftp_brute_passwds = read_from_file: /tmp/pass.txt&ftp_brute_port=21",
            "error_reading_file": "no se puede leer el archivo {0}",
            "error_username": "No se puede especificar el nombre de usuario, no se puede abrir el archivo: {0}",
            "found": "{0} encontrado! ({1}: {2})",
            "error_password_file": "No se puede especificar la (s) contraseña (s), no se puede abrir el archivo: {0}",
            "file_write_error": "¡El archivo \"{0}\" no se puede escribir!",
            "scan_method_select": "¡por favor elija su método de escaneo!",
            "remove_temp": "eliminando archivos temporales!",
            "sorting_results": "¡clasificando resultados!",
            "done": "¡hecho!",
            "start_attack": "comience a atacar {0}, {1} de {2}",
            "module_not_available": "este módulo \"{0}\" no está disponible",
            "error_platform": "desafortunadamente, esta versión del software solo podría ejecutarse en "
                              "linux / osx / windows.",
            "python_version_error": "¡Tu versión de Python no es compatible!",
            "skip_duplicate_target": "omitir el objetivo duplicado (algunos subdominios / dominios pueden "
                                     "tener el mismo IP y rangos)",
            "unknown_target": "tipo desconocido de destino [{0}]",
            "checking_range": "revisando el rango {0} ...",
            "checking": "revisando {0} ...",
            "HOST": "ANFITRIÓN",
            "USERNAME": "USERNAME",
            "PASSWORD": "CONTRASEÑA",
            "PORT": "PUERTO",
            "TYPE": "TIPO",
            "DESCRIPTION": "DESCRIPCIÓN",
            "verbose_level": "nivel de modo detallado (0-5) (valor predeterminado 0)",
            "software_version": "mostrar la versión del software",
            "check_updates": "Buscar actualizaciones",
            "outgoing_proxy": "proxy de conexiones salientes (calcetines). calcetines de ejemplo5: 127.0.0.1"
                              ":9050, calcetines: //127.0.0.1: calcetines 90505: //127.0.0.1: 9050 o calcetines4:"
                              " calcetines4: //127.0.0.1: 9050, autenticación: calcetines: // nombre de usuario:"
                              " contraseña @ 127.0.0.1, calcetines4: // nombre de usuario: contraseña@127.0.0.1,"
                              " socks5: // nombre de usuario: contraseña@127.0.0.1",
            "valid_socks_address": "por favor ingrese la dirección y el puerto válidos de los calcetines. "
                                   "calcetines de ejemplo5: 127.0.0.1:9050, calcetines: //127.0.0.1: 9050, "
                                   "calcetines5: //127.0.0.1: 9050 o calcetines4: calcetines4: //127.0.0.1:"
                                   " 9050, autenticación: calcetines: // nombre de usuario: contraseña @ "
                                   "127.0.0.1, calcetines4: // nombre de usuario: contraseña@127.0.0.1, "
                                   "socks5: // nombre de usuario: contraseña@127.0.0.1",
            "connection_retries": "Reintentos cuando el tiempo de espera de conexión (valor predeterminado 3)",
            "ftp_connection_timeout": "conexión ftp a {0}: {1} tiempo de espera, omitiendo {2}: {3}",
            "login_successful": "¡INICIADO SUCESIVAMENTE!",
            "login_list_error": "¡INICIADO SUCESIVAMENTE, PERMISO DENEGADO POR COMANDO DE LISTA!",
            "ftp_connection_failed": "La conexión ftp a {0}: {1} falló, omitiendo todo el paso [proceso {2} "
                                     "de {3}]! yendo al siguiente paso",
            "input_target_error": "el destino de entrada para el módulo {0} debe ser DOMINIO, HTTP o "
                                  "SINGLE_IPv4, omitiendo {1}",
            "user_pass_found": "usuario: {0} pase: {1} host: {2} puerto: {3} encontrado!",
            "file_listing_error": "(SIN PERMISO PARA ARCHIVOS DE LISTA)",
            "trying_message": "intentando {0} de {1} en proceso {2} de {3} {4}: {5} ({6})",
            "smtp_connection_timeout": "conexión smtp a {0}: {1} tiempo de espera, omitiendo {2}: {3}",
            "smtp_connection_failed": "smtp conexión a {0}: {1} error, omitiendo todo el paso [proceso "
                                      "{2} de {3}]! yendo al siguiente paso",
            "ssh_connection_timeout": "conexión ssh a {0}: {1} tiempo de espera, omitiendo {2}: {3}",
            "ssh_connection_failed": "la conexión ssh a {0}: {1} falló, omitiendo todo el paso [proceso {2}"
                                     " de {3}]! yendo al siguiente paso",
            "port/type": "{0} / {1}",
            "port_found": "host: {0} puerto: {1} ({2}) encontrado!",
            "target_submitted": "objetivo {0} enviado!",
            "current_version": "está ejecutando la versión de OWASP Nettacker {0} {1} {2} {6} con el nombre de "
                               "código {3} {4} {5}",
            "feature_unavailable": "esta característica aún no está disponible por favor, ejecute \"git clone "
                                   "https://github.com/zdresearch/OWASP-Nettacker.git or pip install -U "
                                   "OWASP-Nettacker para obtener la última versión.",
            "available_graph": "crea un gráfico de todas las actividades y la información, debes usar la "
                               "salida HTML. gráficos disponibles: {0}",
            "graph_output": "para usar la función gráfica, su nombre de archivo de salida debe terminar con "
                            "\".html\" o \".htm\"!",
            "build_graph": "construyendo gráfico ...",
            "finish_build_graph": "terminar de construir el gráfico!",
            "pentest_graphs": "Gráficos de prueba de penetración",
            "graph_message": "Este gráfico creado por OWASP Nettacker. El gráfico contiene todas las actividades"
                             " de los módulos, el mapa de la red y la información confidencial. No comparta este "
                             "archivo con nadie si no es confiable.",
            "nettacker_report": "Informe Nettacker de OWASP",
            "nettacker_version_details": "Detalles del software: versión de OWASP Nettacker {0} [{1}] en {2}",
            "no_open_ports": "¡No se encontraron puertos abiertos!",
            "no_user_passwords": "¡no se encontró usuario / contraseña!",
            "loaded_modules": "{0} módulos cargados ...",
            "graph_module_404": "este módulo gráfico no se encuentra: {0}",
            "graph_module_unavailable": "este módulo de gráfico \"{0}\" no está disponible",
            "ping_before_scan": "ping antes de escanear el host",
            "skipping_target": "salteando el objetivo completo {0} y el método de escaneo {1} debido a que "
                               "--ping-before-scan es verdadero y no respondió!",
            "not_last_version": "no está utilizando la última versión de OWASP Nettacker, actualice.",
            "cannot_update": "no puede verificar la actualización, verifique su conexión a Internet.",
            "last_version": "Estás utilizando la última versión de OWASP Nettacker ...",
            "directoy_listing": "listado de directorio encontrado en {0}",
            "insert_port_message": "por favor inserte el puerto a través del conmutador -g o"
                                   " --methods-args en lugar de url",
            "http_connection_timeout": "http connection {0} timeout!",
            "wizard_mode": "iniciar el modo asistente",
            "directory_file_404": "no se encontró ningún directorio o archivo para {0} en el puerto {1}",
            "open_error": "no se puede abrir {0}",
            "dir_scan_get": "El valor dir_scan_http_method debe ser GET o HEAD, establecer de"
                            " manera predeterminada en GET.",
            "list_methods": "lista todos los métodos args",
            "module_args_error": "no puede obtener {0} argumentos del módulo",
            "trying_process": "intentando {0} de {1} en proceso {2} de {3} en {4} ({5})",
            "domain_found": "dominio encontrado: {0}",
            "TIME": "HORA",
            "CATEGORY": "CATEGORÍA",
            "module_pattern_404": "no puede encontrar ningún módulo con el patrón {0}!",
            "enter_default": "por favor ingrese {0} | Predeterminado [{1}]>",
            "enter_choices_default": "por favor ingrese {0} | opciones [{1}] | Predeterminado [{2}]>",
            "all_targets": "los objetivos",
            "all_thread_numbers": "el número de hilo",
            "out_file": "el nombre del archivo de salida",
            "all_scan_methods": "los métodos de escaneo",
            "all_scan_methods_exclude": "los métodos de escaneo para excluir",
            "all_usernames": "los nombres de usuario",
            "all_passwords": "las contraseñas",
            "timeout_seconds": "los segundos de tiempo de espera",
            "all_ports": "los números de los puertos",
            "all_verbose_level": "el nivel detallado",
            "all_socks_proxy": "los calcetines proxy",
            "retries_number": "el número de reintentos",
            "graph": "un gráfico",
            "subdomain_found": "subdominio encontrado: {0}",
            "select_profile": "seleccionar perfil {0}",
            "profile_404": "el perfil \"{0}\" no encontrado!",
            "waiting": "esperando {0}",
            "vulnerable": "vulnerable a {0}",
            "target_vulnerable": "target {0}: {1} es vulnerable a {2}!",
            "no_vulnerability_found": "¡no se encontró vulnerabilidad! ({0})",
            "Method": "Método",
            "API": "API",
            "API_options": "Opciones de API",
            "start_API": "iniciar el servicio API",
            "API_host": "Dirección de host API",
            "API_port": "Número de puerto API",
            "API_debug": "Modo de depuración API",
            "API_access_key": "Clave de acceso API",
            "white_list_API": "solo permita que los hosts de la lista blanca se conecten a la API",
            "define_whie_list": "definir los hosts de la lista blanca, separar con, (ejemplos: 127.0.0.1, "
                                "192.168.0.1/24, 10.0.0.1-10.0.0.255)",
            "gen_API_access_log": "generar registro de acceso API",
            "API_access_log_file": "Nombre de archivo de registro de acceso API",
            "API_port_int": "¡El puerto API debe ser un número entero!",
            "unknown_ip_input": "tipo de entrada desconocido, los tipos aceptados son SINGLE_IPv4, RANGE_IPv4,"
                                " CIDR_IPv4",
            "API_key": "* Clave de API: {0}",
            "ports_int": "los puertos deben ser enteros! (por ejemplo, 80 || 80,1080 "
                         "|| 80,1080-1300,9000,12000-15000)",
            "through_API": "A través de la API OWASP Nettacker",
            "API_invalid": "clave de API no válida",
            "unauthorized_IP": "su IP no autorizada",
            "not_found": "¡Extraviado!",
            "no_subdomain_found": "subdomain_scan: ¡no se ha creado ningún subdominio!",
            "viewdns_domain_404": "viewdns_reverse_ip_lookup_scan: ¡no se ha encontrado ningún dominio!",
            "browser_session_valid": "su sesión de navegador es válida",
            "browser_session_killed": "su sesión de navegador mató",
            "updating_database": "actualizando la base de datos ...",
            "database_connect_fail": "¡no se pudo conectar a la base de datos!",
            "inserting_report_db": "insertar informe en la base de datos",
            "inserting_logs_db": "insertar registros en la base de datos",
            "removing_logs_db": "eliminando los registros antiguos de db",
            "len_subdomain_found": "{0} subdominio (es) encontrados!",
            "len_domain_found": "{0} dominio (s) encontrados!",
            "phpmyadmin_dir_404": "no se encontró ningún phpmyadmin dir!",
            "DOS_send": "enviar paquetes DoS a {0}",
            "host_up": "{0} está listo! El tiempo necesario para hacer ping es {1}",
            "host_down": "No se puede hacer ping a {0}!",
            "root_required": "esto debe ejecutarse como root",
            "admin_scan_get": "El valor de admin_scan_http_method debe ser GET o HEAD, establecer"
                              " de manera predeterminada en GET.",
            "telnet_connection_timeout": "conexión telnet a {0}: {1} tiempo de espera, omitiendo {2}: {3}",
            "telnet_connection_failed": "La conexión telnet a {0}: {1} falló, omitiendo todo el paso "
                                        "[proceso {2} de {3}]! yendo al siguiente paso",
            "http_auth_success": "http autenticación básica éxito - host: {2}: {3}, usuario: {0}, pase: {1} encontrado!",
            "http_auth_failed": "La autenticación HTTP básica no pudo {0}: {3} usar {1}: {2}",
            "http_form_auth_success": "http form authentication success - host: {2}: {3}, usuario: "
                                      "{0}, pase: {1} encontrado!",
            "http_form_auth_failed": "La autenticación del formulario http no pudo {0}: {3} usar {1}: {2}",
            "http_ntlm_success": "Éxito de autenticación http ntlm - host: {2}: {3}, "
                                 "usuario: {0}, pase: {1} encontrado!",
            "http_ntlm_failed": "La autenticación http ntlm no pudo {0}: {3} usar {1}: {2}",
            "no_response": "no puede obtener respuesta del objetivo",
            "category_framework": "categoría: {0}, marcos: {1} encontrado!",
            "nothing_found": "nada encontrado en {0} en {1}!",
            "no_auth": "No se encontró autorización en {0}: {1}"
        }
