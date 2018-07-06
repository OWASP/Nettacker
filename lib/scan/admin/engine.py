#!/usr/bin/env python
# -*- coding: utf-8 -*-

import socket
import socks
import time
import json
import threading
import string
import requests
import random
import os
from core.alert import *
from core.targets import target_type
from core.targets import target_to_host
from core.load_modules import load_file_path
from lib.socks_resolver.engine import getaddrinfo
from core._time import now
from core.log import __log_into_file
from core._die import __die_failure


def extra_requirements_dict():
    return {
        "admin_scan_http_method": ["GET"],
        "admin_scan_random_agent": ["True"],
        "admin_scan_list": ["~adm", "~admin", "~administrator", "~amanda", "~apache", "~bin", "~ftp", "~guest", "~http",
                            "~httpd", "~log", "~logs", "~lp", "~mail", "~nobody", "~operator", "~root", "~sys", "~sysadm",
                            "~sysadmin", "~test", "~tmp", "~user", "~webmaster", "~www", "wp-admin", "wp-login.php",
                            "administrator", "~backup", "backup.sql", "database.sql", "backup.zip", "backup.tar.gz",
                            "backup", "backup-db", "mysql.sql", "phpmyadmin", "admin", "administrator", "server-status",
                            "server-info", "info.php", "php.php", "info.php", "phpinfo.php", "test.php", ".git",
                            ".htaccess", ".htaccess.old", ".htaccess.save", ".htaccess.txt", ".php-ini", "php-ini",
                            "FCKeditor", "FCK", "editor", "Desktop.ini", "INSTALL", "install", "install.php", "update",
                            "upgrade", "upgrade.php", "update.php", "LICENSE", "LICENSE.txt", "Server.php", "WS_FTP.LOG",
                            "WS_FTP.ini", "WS_FTP.log", "Web.config", "Webalizer", "webalizer", "config.php",
                            "config.php.new", "config.php~", "controlpanel", "cpanel", "favicon.ico", "old", "php-error",
                            "php.ini~", "php.ini", "php.log", "robots.txt", "security", "webdav", "1" '/acceso.asp', '/acceso.php', '/access/', '/access.php', '/account/', '/account.asp', '/account.html', '/account.php', '/acct_login/', '/_adm_/', '/_adm/', '/adm/', '/adm2/', '/adm/admloginuser.asp', '/adm/admloginuser.php', '/adm.asp', '/adm_auth.asp', '/adm_auth.php', '/adm.html', '/_admin_/', '/_admin/', '/admin/', '/Admin/', '/ADMIN/', '/admin1/', '/admin1.asp', '/admin1.html', '/admin1.php', '/admin2/', '/admin2.asp', '/admin2.html', '/admin2/index/', '/admin2/index.asp', '/admin2/index.php', '/admin2/login.asp', '/admin2/login.php', '/admin2.php', '/admin3/', '/admin4/', '/admin4_account/', '/admin4_colon/', '/admin5/', '/admin/account.asp', '/admin/account.html', '/admin/account.php', '/admin/add_banner.php/', '/admin/', 'addblog.php', '/admin/add_gallery_image.php', '/admin/add.php', '/admin/add', 'room.php', '/admin/add', 'slider.php', '/admin/', 'add_testimonials.php', '/admin/admin/', '/admin/adminarea.php', '/admin/admin.asp', '/admin/AdminDashboard.php', '/admin/admin', 'home.php', '/admin/AdminHome.php', '/admin/admin.html', '/admin/admin_index.php', '/admin/admin_login.asp', '/admin/admin', 'login.asp' '/admin/adminLogin.asp', '/admin/admin_login.html' '/admin/admin', 'login.html', '/admin/adminLogin.html', '/admin/admin_login.php', '/admin/admin', 'login.php', '/admin/', 'adminLogin.php', '/admin/admin_management.php', '/admin/admin.php', '/admin/admin_users.php', '/admin/adminview.php', '/admin/adm.php', '/admin_area/', '/adminarea/', '/admin_area/admin.asp', '/adminarea/admin.asp', '/admin_area/admin.html', '/adminarea/admin.html', '/admin_area/', 'admin.php', '/adminarea/admin.php', '/admin_area/index.asp', '/adminarea/index.asp', '/admin_area/index.html', '/adminarea/index.html', '/admin_area/index.php', '/adminarea/index.php', '/admin_area/login.asp', '/adminarea/login.asp', '/admin_area/login.html', '/adminarea/login.html', '/admin_area/login.php', '/adminarea/login.php', '/admin.asp', '/admin/banner.php', '/admin/banners_report.php', '/admin/category.php', '/admin/', 'change_gallery.php', '/admin/checklogin.php', '/admin/configration.php', '/admincontrol.asp', '/admincontrol.html', '/admincontrol/login.asp', '/admincontrol/login.html', '/admincontrol/login.php', '/admin/control_pages/admin_home.php', '/admin/controlpanel.asp', '/admin/controlpanel.html', '/admin/controlpanel.php', '/admincontrol.php', '/admincontrol.php/', '/admin/cpanel.php', '/admin/cp.asp', '/admin/CPhome.php', '/admin/cp.html', '/admincp/index.asp', '/admincp/index.html', '/admincp/login.asp', '/admin/cp.php', '/admin/dashboard/index.php', '/admin/dashboard.php', '/admin/dashbord.php', '/admin/dash.php', '/admin/default.php', '/adm/index.asp', '/adm/index.html', '/adm/index.php', '/admin/enter.php', '/admin/event.php', '/admin/form.php', '/admin/gallery.php', '/admin/headline.php', '/admin/home.asp', '/admin/home.html', '/admin_home.php', '/admin/home.php', '/admin.html', '/admin/index.asp', '/admin/index', 'digital.php', '/admin/', 'index.html', '/admin/index.php', '/admin/index_ref.php', '/admin/initialadmin.php', '/administer/', '/administr8/', '/administr8.asp', '/administr8.html', '/administr8.php', '/administracion.php', '/administrador/', '/administratie/', '/administration/', '/administration.html', '/administration.php', '/administrator', '/_administrator_/', '/_administrator/', '/administrator/', '/administrator/account.asp', '/administrator/account.html', '/administrator/account.php', '/administratoraccounts/', '/administrator.asp', '/administrator.html', '/administrator/index.asp', '/administrator/index.html', '/administrator/', 'index.php', '/administratorlogin/', '/administrator/login.asp', '/administratorlogin.asp', '/administrator/login.html', '/administrator/login.php', '/administratorlogin.php', '/administratorlogin.php', '/administrator.php', '/administrators/', '/administrivia/', '/admin/', 'leads.php', '/admin/list_gallery.php', '/admin/login', '/adminLogin/', '/admin_login.asp', '/admin', 'login.asp', '/admin/login.asp', '/adminLogin.asp', '/admin/login', 'home.php', '/admin_login.html', '/admin', 'login.html', '/admin/login.html', '/adminLogin.html', '/ADMIN/login.html' '/admin_login.php', '/admin_login.php', '/admin', 'login.php ', '/admin', 'login.php/', '/admin/login.php', '/adminLogin.php', '/ADMIN/login.php', '/admin/login_success.php', '/admin/loginsuccess.php', '/admin/log.php', '/admin_main.html', '/admin/main_page.php', '/admin/main.php/', '/admin/', 'ManageAdmin.php', '/admin/manageImages.php', '/admin/manage_team.php', '/admin/member_home.php', '/admin/moderator.php', '/admin/my_account.php', '/admin/myaccount.php', '/admin/overview.php', '/admin/page_management.php', '/admin/pages/home_admin.php', '/adminpanel/' '/adminpanel.asp', '/adminpanel.html', '/adminpanel.php', '/admin.php', '/Admin/private/', '/adminpro/', '/admin/product.php', '/admin/products.php', '/admins/', '/admins.asp', '/admin/save.php', '/admins.html', '/admin/slider.php', '/admin/specializations.php', '/admins.php', '/admin_tool/', '/AdminTools/', '/admin/uhome.html', '/admin/upload.php', '/admin/userpage.php', '/admin/viewblog.php', '/admin/viewmembers.php', '/admin/voucher.php', '/AdminWeb/', '/admin/welcomepage.php', '/admin/welcome.php', '/admloginuser.asp', '/admloginuser.php', '/admon/', '/ADMON/', '/adm.php', '/affiliate.asp', '/affiliate.php', '/auth/', '/auth/login/', '/authorize.php', '/autologin/', '/banneradmin/', '/base/admin/', '/bb', 'admin/', '/bbadmin/', '/bb', 'admin/admin.asp', '/bb', 'admin/admin.html /bb', 'admin/admin.php /bb', 'admin/index.asp /bb', 'admin/index.html /bb', 'admin/index.php /bb', 'admin/login.asp /bb', 'admin/login.html /bb', 'admin/login.php', '/bigadmin/', '/blogindex/', '/cadmins/', '/ccms/', '/ccms/', 'index.php', '/ccms/login.php', '/ccp14admin/', '/cms/', '/cms/admin/', '/cmsadmin/', '/cms/_admin/logon.php', '/cms/login/', '/configuration/', '/configure/', '/controlpanel/', '/controlpanel.asp', '/controlpanel.html', '/controlpanel.php', '/cpanel/', '/cPanel/', '/cpanel_file/', '/cp.asp', '/cp.html', '/cp.php', '/customer_login/', '/database_administration/', '/Database_Administration/', '/db/admin.php', '/directadmin/', '/dir', 'login/', '/editor/', '/edit.php', '/evmsadmin/', '/ezsqliteadmin/', '/fileadmin/', '/fileadmin.asp', '/fileadmin.html', '/fileadmin.php', '/formslogin/', '/forum/admin', '/globes_admin/', '/home.asp', '/home.html', '/home.php', '/hpwebjetadmin/', '/include/admin.php', '/includes/login.php', '/Indy_admin/', '/instadmin/', '/interactive/admin.php', '/irc', 'macadmin/', '/links/login.php', '/LiveUser_Admin/', '/login/', '/login1/', '/login.asp', '/login_db/', '/loginflat/', '/login.html', '/login/login.php', '/login.php', '/login', 'redirect/', '/logins/', '/login', 'us/', '/logon/', '/logo_sysadmin/', '/Lotus_Domino_Admin/', '/macadmin/', '/mag/admin/', '/maintenance/', '/manage_admin.php', '/manager/', '/manager/ispmgr/', '/manuallogin/', '/memberadmin/', '/memberadmin.asp', '/memberadmin.php', '/members/', '/memlogin/', '/meta_login/', '/modelsearch/', 'admin.asp', '/modelsearch/admin.html', '/modelsearch/admin.php', '/modelsearch/index.asp', '/modelsearch/index.html', '/modelsearch/', 'index.php', '/modelsearch/login.asp', '/modelsearch/login.html', '/modelsearch/login.php', '/moderator/', '/moderator/admin.asp', '/moderator/admin.html', '/moderator/admin.php', '/moderator.asp', '/moderator.html', '/moderator/login.asp', '/moderator/login.html', '/moderator/login.php', '/moderator.php', '/moderator.php/', '/myadmin/', '/navSiteAdmin/', '/newsadmin/', '/nsw/admin/login.php', '/openvpnadmin/', '/pages/admin/admin', 'login.asp', '/pages/admin/admin', 'login.html', '/pages/admin/admin', 'login.php /panel/', '/panel', 'administracion/ /panel', 'administracion/admin.asp', '/panel', 'administracion/admin.html', '/panel', 'administracion/admin.php /panel', 'administracion/index.asp /panel', 'administracion/index.html /panel', 'administracion/index.php /panel', 'administracion/login.asp /panel', 'administracion/login.html /panel', 'administracion/login.php /panelc/', '/paneldecontrol/', '/panel.php', '/pgadmin/', '/phpldapadmin/', '/phpmyadmin/', '/phppgadmin/', '/phpSQLiteAdmin/', '/platz_login/', '/pma/', '/power_user/', '/project', 'admins/', '/pureadmin/', '/radmind/', '/radmind', '1/ /rcjakar/admin/login.php', '/rcLogin/', ' /server/', '/Server/', '/ServerAdministrator/', '/server_admin_small/', '/Server.asp', '/Server.html', '/Server.php', '/showlogin/', '/simpleLogin/', '/site/admin/', '/siteadmin/', '/siteadmin/index.asp', '/siteadmin/index.php', '/siteadmin/login.asp', '/siteadmin/login.html', '/site_admin/login.php', '/siteadmin/login.php', '/smblogin/', '/sql', 'admin/', '/sshadmin/', '/ss_vms_admin_sm/', '/staradmin/', '/sub', 'login/ /Super', 'Admin/ /support_login/ /sys', 'admin/ /sysadmin/ /SysAdmin/ /SysAdmin2/ /sysadmin.asp', '/sysadmin.html /sysadmin.php', '/sysadmins/', '/system_administration/', '/system', 'administration/ /typo3/ /ur', 'admin/ /ur', 'admin.asp /ur', 'admin.html /ur', 'admin.php /useradmin/ /user.asp ', '/user.html', '/UserLogin/ /user.php', '/usuario/ /usuarios/ /usuarios// /usuarios/login.php', '/utility_login/', '/vadmind/', '/vmailadmin/', '/webadmin/ /WebAdmin/ /webadmin/admin.asp', '/webadmin/admin.html', '/webadmin/admin.php', '/webadmin.asp', '/webadmin.html', '/webadmin/index.asp', '/webadmin/index.html', '/webadmin/index.php', '/webadmin/login.asp', '/webadmin/login.html', '/webadmin/login.php', '/webadmin.php', '/webmaster/ /websvn/ /wizmysqladmin/ /wp', 'admin/ /wp', 'login/ /wplogin/ /wp', 'login.php', '/xlogin/', '/yonetici.asp', '/yonetici.html', '/yonetici.php ', '/yonetim.asp', '/yonetim.html', '/yonetim.php', ]
    }


def check(target, user_agent, timeout_sec, log_in_file, language, time_sleep, thread_tmp_filename, retries,
          http_method, socks_proxy, scan_id, scan_cmd):
    status_codes = [200, 401, 403]
    directory_listing_msgs = ["<title>Index of /", "<a href=\"\\?C=N;O=D\">Name</a>", "Directory Listing for",
                              "Parent Directory</a>", "Last modified</a>", "<TITLE>Folder Listing.",
                              "- Browsing directory "]
    time.sleep(time_sleep)
    try:
        if socks_proxy is not None:
            socks_version = socks.SOCKS5 if socks_proxy.startswith(
                'socks5://') else socks.SOCKS4
            socks_proxy = socks_proxy.rsplit('://')[1]
            if '@' in socks_proxy:
                socks_username = socks_proxy.rsplit(':')[0]
                socks_password = socks_proxy.rsplit(':')[1].rsplit('@')[0]
                socks.set_default_proxy(socks_version, str(socks_proxy.rsplit('@')[1].rsplit(':')[0]),
                                        int(socks_proxy.rsplit(':')[-1]), username=socks_username,
                                        password=socks_password)
                socket.socket = socks.socksocket
                socket.getaddrinfo = getaddrinfo
            else:
                socks.set_default_proxy(socks_version, str(
                    socks_proxy.rsplit(':')[0]), int(socks_proxy.rsplit(':')[1]))
                socket.socket = socks.socksocket
                socket.getaddrinfo = getaddrinfo
        n = 0
        while 1:
            try:
                if http_method == "GET":
                    r = requests.get(
                        target, timeout=timeout_sec, headers=user_agent)
                elif http_method == "HEAD":
                    r = requests.head(
                        target, timeout=timeout_sec, headers=user_agent)
                content = r.content
                break
            except:
                n += 1
                if n is retries:
                    warn(messages(language, "http_connection_timeout").format(target))
                    return 1
        if version() is 3:
            content = content.decode('utf8')
        if r.status_code in status_codes:
            log_in_file(thread_tmp_filename, 'w', '0', language)
            info(messages(language, "found").format(
                target, r.status_code, r.reason), log_in_file, "a",
                {'HOST': target_to_host(target), 'USERNAME': '', 'PASSWORD': '',
                               'PORT': "", 'TYPE': 'admin_scan',
                               'DESCRIPTION': messages(language, "found").format(target, r.status_code, r.reason),
                               'TIME': now(), 'CATEGORY': "scan", 'SCAN_ID': scan_id, 'SCAN_CMD': scan_cmd}, language, thread_tmp_filename)
            if r.status_code is 200:
                for dlmsg in directory_listing_msgs:
                    if dlmsg in content:
                        info(messages(language, "directory_listing").format(target), log_in_file, "a"
                                           ,{'HOST': target_to_host(target), 'USERNAME': '', 'PASSWORD': '',
                                           'PORT': "", 'TYPE': 'admin_scan',
                                           'DESCRIPTION': messages(language, "directoy_listing").format(target), 'TIME': now(),
                                           'CATEGORY': "scan", 'SCAN_ID': scan_id, 'SCAN_CMD': scan_cmd}, language, thread_tmp_filename)
                        __log_into_file(log_in_file, 'a', data, language)
                        break
        return True
    except:
        return False


def test(target, retries, timeout_sec, user_agent, http_method, socks_proxy, verbose_level, trying, total_req, total,
         num, language):
    if verbose_level > 3:
        info(messages(language, "trying_message").format(trying, total_req, num, total, target_to_host(target), "default_port",
                                                         'admin_scan'))
    if socks_proxy is not None:
        socks_version = socks.SOCKS5 if socks_proxy.startswith(
            'socks5://') else socks.SOCKS4
        socks_proxy = socks_proxy.rsplit('://')[1]
        if '@' in socks_proxy:
            socks_username = socks_proxy.rsplit(':')[0]
            socks_password = socks_proxy.rsplit(':')[1].rsplit('@')[0]
            socks.set_default_proxy(socks_version, str(socks_proxy.rsplit('@')[1].rsplit(':')[0]),
                                    int(socks_proxy.rsplit(':')[-1]), username=socks_username,
                                    password=socks_password)
            socket.socket = socks.socksocket
            socket.getaddrinfo = getaddrinfo
        else:
            socks.set_default_proxy(socks_version, str(
                socks_proxy.rsplit(':')[0]), int(socks_proxy.rsplit(':')[1]))
            socket.socket = socks.socksocket
            socket.getaddrinfo = getaddrinfo
    n = 0
    while 1:
        try:
            if http_method == "GET":
                r = requests.get(target, timeout=timeout_sec,
                                 headers=user_agent)
            elif http_method == "HEAD":
                r = requests.head(target, timeout=timeout_sec,
                                  headers=user_agent)
            return 0
        except:
            n += 1
            if n is retries:
                return 1


def start(target, users, passwds, ports, timeout_sec, thread_number, num, total, log_in_file, time_sleep, language,
          verbose_level, socks_proxy, retries, methods_args, scan_id, scan_cmd):  # Main function
    if target_type(target) != 'SINGLE_IPv4' or target_type(target) != 'DOMAIN' or target_type(
            target) != 'HTTP' or target_type(target) != 'SINGLE_IPv6':
        # rand useragent
        user_agent_list = [
            "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.0.5) Gecko/20060719 Firefox/1.5.0.5",
            "Googlebot/2.1 ( http://www.googlebot.com/bot.html)",
            "Mozilla/5.0 (X11; U; Linux x86_64; en-US) AppleWebKit/534.13 (KHTML, like Gecko) Ubuntu/10.04"
            " Chromium/9.0.595.0 Chrome/9.0.595.0 Safari/534.13",
            "Mozilla/5.0 (compatible; MSIE 7.0; Windows NT 5.2; WOW64; .NET CLR 2.0.50727)",
            "Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51",
            "Mozilla/5.0 (compatible; 008/0.83; http://www.80legs.com/webcrawler.html) Gecko/2008032620",
            "Debian APT-HTTP/1.3 (0.8.10.3)",
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
            "Googlebot/2.1 (+http://www.googlebot.com/bot.html)",
            "Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)",
            "YahooSeeker/1.2 (compatible; Mozilla 4.0; MSIE 5.5; yahooseeker at yahoo-inc dot com ; "
            "http://help.yahoo.com/help/us/shop/merchant/)",
            "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
            "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
            "msnbot/1.1 (+http://search.msn.com/msnbot.htm)"
        ]
        http_methods = ["GET", "HEAD"]
        user_agent = {'User-agent': random.choice(user_agent_list)}

        # requirements check
        new_extra_requirements = extra_requirements_dict()
        if methods_args is not None:
            for extra_requirement in extra_requirements_dict():
                if extra_requirement in methods_args:
                    new_extra_requirements[
                        extra_requirement] = methods_args[extra_requirement]
        extra_requirements = new_extra_requirements
        if extra_requirements["admin_scan_http_method"][0] not in http_methods:
            warn(messages(language, "admin_scan_get"))
            extra_requirements["admin_scan_http_method"] = ["GET"]
        random_agent_flag = True
        if extra_requirements["admin_scan_random_agent"][0] == "False":
            random_agent_flag = False
        threads = []
        total_req = len(extra_requirements["admin_scan_list"])
        thread_tmp_filename = '{}/tmp/thread_tmp_'.format(load_file_path()) + ''.join(
            random.choice(string.ascii_letters + string.digits) for _ in range(20))
        __log_into_file(thread_tmp_filename, 'w', '1', language)
        trying = 0
        if target_type(target) != "HTTP":
            target = 'http://' + target
        if test(str(target), retries, timeout_sec, user_agent, extra_requirements["admin_scan_http_method"][0],
                socks_proxy, verbose_level, trying, total_req, total, num, language) is 0:
            keyboard_interrupt_flag = False
            for idir in extra_requirements["admin_scan_list"]:
                if random_agent_flag:
                    user_agent = {'User-agent': random.choice(user_agent_list)}
                t = threading.Thread(target=check,
                                     args=(
                                         target + '/' + idir, user_agent, timeout_sec, log_in_file, language,
                                         time_sleep, thread_tmp_filename, retries,
                                         extra_requirements[
                                             "admin_scan_http_method"][0],
                                         socks_proxy, scan_id, scan_cmd))
                threads.append(t)
                t.start()
                trying += 1
                if verbose_level > 3:
                    info(messages(language, "trying_message").format(trying, total_req, num, total, target_to_host(target),
                                                                     "default_port", 'admin_scan'))
                while 1:
                    try:
                        if threading.activeCount() >= thread_number:
                            time.sleep(0.01)
                        else:
                            break
                    except KeyboardInterrupt:
                        keyboard_interrupt_flag = True
                        break
                if keyboard_interrupt_flag:
                    break

        else:
            warn(messages(language, "open_error").format(target))

        # wait for threads
        kill_switch = 0
        kill_time = int(
            timeout_sec / 0.1) if int(timeout_sec / 0.1) is not 0 else 1
        while 1:
            time.sleep(0.1)
            kill_switch += 1
            try:
                if threading.activeCount() is 1 or kill_switch is kill_time:
                    break
            except KeyboardInterrupt:
                break
        thread_write = int(open(thread_tmp_filename).read().rsplit()[0])
        if thread_write is 1:
            if verbose_level is not 0:
                info(messages(language, "directory_file_404").format(
                    target, "default_port"), log_in_file, "a",
                    {'HOST': target_to_host(target), 'USERNAME': '', 'PASSWORD': '', 'PORT': '', 'TYPE': 'admin_scan',
                     'DESCRIPTION': messages(language, "direcroty_file_404").format(target, "default_port"), 'TIME': now(), 'CATEGORY': "scan", 'SCAN_ID': scan_id,
                     'SCAN_CMD': scan_cmd}, language, thread_tmp_filename)
                __log_into_file(log_in_file, 'a', data, language)
        os.remove(thread_tmp_filename)
    else:
        warn(messages(language, "input_target_error").format('admin_scan', target))
