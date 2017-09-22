#!/usr/bin/env python
# -*- coding: utf-8 -*-


def all_messages():
    return \
        {
            "0": {
                "en": "Nettacker engine started ...\n\n",
                "fa": "انجین Nettacker شروع به کار کرد...\n\n",
                "ru": "Начался запуск Nettacker ... \n\n"
            },
            "1": {  # not using replace optparse with argparse
                "en": "python nettacker.py [options]",
                "fa": "python nettacker.py [گزینه ها]",
                "ru": "python nettacker.py [опции]"
            },
            "2": {
                "en": "Show Nettacker Help Menu",
                "fa": "نشان دادن منوی راهنمای Nettacker",
                "ru": "Показать меню справки Nettacker"
            },
            "3": {
                "en": "Please read license and agreements https://github.com/Nettacker/Nettacker",
                "fa": "لطفا مجوز و موافقت نامه را مطالعه فرمایید https://github.com/Nettacker/Nettacker",
                "ru": "Пожалуйста, прочтите лицензию и соглашение https://github.com/Nettacker/Nettacker"
            },
            "4": {
                "en": "Engine",
                "fa": "انجین",
                "ru": "двигатель"
            },
            "5": {
                "en": "Engine input options",
                "fa": "گزینه های ورودی انجین",
                "ru": "Параметры ввода двигателя"
            },
            "6": {
                "en": "select a language {0}",
                "fa": "لطفا یک زبان انتخاب کنید {0}",
                "ru": "выберите язык {0}"
            },
            "7": {
                "en": "scan all IPs in the range",
                "fa": "اسکن کل آی پی ها در رنج",
                "ru": "сканировать все IP-адреса в диапазоне"
            },
            "8": {
                "en": "find and scan subdomains",
                "fa": "یافتن و اسکن کردن ساب دامین ها",
                "ru": "находить и сканировать субдомены"
            },
            "9": {
                "en": "thread numbers for connections to a host",
                "fa": "تعداد ریسه ها برای ارتباطات با یک هاست",
                "ru": "номера потоков для соединений с хостом"
            },
            "10": {
                "en": "thread numbers for scan hosts",
                "fa": "تعداد ریسه ها برای اسکن هاست ها",
                "ru": "номера потоков для хостов сканирования"
            },
            "11": {
                "en": "save all logs in file (results.txt, results.html)",
                "fa": "ذخیره کردن کل لاگ ها در فایل (result.txt، result.html)",
                "ru": "сохранить все журналы в файле (results.txt, results.html)"
            },
            "12": {
                "en": "Target",
                "fa": "هدف",
                "ru": "цель"
            },
            "13": {
                "en": "Target input options",
                "fa": "گزینه های ورودی هدف",
                "ru": "Целевые параметры ввода"
            },
            "14": {
                "en": "target(s) list, separate with \",\"",
                "fa": "لیست هدف (ها)، با \",\" جدا کنید",
                "ru": "список целей, разделенных с \",\""
            },
            "15": {
                "en": "read target(s) from file",
                "fa": "خواندن هدف (ها) از فایل",
                "ru": "читать цель (цели) из файла"
            },
            "16": {
                "en": "Scan method options",
                "fa": "گزینه های متود های اسکن",
                "ru": "Параметры метода сканирования"
            },
            "17": {
                "en": "choose scan method {0}",
                "fa": "متود اسکن را انتخاب کنید {0}",
                "ru": "выбрать метод сканирования {0}"
            },
            "18": {
                "en": "choose scan method to exclude {0}",
                "fa": "انتخاب متود اسکن استثنا {0}",
                "ru": "выберите исключительный метод сканирования {0}"
            },
            "19": {
                "en": "username(s) list, separate with \",\"",
                "fa": "لیست نام کاربری (ها)، با \",\" جدا شود",
                "ru": "список пользователей, разделенных \",\""
            },
            "20": {
                "en": "read username(s) from file",
                "fa": "خواندن نام کاربری (ها) از لیست",
                "ru": "читать имя пользователя из файла"
            },
            "21": {
                "en": "password(s) list, separate with \",\"",
                "fa": "لیست کلمه عبور (ها)، با \",\" جدا شود",
                "ru": "список паролей, разделенных с \",\""
            },
            "22": {
                "en": "read password(s) from file",
                "fa": "خواندن کلمه عبور (ها) از فایل",
                "ru": "читать пароль (ы) из файла"
            },
            "23": {
                "en": "port(s) list, separate with \",\"",
                "fa": "لیست درگاه (ها)، با \",\" جدا شود",
                "ru": "список портов, разделенных с \", \""
            },
            "24": {
                "en": "read passwords(s) from file",
                "fa": "خواندن کلمه عبور (ها) از فایل",
                "ru": "читать пароли (ы) из файла"
            },
            "25": {
                "en": "time to sleep between each request",
                "fa": "زمان مکث بین هر درخواست",
                "ru": "время спать между каждым запросом"
            },
            "26": {
                "en": "Cannot specify the target(s)",
                "fa": "عدم توانایی در مشخص کردن هدف (ها)",
                "ru": "Невозможно указать цель (ы)"
            },
            "27": {
                "en": "Cannot specify the target(s), unable to open file: {0}",
                "fa": "عدم توانایی در مشخص کردن هدف (ها)، عدم توانایی در بازکردن فایل: {0}",
                "ru": "Невозможно указать цель (ы), неспособность открыть файл: {0}"
            },
            "28": {
                "en": "it\'s better to use thread number lower than 100, BTW we are continuing...",
                "fa": "بهتر است که از تعداد ریسه کمتر از 100 استفاده کنید، به هر حال ما ادامه می دهیم...",
                "ru": "лучше использовать число потоков ниже 100, кстати, мы продолжаем ..."
            },
            "29": {
                "en": "set timeout to {0} seconds, it is too big, isn\"t it ? by the way we are continuing...",
                "fa": "زمان وقفه {0} ثانیه قرار داده شد، زیادی بزرگ است، نیست؟ به هر حال ما ادامه می دهیم...",
                "ru": "установите тайм-аут на {0} секунд, он слишком велик, не так ли? кстати, мы продолжаем."
            },
            "30": {
                "en": "this scan module [{0}] not found!",  # Duplicate
                "fa": "این ماژول اسکن [{0}] پیدا نشد!",
                "ru": "этот модуль сканирования [{0}] не найден!"
            },
            "31": {
                "en": "this scan module [{0}] not found!",  # Duplicate
                "fa": "این ماژول اسکن [{0}] پیدا نشد!",
                "ru": "этот модуль сканирования [{0}] не найден!"
            },
            "32": {
                "en": "you cannot exclude all scan methods",  # Duplicate
                "fa": "شما نمی توانید همه متود های اسکن را استثنا کنید",
                "ru": "вы не можете исключить все методы сканирования"
            },
            "33": {
                "en": "you cannot exclude all scan methods",  # Duplicate
                "fa": "شما نمی توانید همه متود های اسکن را استثنا کنید",
                "ru": "вы не можете исключить все методы сканирования"
            },
            "34": {
                "en": "the {0} module you selected to exclude not found!",
                "fa": "ماژول {0} که شما جهت استثنا کردن انتخاب کردید پیدا نشد!",
                "ru": "модуль {0}, который вы выбрали для исключения, не найден!"
            },
            "35": {
                "en": "please enter one port at least!",
                "fa": "لطفا حداقل یک درگاه وارد نمایید",
                "ru": "введите хотя бы один порт!"
            },
            "36": {
                "en": "this module requires username(s) (list) to brute force!",
                "fa": "این ماژول نیازمند به (لیست) نام کاربری (ها) جهت بروتفورس را دارد!",
                "ru": "этот модуль требует, чтобы имя пользователя (список) перебралось в грубую силу!"
            },
            "37": {
                "en": "Cannot specify the username(s), unable to open file: {0}",
                "fa": "عدم توانایی مشخص کردن نام کاربری (ها)، عدم توانایی در بازکردن فایل: {0}",
                "ru": "Невозможно указать имя пользователя (ов), неспособное открыть файл: {0}"
            },
            "38": {
                "en": "this module requires password(s) (list) to brute force!",
                "fa": "این ماژول نیازمند به (لیست) کلمه عبور (ها) جهت بروتفورس را دارد!",
                "ru": "этот модуль требует пароля (списка) для перебора!"
            },
            "39": {
                "en": "Cannot specify the password(s), unable to open file: {0}",
                "fa": "عدم توانایی مشخص کردن کلمه عبور (ها)، عدم توانایی در بازکردن فایل: {0}",
                "ru": "Не удается указать пароль (ы), не удается открыть файл: {0}"
            },
            "40": {
                "en": "file \"{0}\" is not writable!",
                "fa": "فایل \"{0}\" قابل نوشتن نیست",
                "ru": "Файл \"{0}\" не доступен для записи!"
            },
            "41": {
                "en": "please choose your scan method!",
                "fa": "متود اسکن خود را انتخاب کنید!",
                "ru": "выберите способ сканирования!"
            },
            "42": {
                "en": "removing temp files!",
                "fa": "در حال پاک کردن فایل های موقتی!",
                "ru": "удаление временных файлов!"
            },
            "43": {
                "en": "sorting results!",
                "fa": "در حال مرتب سازی نتایج!",
                "ru": "sorting results!"
            },
            "44": {
                "en": "done!",
                "fa": "انجام شد!",
                "ru": "сделанный!"
            },
            "45": {
                "en": "start attacking {0}, {1} of {2}",
                "fa": "شروع حمله به {0}، {1} از {2}",
                "ru": "начать атаковать {0}, {1} из {2}"
            },
            "46": {
                "en": "this module \"{0}\" is not available",
                "fa": "این ماژول \"{0}\" در دسترس نیست",
                "ru": "этот модуль \"{0}\" недоступен"
            },
            "47": {
                "en": "unfortunately this version of the software just could be run on linux/osx/windows.",
                "fa": "متاسفانه این ورژن از نرم افزار فقط می تواند بر روی لینوکس/او اس ایکس/ویندوز اجرا شود.",
                "ru": "к сожалению, эту версию программного обеспечения можно было запустить только на "
                      "linux/osx/windows."
            },
            "48": {
                "en": "Your Python version is not supported!",
                "fa": "از ورژن پایتون شما پشتیبانی نشده!",
                "ru": "Ваша версия Python не поддерживается!"
            },
            "49": {
                "en": "skip duplicate target (some subdomains/domains may have same IP and Ranges)",
                "fa": "چشم پوشی از هدف تکراری (بعضی از ساب دامین ها/دامین ها آی پی و یا رنج یکسان دارند)",
                "ru": "пропустить дублируемую цель (некоторые поддомены / домены могут иметь одинаковые IP-адреса и диапазоны)",
            },
            "50": {
                "en": "unknown type of target [{0}]",
                "fa": "نوع هدف ناشتناخته است [{0}]",
                "ru": "неизвестный тип цели [{0}]"
            },
            "51": {
                "en": "checking {0} range ...",
                "fa": "در حال بررسی رنج {0} ...",
                "ru": "проверка диапазона {0} ..."
            },
            "52": {
                "en": "checking {0} ...",
                "fa": "در حال بررسی {0} ...",
                "ru": "проверка {0} ..."
            },
            "53": {
                "en": "HOST",
                "fa": "هاست",
                "ru": "хозяин"
            },
            "54": {
                "en": "USERNAME",
                "fa": "نام کاربری",
                "ru": "имя пользователя"
            },
            "55": {
                "en": "PASSWORD",
                "fa": "کلمه عبور",
                "ru": "пароль"
            },
            "56": {
                "en": "PORT",
                "fa": "درگاه",
                "ru": "порт"
            },
            "57": {
                "en": "TYPE",
                "fa": "نوع",
                "ru": "тип"
            },
            "58": {
                "en": "DESCRIPTION",
                "fa": "توضیحات",
                "ru": "описание"
            },
            "59": {
                "en": "verbose mode level (0-5) (default 0)",
                "fa": "سطح حالت پرگویی (0-5) (پیشفرض 0)",
                "ru": "уровень подробного режима (0-5) (по умолчанию 0)"
            },
            "60": {
                "en": "show software version",
                "fa": "نمایش ورژن نرم افزار",
                "ru": "показать версию программного обеспечения"
            },
            "61": {
                "en": "check for update",
                "fa": "چک کردن جهت آپدیت",
                "ru": "Проверить обновления"
            },
            "62": {
                "en": "proxy(s) list, separate with \",\" (out going connections)",
                "fa": "لیست پروکسی (ها)، جدا سازی به وسیله \",\" (ارتباطات خروجی)",
                "ru": "прокси (ы), разделяемые с \",\" (исходящие соединения)"
            },
            "63": {
                "en": "read proxies from a file (outgoing connections)",
                "fa": "خواندن پراکسی ها از فایل (ارتباطات خروجی)",
                "ru": "читать прокси из файла (исходящие соединения)"
            },
            "64": {
                "en": "Retries when the connection timeout (default 3)",
                "fa": "سعی مجدد وقتی که ارتباط قطع شد (پیشفرض 3)",
                "ru": "Повторяет попытку, когда таймаут соединения (по умолчанию 3)"
            },
            "65": {
                "en": "ftp connection to {0}:{1} timeout, skipping {2}:{3}",
                "fa": "ارتباط ftp به {0}:{0} قطع شد، چشم پوشی از {2}:{3}",
                "ru": "ftp для {0}: {1} таймаут, пропуская {2}: {3}"
            },
            "66": {
                "en": "LOGGED IN SUCCESSFULLY!",
                "fa": "با موفقیت وارد شده!",
                "ru": "успешно зарегистрирован!"
            },
            "67": {
                "en": "LOGGED IN SUCCESSFULLY, PERMISSION DENIED FOR LIST COMMAND!",
                "fa": "با موفقیت کامل شده، اجازه برای دستور LIST داده نشد.",
                "ru": "успешно зарегистрирован, разрешение отказано для команды списка!"
            },
            "68": {
                "en": "ftp connection to {0}:{1} failed, skipping whole step [process {2} of {3}]! going to next step",
                "fa": "ارتباط ftp به {0}:{1} نا موفق بود، از کل مرحله [روند {2} از {3}] چشم پوشی شد! در حال رفتن به"
                      " مرحله بعد",
                "ru": "ftp-подключение к {0}: {1} не удалось, пропустив весь шаг [процесс {2} из {3}]! "
                      "переход к следующему шагу"
            },
            "69": {
                "en": "input target for {0} module must be DOMAIN, HTTP or SINGLE_IPv4, skipping {1}",
                "fa": "ورودی هدف برای ماژول {0} باید DOMAIN، HTTP یا SINGLE_IPv4 باشد، از {1} چشم پوشی شد",
                "ru": "входная цель для модуля {0} должна быть DOMAIN, HTTP или SINGLE_IPv4, пропуская {1}"
            },
            "70": {
                "en": "user: {0} pass:{1} host:{2} port:{3} found!",
                "fa": "نام کاربری: {0} کلمه عبور: {1} هاست: {2} درگاه: {3} پیدا شد!",
                "ru": "имя пользователя: {0} пароль: {1} хозяин: {2} порт: {3} найдено!"
            },
            "71": {
                "en": "(NO PERMISSION FOR LIST FILES)",
                "fa": "(عدم دسترسی جهت لیست کردن فایل ها)",
                "ru": "(без разрешения для файлов списка)"
            },
            "72": {
                "en": "trying {0} of {1} in process {2} of {3} {4}:{5}",
                "fa": "تلاش برای {0} از {1} در روند {2} از {3} {4}:{5}",
                "ru": "{0} из {1} в процессе {2} из {3} {4}:{5}"
            },
            "73": {
                "en": "smtp connection to {0}:{1} timeout, skipping {2}:{3}",
                "fa": "ارتباط smtp به {0}:{1} قطع شد، جشم پوشی از {2}:{3}",
                "ru": "smtp-соединение с {0}: {1} таймаут, пропуская {2}:{3}"
            },
            "74": {
                "en": "smtp connection to {0}:{1} failed, skipping whole step [process {2} of {3}]! going to next step",
                "fa": "ارتباط smtp به {0}:{1} ناموفق بود، از کل مرحله [روند {2} از {3}]! چشم پوشی شد! در حال رفتن به"
                      " مرحله بعد",
                "ru": "smtp-соединение с {0}: {1} не удалось, пропустив весь шаг [процесс {2} из {3}]! "
                      "переход к следующему шагу"
            },
            "75": {
                "en": "input target for {0} module must be HTTP, skipping {1}",
                "fa": "ورودی هدف برای ماژول {0} باید از نوع HTTP باشد، از {1} چشم پوشی",
                "ru": "входная цель для модуля {0} должна быть HTTP, пропуская {1}"
            },
            "76": {
                "en": "ssh connection to {0}:{1} timeout, skipping {2}:{3}",
                "fa": "ارتباط ssh به {0}:{1} قطع شد، چشم پوشی از {2}:{3}",
                "ru": "ssh для {0}:{1} таймаут, пропуская {2}:{3}"
            },
            "77": {
                "en": "ssh connection to {0}:{1} failed, skipping whole step [process {2} of {3}]! going to next step",
                # Duplicate
                "fa": "ارتباط ssh به {0}:{1} ناموفق بود، از کل مرحله [روند {2} از {3}]! چشم پوشی شد! در حال رفتن به"
                      " مرحله بعد",
                "ru": "ssh-соединение с {0}: {1} не удалось, пропустив весь шаг [процесс {2} из {3}]! "
                      "переход к следующему шагу"
            },
            "78": {
                "en": "ssh connection to %s:%s failed, skipping whole step [process %s of %s]! going to next step",
                # Duplicate
                "fa": "ارتباط ssh به %s:%s ناموفق بود، از کل مرحله [روند %s از %s]! چشم پوشی شد! در حال رفتن به"
                      " مرحله بعد",
                "ru": "ssh-соединение с {0}: {1} не удалось, пропустив весь шаг [процесс {2} из {3}]! "
                      "переход к следующему шагу"
            },
            "79": {
                "en": "OPEN PORT",
                "fa": "درگاه باز",
                "ru": "открытый порт"
            },
            "80": {
                "en": "host: {0} port: {1} found!",
                "fa": "هاست: {0} درگاه: {1} پیدا شد!",
                "ru": "хозяин: {0} порт: {1} найдено!"
            },
            "81": {
                "en": "target {0} submitted!",
                "fa": "هدف {0} ارسال شد!",
                "ru": "цель {0} представлена!"
            },
            "82": {
                "en": "cannot open proxies list file: {0}",
                "fa": "عدم توانایی در باز کردن فایل لیست پروکسی ها: {0}"
            },
            "83": {
                "en": "cannot find proxies list file: {0}",
                "fa": "عدم توانایی در پیدا کردن فایل لیست پروکسی ها: {0}",
                "ru": "не удается найти файл списка прокси: {0}"
            },
            "84": {
                "en": "you are running OWASP Nettacker version {0}{1}{2}{6} with code name {3}{4}{5}",
                "fa": "شما در حال اجرای OWASP Nettacker ورژن {0}{1}{2}{6} با اسم کد {3}{4}{5} می باشید",
                "ru": "вы используете версию OWASP Nettacker {0} {1} {2} {6} с кодовым названием {3} {4} {5}"
            },
            "85": {
                "en": "this feature is not available yet! please run \"git clone "
                      "https://github.com/viraintel/OWASP-Nettacker.git\" or \"pip "
                      "install -U OWASP-Nettacker\" to get the last version.",
                "fa": "این ویژگی هنوز فعال نشده است! لطفا \"git clone "
                      "https://github.com/viraintel/OWASP-Nettacker.git\" یا \"pip "
                      "install -U OWASP-Nettacker\" را جهت گرفتن اخرین ورژن اجرا کنید.",
                "ru": "эта функция пока недоступна! запустите \"git clone " \
                      "https://github.com/viraintel/OWASP-Nettacker.git\" или "
                      "\"pip install -U OWASP-Nettacker\" чтобы получить последнюю версию."
            },
            "86": {
                "en": "build a graph of all activities and information, you must use html output. "
                      "available graphs: {0}",
                "fa": "ساخت گراف از همه فعالیت ها و اطلاعات، شما باید از خروجی HTML استفاده کنید. "
                      "گراف های در دسترس: {0}",
                "ru": "постройте график всех действий и информации, вы должны использовать вывод html. "
                      "доступные графики: {0}"
            },
            "87": {
                "en": "to use graph feature your output filename must end with \".html\" or \".htm\"!",
                "fa": "جهت استفاده از ویژگی گراف نام فایل خروجی شما باید با\".html\" یا \".htm\" تمام شود! ",
                "ru": "для использования функции графика ваше имя выходного файла должно заканчиваться "
                      "символом \".html\" или \".htm\"!"
            },
            "88": {
                "en": "building graph ...",
                "fa": "در حال ساخت گراف ...",
                "ru": "строительный график ..."
            },
            "89": {
                "en": "finish building graph!",
                "fa": "پایان ساخت گراف!",
                "ru": "закончите строить график!"
            },
            "90": {
                "en": "Penetration Testing Graphs",
                "fa": "گراف تست نفوذ",
                "ru": "Графики тестирования проникновения"
            },
            "91": {
                "en": "This graph created by OWASP Nettacker. Graph contains all modules "
                      "activities, network map and sensitive information, Please don't share "
                      "this file with anyone if it's not reliable.",
                "fa": "این گراف توسط OWASP Nettacker ایجاد شده است. گراف شامل فعالیت همه "
                      "ماژول ها، نقشه شبکه و اطلاعات حساس می باشد، لطفا با کسی که قابل"
                      " اعتماد نیست به اشتراک تگذارید.",
                "ru": "Этот график создан OWASP Nettacker. График содержит все действия "
                      "модулей, карту сети и конфиденциальную информацию. Пожалуйста, "
                      "не сообщайте этот файл никому, если он не является надежным"
            },
            "92": {
                "en": "OWASP Nettacker Report",
                "fa": "گزارش OWASP Nettacker",
                "ru": "Отчет OwASP Nettacker"
            },
            "93": {
                "en": "Software Details: OWASP Nettacker version {0} [{1}] in {2}",
                "fa": "جزییات نرم افزار: OWASP Nettacker ورژن {0} [{1}] در {2}",
                "ru": "Сведения о программном обеспечении: версия OWASP Nettacker {0} [{1}] в {2}"
            },
            "94": {
                "en": "no open ports found!",
                "fa": "هیچ درگاه بازی پیدا نشد!",
                "ru": "открытых портов не найдено!"
            },
            "95": {
                "en": "no user/password found!",
                "fa": "هیچ نام کاربری/پسوردی پیدا نشد!",
                "ru": "нет имени пользователя/пароля!"
            },
            "96": {
                "en": "{0} modules loaded ...",
                "fa": "{0} ماژول بارگزاری شد ...",
                "ru": "Загружено модулей {0} ..."
            },
            "97": {
                "en": "this graph module not found: {0}",
                "fa": "این ماژول گراف پیدا نشد: {0}",
                "ru": "этот модуль графа не найден: {0}"
            },
            "98": {
                "en": "this graph module \"{0}\" is not available",
                "fa": "این ماژول گراف \"{0}\" در دسترس نیست",
                "ru": "этот модуль графа \"{0}\" недоступен"
            },
            "99": {
                "en": "ping before scan the host",
                "fa": "پینگ کردن هست قبل از اسکن",
                "ru": "ping перед сканированием хоста"
            },
            "100": {
                "en": "skipping whole target {0} and scanning methods {1} because of --ping-before-scan"
                      " is true and it didn\'t response!",
                "fa": "از هدف {0} و متود های اسکن {1} به دلیل true بودن --ping-before-scan "
                      "و عدم دریافت پاسخ صرف نظر شد! ",
                "ru": "пропуская мишень {0} и методы сканирования {1} из-за --ping-before-scan истинны,"
                      " и он не ответил!"
            }
        }
