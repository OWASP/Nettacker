import sys
import os
from io import StringIO

import yaml

from nettacker.config import Config
from nettacker.core.utils.common import find_args_value


def application_language():
    if "-L" in sys.argv:
        language = find_args_value("-L") or "en"
    elif "--language" in sys.argv:
        language = find_args_value("--language") or "en"
    else:
        language = Config.settings.language
    if language not in get_languages():
        language = "en"
    return language


def load_yaml(filename):
    with open(filename, "r", encoding="utf-8") as f:
        return yaml.load(f, Loader=yaml.FullLoader)


def get_languages():
    languages_list = []
    for language in Config.path.locale_dir.glob("*.yaml"):
        languages_list.append(os.path.splitext(os.path.basename(str(language)))[0])
    return list(set(languages_list))

class load_message:
    def __init__(self):
        self.language = application_language()
        print(f"[DEBUG] Selected language: {self.language}")
        print(f"[DEBUG] Available languages: {get_languages()}")
        # Build path safely
        language_file = os.path.join(Config.path.locale_dir, f"{self.language}.yaml")
        self.messages = load_yaml(language_file)

        if self.language != "en":
         fallback_file = os.path.join(Config.path.locale_dir, "en.yaml")
         self.messages_en = load_yaml(fallback_file)

         for message_id in self.messages_en:
             if message_id not in self.messages:
                 self.messages[message_id] = self.messages_en[message_id]
        print(f"[DEBUG] Selected language: {self.language}")


try:
    message_cache = load_message().messages
except Exception as e:
    print(f"[!] Failed to load messages: {e}")
    message_cache = {}


def messages(msg_id):
    """
    Load a message from the message library with the selected language.

    Args:
        msg_id: message ID

    Returns:
        The message content in the selected language if found,
        otherwise returns the message ID itself as a fallback.
    """
    return message_cache.get(str(msg_id), str(msg_id))
