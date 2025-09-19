import sys
from io import StringIO

import yaml

from nettacker.config import Config
from nettacker.core.utils.common import find_args_value
from nettacker.core.utils.path_utils import get_filename_stem, build_message_path


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
    return yaml.load(StringIO(open(filename, "r").read()), Loader=yaml.FullLoader)


def get_languages():
    """
    Get available languages

    Returns:
        an array of languages
    """
    languages_list = []

    for language in Config.path.locale_dir.glob("*.yaml"):
        languages_list.append(get_filename_stem(str(language)))
    return list(set(languages_list))


class load_message:
    def __init__(self):
        self.language = application_language()
        self.messages = load_yaml(
            build_message_path(Config.path.locale_dir, self.language)
        )
        if self.language != "en":
            self.messages_en = load_yaml(
                build_message_path(Config.path.locale_dir, "en")
            )
            for message_id in self.messages_en:
                if message_id not in self.messages:
                    self.messages[message_id] = self.messages_en[message_id]


message_cache = load_message().messages


def messages(msg_id):
    """
    load a message from message library with specified language

    Args:
        msg_id: message id

    Returns:
        the message content in the selected language if
        message found otherwise return message in English
    """
    return message_cache[str(msg_id)]
