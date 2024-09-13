from nettacker.core.utils.common import now, generate_random_token
from nettacker.config import Config

def structure(status="", msg=""):
    """
    basic JSON message structure

    Args:
        status: status (ok, failed)
        msg: the message content

    Returns:
        a JSON message
    """
    return {"status": status, "msg": msg}


def generate_compare_filepath():
    return "/results_{date_time}_{random_chars}.json".format(
        date_time=now(format="%Y_%m_%d_%H_%M_%S"),
        random_chars=generate_random_token(10),
    )