import datetime


def now(format="%Y-%m-%d %H:%M:%S"):
    """
    get now date and time
    Args:
        format: the date and time model, default is "%Y-%m-%d %H:%M:%S"

    Returns:
        the date and time of now
    """
    return datetime.datetime.now().strftime(format)
