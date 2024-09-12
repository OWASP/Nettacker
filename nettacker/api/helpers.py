import re

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

def sanitize_path(path):
    """
    Sanitize the file path to preven unathorized access
    Args:
        path: filepath(user input)

    Returns:
        sanitized_path
    """
    allowed_pattern = r'^[a-zA-Z0-9_-]+(\.[a-zA-Z0-9_-]+)?$'
    
    components = re.split(r'[/\\]', path)
    
    sanitized_components = []
    for component in components:
        if re.match(allowed_pattern, component):
            sanitized_components.append(component)

    sanitized_path = '_'.join(sanitized_components)
    
    return sanitized_path