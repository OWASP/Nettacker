from typing import List


def parse_port_expression(expression: str) -> List[int]:
    """
    Parse a port expression string like:
    '80'
    '80,443'
    '20-22'
    '20-22,80,443'

    Returns a sorted list of unique ports.
    Raises ValueError for invalid inputs.
    """
    if not expression:
        return []

    ports = set()

    for part in expression.split(","):
        part = part.strip()

        if "-" in part:
            try:
                start, end = map(int, part.split("-"))
            except ValueError:
                raise ValueError(f"Invalid port range: {part}")

            if start > end:
                raise ValueError(f"Invalid port range: {part}")

            if start < 1 or end > 65535:
                raise ValueError(f"Port out of range: {part}")

            for port in range(start, end + 1):
                ports.add(port)

        else:
            try:
                port = int(part)
            except ValueError:
                raise ValueError(f"Invalid port value: {part}")

            if port < 1 or port > 65535:
                raise ValueError(f"Port out of range: {port}")

            ports.add(port)

    return sorted(ports)
