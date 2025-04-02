import sys
try:
    import asyncssh
    import cryptography
    print(f"Python {sys.version} compatible!")
except ImportError as e:
    print(f"Error: {e}")