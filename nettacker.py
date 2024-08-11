"""OWASP Nettacker application entry point."""

from nettacker.core.app import Nettacker

if __name__ == "__main__":
    app = Nettacker()
    app.run()
