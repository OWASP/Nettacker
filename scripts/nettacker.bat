@echo off
python -c "import nettacker; nettacker.__check_external_modules();nettacker.load()" %*