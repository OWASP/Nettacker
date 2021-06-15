@echo off
python3 -c "import nettacker; nettacker.__check_external_modules();nettacker.load()" %*