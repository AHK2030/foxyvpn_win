@echo off
call .venv\Scripts\activate.bat
pip install pyinstaller
pyinstaller --noconfirm --clean --onefile --windowed --name FoxyVPN foxyvpn.py
pause
