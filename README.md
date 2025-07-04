# RCON Admin Web App

## English

This project is a small Flask application for administrating a Counter-Strike 1.6 server via RCON. You can save server profiles, send commands and see who is online.

### Setup
1. Install Python 3 and [Flask](https://flask.palletsprojects.com/).
2. Run `pip install flask` to install the dependency.
3. Start the app with `python3 app.py`.
4. Open `http://localhost:5000` in your browser.

### Usage
- Fill in the server host, port and RCON password.
- Save the profile so you can quickly select it later.
- Use the buttons to send common commands like **status** or **changelevel**.
- The player list and console log can be refreshed automatically.

All server profiles are stored in `servers.json` in the same folder.

---

## Deutsch

Dieses Projekt ist eine kleine Flask-Anwendung, um einen Counter-Strike 1.6 Server über RCON zu verwalten. Man kann Server-Profile speichern, Befehle senden und sehen, wer online ist.

### Einrichtung
1. Python 3 und [Flask](https://flask.palletsprojects.com/) installieren.
2. Mit `pip install flask` die Abhängigkeit installieren.
3. Die App mit `python3 app.py` starten.
4. `http://localhost:5000` im Browser öffnen.

### Benutzung
- Serveradresse, Port und RCON-Passwort eintragen.
- Das Profil speichern, damit es später schnell auswählbar ist.
- Über die Buttons lassen sich Befehle wie **status** oder **changelevel** senden.
- Spieler-Liste und Konsolenlog können automatisch aktualisiert werden.

Alle Server-Profile werden in der Datei `servers.json` im gleichen Verzeichnis abgelegt.
