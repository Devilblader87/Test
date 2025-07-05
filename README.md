# RCON Admin Web App

## English

This project is a small Flask application for administrating a Counter-Strike 1.6 server via RCON. You can save server profiles, send commands and see who is online.

### Setup
1. Install Python 3 and [Flask](https://flask.palletsprojects.com/).
2. Run `pip install flask` to install the dependency.
3. (Optional) set `SECRET_KEY` environment variable for session protection.
4. Start the app with `python3 app.py`.
5. Open `http://localhost:5000` in your browser. CSRF protection is disabled so
   the app works even if cookies are turned off.
6. This uses the Flask development server. For production deployments, run the
   app with a WSGI server like **gunicorn**.

### Usage
- Fill in the server host, port and RCON password.
- Save the profile so you can quickly select it later.
- Use the buttons to send common commands like **status** or **changelevel**.
- The player list and console log can be refreshed automatically.

All server profiles are stored in `servers.json` in the same folder.

### Additional Features
- War3FT configuration editor available at `/war3ft/config`
- Hot-reload the War3FT plugin via `/war3ft/reload`
- Manage AMXX plugins and edit plugin configs under `/amxx/...`

---

## Deutsch

Dieses Projekt ist eine kleine Flask-Anwendung, um einen Counter-Strike 1.6 Server über RCON zu verwalten. Man kann Server-Profile speichern, Befehle senden und sehen, wer online ist.

### Einrichtung
1. Python 3 und [Flask](https://flask.palletsprojects.com/) installieren.
2. Mit `pip install flask` die Abhängigkeit installieren.
3. Optional `SECRET_KEY` Umgebungsvariable setzen.
4. Die App mit `python3 app.py` starten.
5. `http://localhost:5000` im Browser öffnen und Cookies aktivieren.

### Benutzung
- Serveradresse, Port und RCON-Passwort eintragen.
- Das Profil speichern, damit es später schnell auswählbar ist.
- Über die Buttons lassen sich Befehle wie **status** oder **changelevel** senden.
- Spieler-Liste und Konsolenlog können automatisch aktualisiert werden.

Alle Server-Profile werden in der Datei `servers.json` im gleichen Verzeichnis abgelegt.

### Weitere Funktionen
- War3FT-Konfiguration unter `/war3ft/config` bearbeiten
- Plugin-Hotreload über `/war3ft/reload`
- AMXX-Plugins und Konfigs unter `/amxx/...` verwalten

## Neue Features
- Serverprofile-Auswahl und Zurück-Link auf `/war3ft/config` und `/amxx/plugins`
- Login unter `/login` und Benutzerverwaltung unter `/users`
- Rollenliste auf `/roles`
- Dashboard mit Widgets auf `/dashboard`
- Widget-Konfiguration via `/widgets`
- Datei-Editor auf `/files/edit/<path>`
- Aufgabenplanung auf `/tasks`
- Statistikseite unter `/stats`

- Registrierung unter `/register`


