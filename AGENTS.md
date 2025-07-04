# AGENTS.md

## 1. Projektüberblick
Diese Flask-App ermöglicht die Verwaltung von RCON-Befehlen für Game-Server und bietet ein Dashboard mit Player-Statistiken. 

## 2. Projektstruktur
- `app.py`: Hauptlogik und Routen  
- `templates/`: Jinja2-Templates für das Frontend  
- `static/`: CSS- und JavaScript-Assets  
- `servers.json`: Konfigurationsdatei für Server-Profile  
- `tests/`: Unit- und Integrationstests  

## README-Aktualisierung  
- Nach jedem neuen Feature:  
  1. Öffne `README.md`.  
  2. Füge unter „## Neue Features“ eine Liste der kürzlich hinzugekommenen Endpoints ein.  
  3. Committe die geänderte `README.md`.  


## 3. Einrichtung & Tests
```bash
pip install -r requirements.txt   # Abhängigkeiten installieren  
pytest --maxfail=1 --disable-warnings -q   # Tests ausführen  


