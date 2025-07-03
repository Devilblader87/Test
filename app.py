from flask import Flask, render_template, request, jsonify
import socket, os, json

"""Kleines Flask-Webinterface zum Versenden von RCON-Befehlen.

Die Anwendung speichert Serverprofile in einer JSON-Datei und erlaubt das
Senden von Befehlen an einen CS 1.6 Server.
"""

app = Flask(__name__)
SERVER_FILE = 'servers.json'

def load_servers():
    """Liest gespeicherte Serverprofile aus der JSON-Datei."""

    if os.path.exists(SERVER_FILE):
        with open(SERVER_FILE, encoding='utf-8') as f:
            return json.load(f)
    return {}

def save_servers(servers):
    """Speichert die gegebenen Serverprofile in die JSON-Datei."""

    with open(SERVER_FILE, 'w', encoding='utf-8') as f:
        json.dump(servers, f, indent=2)

def send_rcon(addr, port, password, command):
    """Sendet einen RCON-Befehl an den angegebenen Server."""

    # Debug-Ausgaben für die Konsole
    print(f"\nSending RCON Command to {addr}:{port}")
    print(f"Command: {command}")
    print(f"Password: {'*' * len(password)}")

    # UDP-Socket vorbereiten
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1.0)

    # Payload nach HL1-RCON-Spezifikation erstellen
    payload = b'\xff\xff\xff\xffrcon ' + password.encode() + b' ' + command.encode() + b'\n'
    
    try:
        # Befehl senden
        sock.sendto(payload, (addr, port))
    except Exception as e:
        # Fehler beim Senden abfangen
        print("Socket send error:", e)
        return b"Error sending data"

    data = b''
    try:
        # Mehrere Pakete empfangen, bis Timeout erreicht wird
        while True:
            packet, _ = sock.recvfrom(4096)
            data += packet
    except socket.timeout:
        # Wenn der Server nicht antwortet
        print("Socket timed out waiting for response.")
    except Exception as e:
        # Allgemeiner Fehler beim Empfangen
        print("Socket receive error:", e)
    
    # Erste 100 Bytes der Antwort zu Debugzwecken ausgeben
    print(f"Raw response bytes: {data[:100]}...")
    return data

def decode_resp(resp_bytes):
    """Dekodiert die RCON-Antwort des Servers zu lesbarem Text."""

    # Antwort besteht oft aus mehreren Paketen, die mit 0xff beginnen
    parts = resp_bytes.split(b'\xff\xff\xff\xff')[1:]
    # Jedes Paket bereinigen und dekodieren
    decoded = "\n".join(
        chunk.rstrip(b'\x00\r\n').decode('utf-8', 'ignore') for chunk in parts
    )
    print(f"Decoded response:\n{decoded}")
    return decoded or "(no response)"

@app.route('/', methods=['GET', 'POST'])
def index():
    """Startseite und Verarbeitung des Eingabeformulars."""

    servers = load_servers()
    output = ""

    if request.method == 'POST':
        # Alle Formulardaten sammeln
        form = request.form.to_dict()
        print("\nForm Submission:", form)

        host = form.get('host', '').strip()
        port = form.get('port', '27015').strip()
        password = form.get('password', '').strip()

        # "say"-Nachricht behandeln, wenn vorhanden
        say_message = form.get("say_message")
        if say_message:
            raw = send_rcon(host, int(port), password, f"say {say_message}")
            output = decode_resp(raw)
        else:
            command = form.get('command', '').strip()
            if host and port and password and command:
                try:
                    raw = send_rcon(host, int(port), password, command)
                    output = decode_resp(raw)
                except Exception as e:
                    output = f"Error: {e}"
                    print("Exception occurred:", e)

        # Neues Serverprofil speichern, falls ein Name angegeben wurde
        new_name = form.get('new_name', '').strip()
        if new_name and host:
            servers[new_name] = {'host': host, 'port': port, 'password': password}
            save_servers(servers)

    return render_template('index.html', servers=servers, output=output)

@app.route('/get_server/<name>')
def get_server(name):
    """Liefert die Konfiguration eines gespeicherten Servers."""

    return jsonify(load_servers().get(name, {}))

if __name__ == '__main__':
    # Anwendung starten
    app.run(host='0.0.0.0', port=5000)
