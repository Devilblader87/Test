from flask import Flask, render_template, request, jsonify
import socket, os, json
import re

app = Flask(__name__)
SERVER_FILE = 'servers.json'

# Load saved servers from JSON
def load_servers():
    if os.path.exists(SERVER_FILE):
        with open(SERVER_FILE, encoding='utf-8') as f:
            return json.load(f)
    return {}

# Save new servers to JSON
def save_servers(servers):
    with open(SERVER_FILE, 'w', encoding='utf-8') as f:
        json.dump(servers, f, indent=2)

# Send RCON command
def send_rcon(addr, port, password, command):
    print(f"\nSending RCON Command to {addr}:{port}")
    print(f"Command: {command}")
    print(f"Password: {'*' * len(password)}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1.0)
    payload = b'\xff\xff\xff\xffrcon ' + password.encode() + b' ' + command.encode() + b'\n'
    
    try:
        sock.sendto(payload, (addr, port))
    except Exception as e:
        print("Socket send error:", e)
        return b"Error sending data"

    data = b''
    try:
        while True:
            packet, _ = sock.recvfrom(4096)
            data += packet
    except socket.timeout:
        print("Socket timed out waiting for response.")
    except Exception as e:
        print("Socket receive error:", e)
    
    print(f"Raw response bytes: {data[:100]}...")  # Show first 100 bytes
    return data

# Decode RCON server response
def decode_resp(resp_bytes):
    parts = resp_bytes.split(b'\xff\xff\xff\xff')[1:]
    decoded = "\n".join(chunk.rstrip(b'\x00\r\n').decode('utf-8', 'ignore') for chunk in parts)
    print(f"Decoded response:\n{decoded}")
    return decoded or "(no response)"

# Parse player list from a status response
def parse_players(decoded_status):
    players = []
    for line in decoded_status.splitlines():
        line = line.strip()
        if line.startswith('#') and '"' in line and not line.startswith('# userid'):
            # Example line: # 1 "Player" 123 STEAM_1:0:1 0 00:02 0 0
            try:
                pre, rest = line.split('"', 1)
                name, _ = rest.split('"', 1)
                userid = pre.strip('# ').split()[0]
                players.append({'userid': userid, 'name': name})
            except ValueError:
                continue
    return players

# Main page + form handler
@app.route('/', methods=['GET', 'POST'])
def index():
    servers = load_servers()
    output = ""

    if request.method == 'POST':
        form = request.form.to_dict()
        print("\nForm Submission:", form)

        host = form.get('host', '').strip()
        port = form.get('port', '27015').strip()
        password = form.get('password', '').strip()

        # Handle "say" message if submitted
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

        # Save server profile if name + host are provided
        new_name = form.get('new_name', '').strip()
        if new_name and host:
            servers[new_name] = {'host': host, 'port': port, 'password': password}
            save_servers(servers)

    return render_template('index.html', servers=servers, output=output)

# API to fetch server config
@app.route('/get_server/<name>')
def get_server(name):
    return jsonify(load_servers().get(name, {}))

# Return list of players for a server
@app.route('/players/<name>')
def get_players(name):
    cfg = load_servers().get(name)
    if not cfg:
        return jsonify({'error': 'Unknown server'}), 404
    raw = send_rcon(cfg['host'], int(cfg.get('port', 27015)), cfg['password'], 'status')
    decoded = decode_resp(raw)
    return jsonify({'players': parse_players(decoded)})

# Kick or ban a player
@app.route('/player_action/<name>/<action>/<userid>', methods=['POST'])
def player_action(name, action, userid):
    cfg = load_servers().get(name)
    if not cfg:
        return jsonify({'error': 'Unknown server'}), 404
    if action == 'kick':
        cmd = f"kick #{userid}"
    elif action == 'ban':
        cmd = f"banid 0 #{userid};kick #{userid}"
    else:
        return jsonify({'error': 'Invalid action'}), 400
    raw = send_rcon(cfg['host'], int(cfg.get('port', 27015)), cfg['password'], cmd)
    decoded = decode_resp(raw)
    return jsonify({'result': decoded})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
