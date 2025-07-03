from flask import Flask, render_template, request, jsonify
import socket, os, json

# simple in-memory console log
CONSOLE_LOG = []

def append_log(entry: str):
    """Add a message to the in-memory log keeping the last 50 entries."""
    CONSOLE_LOG.append(entry)
    if len(CONSOLE_LOG) > 50:
        CONSOLE_LOG.pop(0)

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

def parse_players(status_output: str):
    """Parse `status` command output and extract a list of players."""
    players = []
    for raw in status_output.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith('print'):
            line = line[5:].strip()
        if not line or line.startswith('map:') or line.startswith('#'):
            # skip headers and map line
            continue

        # format: columns separated by tabs with IP at the end
        if '\t' in line:
            parts = [p for p in line.split('\t') if p]
            if len(parts) >= 2:
                prefix = parts[0].strip()
                name = parts[-2].strip()
                ip = parts[-1].strip()
                fields = prefix.split()
                if fields and fields[0].isdigit():
                    userid = fields[0]
                    ping = fields[2] if len(fields) > 2 else ''
                    players.append({'userid': userid, 'name': name, 'ping': ping, 'ip': ip})
                    continue

        # fallback for classic status output (# userid name ...)
        if line.startswith('#') and '"' in line:
            parts = line.split('"')
            if len(parts) >= 3:
                name = parts[1]
                fields = line.split()
                userid = fields[1] if len(fields) > 1 else ''
                ping = fields[-2] if len(fields) > 1 else ''
                players.append({'userid': userid, 'name': name, 'ping': ping, 'ip': ''})

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
        mapfile = form.get('mapfile', 'mapcycle.txt').strip()

        # Handle "say" message if submitted
        say_message = form.get("say_message")
        if say_message:
            raw = send_rcon(host, int(port), password, f"say {say_message}")
            output = decode_resp(raw)
            append_log(output)
        else:
            command = form.get('command', '').strip()
            if host and port and password and command:
                try:
                    raw = send_rcon(host, int(port), password, command)
                    output = decode_resp(raw)
                    append_log(output)
                except Exception as e:
                    output = f"Error: {e}"
                    print("Exception occurred:", e)

        # Save server profile if name + host are provided
        new_name = form.get('new_name', '').strip()
        if new_name and host:
            servers[new_name] = {'host': host, 'port': port, 'password': password, 'mapfile': mapfile}
            save_servers(servers)

    return render_template('index.html', servers=servers, output=output)

# API to fetch server config
@app.route('/get_server/<name>')
def get_server(name):
    data = load_servers().get(name, {})
    if data and 'mapfile' not in data:
        data['mapfile'] = 'mapcycle.txt'
    return jsonify(data)

# API to fetch console log
@app.route('/console')
def get_console():
    return jsonify(CONSOLE_LOG)

# API to fetch player list using status command
@app.route('/players', methods=['POST'])
def get_players():
    data = request.get_json(force=True)
    host = data.get('host')
    port = int(data.get('port', 27015))
    password = data.get('password', '')
    raw = send_rcon(host, port, password, 'status')
    output = decode_resp(raw)
    append_log(output)
    return jsonify(parse_players(output))

# API to load maps from a mapcycle file
@app.route('/maps', methods=['POST'])
def get_maps():
    data = request.get_json(force=True)
    path = data.get('file', 'mapcycle.txt')
    try:
        with open(path, encoding='utf-8') as f:
            maps = [line.strip() for line in f if line.strip() and not line.startswith(';')]
        return jsonify(maps)
    except Exception as e:
        return jsonify({'error': str(e)}), 400

# API to send arbitrary command via AJAX
@app.route('/command', methods=['POST'])
def ajax_command():
    data = request.get_json(force=True)
    host = data.get('host')
    port = int(data.get('port', 27015))
    password = data.get('password', '')
    command = data.get('command', '')
    raw = send_rcon(host, port, password, command)
    output = decode_resp(raw)
    append_log(output)
    return jsonify({'output': output})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
