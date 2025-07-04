from flask import Flask, render_template, request, jsonify, abort, session
import socket, os, json

# simple in-memory console log
CONSOLE_LOG = []

def append_log(entry: str):
    """Add a message to the in-memory log keeping the last 50 entries."""
    CONSOLE_LOG.append(entry)
    if len(CONSOLE_LOG) > 50:
        CONSOLE_LOG.pop(0)

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'change-me')

# CSRF helpers
def generate_csrf_token():
    token = session.get('_csrf_token')
    if not token:
        token = os.urandom(16).hex()
        session['_csrf_token'] = token
    return token

@app.before_request
def csrf_protect():
    """No-op CSRF check to allow POST requests without a token."""
    pass

app.jinja_env.globals['csrf_token'] = generate_csrf_token
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
    finally:
        sock.close()

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

# --- Config file helpers ---
def parse_config(path, sections=None):
    """Parse a simple key/value cfg file grouped by provided section names."""
    if sections is None:
        sections = []
    data = {s: {} for s in sections}
    other = {}
    current = None
    try:
        with open(path, encoding='utf-8') as f:
            for line in f:
                stripped = line.strip()
                if not stripped or stripped.startswith((';', '//')):
                    current = None
                    continue
                sec_hit = False
                for sec in sections:
                    if sec.lower() in stripped.lower():
                        current = sec
                        sec_hit = True
                        break
                if sec_hit:
                    continue
                if ' ' in stripped:
                    key, val = stripped.split(None, 1)
                    if sections:
                        target = data.setdefault(current, {}) if current else other
                        target[key] = val
                    else:
                        data[key] = val
    except FileNotFoundError:
        pass
    if sections and other:
        data['other'] = other
    return data

def update_config(path, updates):
    """Update key/value pairs in a cfg file preserving original lines."""
    if not os.path.exists(path):
        return
    with open(path, encoding='utf-8') as f:
        lines = f.readlines()
    new_lines = []
    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith((';', '//')) and ' ' in stripped:
            key = stripped.split(None, 1)[0]
            if key in updates:
                prefix = line[: line.index(key)] if key in line else ''
                line = f"{prefix}{key} {updates[key]}\n"
        new_lines.append(line)
    with open(path, 'w', encoding='utf-8') as f:
        f.writelines(new_lines)

# Main page + form handler
@app.route('/', methods=['GET', 'POST'])
def index():
    servers = load_servers()
    output = ""
    selected_server = ""

    if request.method == 'POST':
        form = request.form.to_dict()
        print("\nForm Submission:", form)

        host = form.get('host', '').strip()
        port = form.get('port', '27015').strip()
        password = form.get('password', '').strip()
        mapfile = form.get('mapfile', 'mapcycle.txt').strip()
        selected_server = form.get('server', '').strip()

        # Delete an existing profile if requested
        if 'delete_profile' in form:
            if selected_server and selected_server in servers:
                del servers[selected_server]
                save_servers(servers)
                output = f"Deleted profile {selected_server}"
            selected_server = ""
            return render_template('index.html', servers=servers, output=output, selected_server=selected_server)

        # Edit existing profile details
        if 'edit_profile' in form:
            if selected_server and selected_server in servers:
                servers[selected_server] = {
                    'host': host,
                    'port': port,
                    'password': password,
                    'mapfile': mapfile
                }
                save_servers(servers)
                output = f"Updated profile {selected_server}"
            return render_template('index.html', servers=servers, output=output, selected_server=selected_server)

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
            selected_server = new_name

    else:
        selected_server = request.args.get('server', '')

    return render_template('index.html', servers=servers, output=output, selected_server=selected_server)

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

# Lightweight server status check
@app.route('/server_status', methods=['POST'])
def server_status():
    data = request.get_json(force=True)
    host = data.get('host')
    port = int(data.get('port', 27015))
    password = data.get('password', '')
    try:
        raw = send_rcon(host, port, password, 'status')
        online = bool(raw)
    except Exception as e:
        print('Status check error:', e)
        online = False
    return jsonify({'online': online})

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

# ----------------- War3FT config -----------------
WAR3FT_CFG = 'addons/amxmodx/configs/war3ft/war3FT.cfg'
WAR3FT_SECTIONS = ['Saving Options', 'Gameplay', 'Skills', 'Items', 'Disables']

@app.route('/war3ft/config', methods=['GET', 'POST'])
def war3ft_config():
    if request.method == 'POST':
        data = request.get_json(force=True)
        try:
            update_config(WAR3FT_CFG, data)
            return jsonify({'success': True})
        except Exception as e:
            return jsonify({'error': str(e)}), 400

    if request.accept_mimetypes.best == 'application/json' or request.args.get('json'):
        return jsonify(parse_config(WAR3FT_CFG, WAR3FT_SECTIONS))
    return render_template('war3ft_config.html')

@app.route('/war3ft/reload', methods=['POST'])
def war3ft_reload():
    data = request.get_json(force=True)
    host = data.get('host')
    port = int(data.get('port', 27015))
    password = data.get('password', '')
    raw = send_rcon(host, port, password, 'amx_reload war3ft.amxx')
    output = decode_resp(raw)
    append_log(output)
    return jsonify({'output': output})

# ----------------- AMXX plugin manager -----------------

@app.route('/amxx/plugins', methods=['GET'])
def amxx_plugins():
    if request.accept_mimetypes.best == 'application/json' or request.args.get('json'):
        host = request.args.get('host')
        port = int(request.args.get('port', 27015))
        password = request.args.get('password', '')
        raw = send_rcon(host, port, password, 'amx_plugins list')
        output = decode_resp(raw)
        plugins = []
        for line in output.splitlines():
            parts = line.split()
            if parts and parts[0].isdigit():
                pid = int(parts[0])
                name = parts[1]
                enabled = 'running' in line or 'loaded' in line
                plugins.append({'id': pid, 'name': name, 'enabled': enabled})
        return jsonify(plugins)
    return render_template('amxx_plugins.html')

@app.route('/amxx/plugins/<int:pid>/<action>', methods=['POST'])
def toggle_plugin(pid, action):
    data = request.get_json(force=True)
    host = data.get('host')
    port = int(data.get('port', 27015))
    password = data.get('password', '')
    if action == 'enable':
        cmd = f'amx_plugins load {pid}'
    else:
        cmd = f'amx_plugins unload {pid}'
    raw = send_rcon(host, port, password, cmd)
    output = decode_resp(raw)
    append_log(output)
    return jsonify({'output': output})

# ----------------- Generic AMXX config editor -----------------

@app.route('/amxx/configs/<plugin>', methods=['GET', 'POST'])
def plugin_config(plugin):
    cfg_path = f'addons/amxmodx/configs/{plugin}/{plugin}.cfg'
    if request.method == 'POST':
        data = request.get_json(force=True)
        try:
            update_config(cfg_path, data)
            return jsonify({'success': True})
        except Exception as e:
            return jsonify({'error': str(e)}), 400

    if request.accept_mimetypes.best == 'application/json' or request.args.get('json'):
        return jsonify(parse_config(cfg_path))
    return render_template('plugin_config.html', plugin=plugin)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
