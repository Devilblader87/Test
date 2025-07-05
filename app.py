from flask import Flask, render_template, request, jsonify, abort, session, redirect, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash


from functools import wraps
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_principal import Principal, Permission, RoleNeed, Identity, identity_loaded, identity_changed, AnonymousIdentity
from apscheduler.schedulers.background import BackgroundScheduler

# simple in-memory console log
CONSOLE_LOG = []

def append_log(entry: str):
    """Add a message to the in-memory log keeping the last 50 entries."""
    CONSOLE_LOG.append(entry)
    if len(CONSOLE_LOG) > 50:
        CONSOLE_LOG.pop(0)

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'change-me')

# --- Authentication setup ---
login_manager = LoginManager(app)
login_manager.login_view = 'login'
principals = Principal(app)
scheduler = BackgroundScheduler()
scheduler.start()


# SQLite database for logs and users
DB_FILE = 'app.db'

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS command_log (ts REAL, user TEXT, command TEXT)")
    conn.commit()
    conn.close()
    load_users()

init_db()

class User(UserMixin):
    def __init__(self, username, role):
        self.id = username
        self.role = role

@login_manager.user_loader
def load_user(user_id):
    users = load_users()
    info = users.get(user_id)
    if info:
        return User(user_id, info.get("role", "read"))
    return None

def role_required(role):
    def decorator(f):
        @wraps(f)
        def wrapped(*a, **kw):
            if not current_user.is_authenticated or current_user.role != role:
                abort(403)
            return f(*a, **kw)
        return wrapped
    return decorator

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

USERS_FILE = "users.json"
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
# User helpers backed by JSON
def load_users():
    if not os.path.exists(USERS_FILE):
        users = {"admin": {"password": generate_password_hash("admin"), "role": "admin"}}
        with open(USERS_FILE, "w", encoding="utf-8") as f:
            json.dump(users, f, indent=2)
        return users
    with open(USERS_FILE, encoding="utf-8") as f:
        users = json.load(f)
    if "admin" not in users:
        users["admin"] = {"password": generate_password_hash("admin"), "role": "admin"}
        save_users(users)
    return users

def save_users(users):
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=2)

def save_user(username, password_hash, role):
    users = load_users()
    users[username] = {"password": password_hash, "role": role}
    save_users(users)

def user_exists(username):
    users = load_users()
    return username in users

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
@login_required
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
@login_required
def get_console():
    return jsonify(CONSOLE_LOG)

# Lightweight server status check
@app.route('/server_status', methods=['POST'])
@login_required
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
@login_required
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
@login_required
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
@login_required
def ajax_command():
    data = request.get_json(force=True)
    host = data.get('host')
    port = int(data.get('port', 27015))
    password = data.get('password', '')
    command = data.get('command', '')
    raw = send_rcon(host, port, password, command)
    output = decode_resp(raw)
    append_log(output)
    conn = sqlite3.connect(DB_FILE)
    conn.execute('INSERT INTO command_log VALUES (?,?,?)', (time.time(), current_user.id, command))
    conn.commit()
    conn.close()
    return jsonify({'output': output})

# ----------------- War3FT config -----------------
WAR3FT_CFG = 'addons/amxmodx/configs/war3ft/war3FT.cfg'
WAR3FT_SECTIONS = ['Saving Options', 'Gameplay', 'Skills', 'Items', 'Disables']

@app.route('/war3ft/config', methods=['GET', 'POST'])
@login_required
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
    servers = load_servers()
    return render_template('war3ft_config.html', servers=servers)

@app.route('/war3ft/reload', methods=['POST'])
@login_required
@role_required('admin')
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
@login_required
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
    servers = load_servers()
    return render_template('amxx_plugins.html', servers=servers)

@app.route('/amxx/plugins/<int:pid>/<action>', methods=['POST'])
@login_required
@role_required('admin')
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
@login_required
@role_required('admin')
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

# ----------------- Authentication & user management -----------------

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        users = load_users()
        info = users.get(username)
        if info and check_password_hash(info["password"], password):
            login_user(User(username, info.get("role", "read")))
            identity_changed.send(app, identity=Identity(username))
            return redirect(url_for("index"))
        flash("Invalid credentials")
        return redirect(url_for("login"))
    return render_template("login.html")


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        role = request.form.get('role', 'read')
        if user_exists(username):
            return render_template('register.html', error='User exists')
        save_user(username, generate_password_hash(password), role)
        return redirect(url_for('login'))
    return render_template('register.html')



@app.route('/logout')
def logout():
    logout_user()
    identity_changed.send(app, identity=AnonymousIdentity())
    return redirect(url_for('login'))

@app.route('/users', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def manage_users():

    users = load_users()
    if request.method == 'POST':
        uname = request.form.get('username')
        pwd = request.form.get('password')
        role = request.form.get('role', 'read')
        if uname:
            pwd_hash = generate_password_hash(pwd) if pwd else users.get(uname, {}).get('password')
            save_user(uname, pwd_hash, role)
            users = load_users()
    users_list = [(u, info.get('role', 'read')) for u, info in users.items()]
    return render_template('users.html', users=users_list)


@app.route('/roles')
@login_required
def roles():
    return jsonify(['admin','moderator','read'])

# ----------------- Dashboard -----------------

WIDGETS = {}
ENABLED_WIDGETS = set()

def register_widget(name, func):
    WIDGETS[name] = func

def sample_widget():
    return '<div class="p-2">Sample Widget</div>'

register_widget('sample', sample_widget)

@app.route('/dashboard')
@login_required
def dashboard():
    servers = load_servers()
    return render_template('dashboard.html', servers=servers, widgets=[WIDGETS[n]() for n in ENABLED_WIDGETS])

@app.route('/widgets', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def widgets():
    if request.method == 'POST':
        name = request.form.get('name')
        state = request.form.get('state')
        if name in WIDGETS:
            if state == 'on':
                ENABLED_WIDGETS.add(name)
            else:
                ENABLED_WIDGETS.discard(name)
    return render_template('widgets.html', widgets=WIDGETS, enabled=ENABLED_WIDGETS)

# ----------------- File editor -----------------

@app.route('/files/edit/<path:fp>', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def edit_file(fp):
    if request.method == 'POST':
        content = request.form.get('content','')
        try:
            with open(fp,'w',encoding='utf-8') as f:
                f.write(content)
            return jsonify({'saved': True})
        except Exception as e:
            return jsonify({'error': str(e)}), 400
    try:
        with open(fp,encoding='utf-8') as f:
            text = f.read()
    except FileNotFoundError:
        abort(404)
    return render_template('edit_file.html', path=fp, text=text)

# ----------------- Task scheduler -----------------

@app.route('/tasks', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def tasks():
    if request.method == 'POST':
        host = request.form.get('host')
        port = int(request.form.get('port','27015'))
        password = request.form.get('password')
        command = request.form.get('command')
        run_at = float(request.form.get('run_at',0))
    scheduler.add_job(lambda: send_rcon(host, port, password, command), 'date', run_date=time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(run_at)))
    return render_template('tasks.html')

@app.route('/stats')
@login_required
def stats():
    conn = sqlite3.connect(DB_FILE)
    rows = conn.execute('SELECT user, COUNT(*) FROM command_log GROUP BY user').fetchall()
    conn.close()
    return render_template('stats.html', rows=rows)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
