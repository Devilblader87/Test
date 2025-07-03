from flask import Flask, render_template, request, jsonify
import socket
import os
import json
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

# ---------------------------------------------------------------------------
# RCON helpers

def get_challenge(sock, addr, port):
    """Request challenge string required by the GoldSrc RCON protocol."""
    try:
        sock.sendto(b'\xff\xff\xff\xffchallenge rcon\n', (addr, port))
        resp, _ = sock.recvfrom(4096)
        idx = resp.find(b'challenge rcon')
        if idx != -1:
            return resp[idx + len('challenge rcon'):].strip().decode()
    except Exception as exc:
        print('Challenge request failed:', exc)
    return ''


def build_payload(challenge, password, command):
    """Construct the UDP payload for a RCON command."""
    if challenge:
        msg = f"rcon {challenge} \"{password}\" {command}\n"
    else:
        msg = f"rcon \"{password}\" {command}\n"
    return b'\xff\xff\xff\xff' + msg.encode()



# Send RCON command
def send_rcon(addr, port, password, command):
    """Send a command to the server using the GoldSrc RCON protocol."""
    print(f"\nSending RCON Command to {addr}:{port}")
    print(f"Command: {command}")
    print(f"Password: {'*' * len(password)}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1.0)

    challenge = get_challenge(sock, addr, port)
    payload = build_payload(challenge, password, command)

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
    """Decode raw bytes returned from the server."""
    parts = resp_bytes.split(b'\xff\xff\xff\xff')
    if parts and not parts[0].strip():
        parts = parts[1:]
    decoded = "\n".join(
        p.rstrip(b'\x00\r\n').decode('utf-8', 'ignore') for p in parts if p
    )
    print(f"Decoded response:\n{decoded}")
    return decoded or "(no response)"


PLAYER_RE = re.compile(r'^#\s+\d+\s+"(?P<name>[^"]+)"\s+(?P<userid>\d+)\s+(?P<uniqueid>\S+)')


def parse_players(status_output):
    """Extract player information from a status command output."""
    players = []
    for line in status_output.splitlines():
        m = PLAYER_RE.match(line.strip())
        if m:
            players.append(m.groupdict())
    return players

# Main page + form handler
@app.route('/', methods=['GET', 'POST'])
def index():
    servers = load_servers()
    output = ""
    players = []

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
            if form.get('list_players'):
                command = 'status'
            if host and port and password and command:
                try:
                    raw = send_rcon(host, int(port), password, command)
                    output = decode_resp(raw)
                    if form.get('list_players'):
                        players = parse_players(output)
                except Exception as e:
                    output = f"Error: {e}"
                    print("Exception occurred:", e)

        # Save server profile if name + host are provided
        new_name = form.get('new_name', '').strip()
        if new_name and host:
            servers[new_name] = {'host': host, 'port': port, 'password': password}
            save_servers(servers)

    return render_template('index.html', servers=servers, output=output, players=players)

# API to fetch server config
@app.route('/get_server/<name>')
def get_server(name):
    return jsonify(load_servers().get(name, {}))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
