from flask import Flask, render_template, request, jsonify, Response, stream_with_context
import socket, os, json, queue, threading, time

app = Flask(__name__)
SERVER_FILE = 'servers.json'

# Globals for live status streaming
poll_queue: queue.Queue = queue.Queue()
poll_thread = None
poll_stop = threading.Event()

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

# Background polling function for live status
def poll_server(host: str, port: int, password: str, interval: int = 5):
    while not poll_stop.is_set():
        try:
            raw = send_rcon(host, int(port), password, 'status')
            out = decode_resp(raw)
            poll_queue.put(out)
        except Exception as e:
            poll_queue.put(f'Error: {e}')
        time.sleep(interval)

# Decode RCON server response
def decode_resp(resp_bytes):
    parts = resp_bytes.split(b'\xff\xff\xff\xff')[1:]
    decoded = "\n".join(chunk.rstrip(b'\x00\r\n').decode('utf-8', 'ignore') for chunk in parts)
    print(f"Decoded response:\n{decoded}")
    return decoded or "(no response)"

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

# Start background polling
@app.route('/start_poll')
def start_poll():
    global poll_thread
    host = request.args.get('host')
    port = int(request.args.get('port', '27015'))
    password = request.args.get('password', '')
    interval = int(request.args.get('interval', '5'))
    poll_stop.clear()
    if poll_thread is None or not poll_thread.is_alive():
        poll_thread = threading.Thread(target=poll_server, args=(host, port, password, interval), daemon=True)
        poll_thread.start()
    return ('', 204)

# Stop background polling
@app.route('/stop_poll')
def stop_poll():
    poll_stop.set()
    poll_queue.put('')  # unblock queue
    return ('', 204)

# Stream polled output using Server-Sent Events
@app.route('/stream')
def stream():
    def event_stream():
        while not poll_stop.is_set():
            try:
                line = poll_queue.get(timeout=1)
            except queue.Empty:
                continue
            if line:
                yield f"data: {line}\n\n"
    return Response(stream_with_context(event_stream()), mimetype='text/event-stream')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
