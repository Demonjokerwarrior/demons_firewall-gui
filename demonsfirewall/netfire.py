from flask import Flask, render_template, request, jsonify, send_file, redirect
import subprocess
import time
import json
import os
import signal
import re
from datetime import datetime
from scapy.all import rdpcap, TCP
import hashlib

app = Flask(__name__)

interface = "lo"
pcap_file = "capture.pcap"
log_file = "scan_logs.json"  # consistent naming
decoded_data_store = {}
process_info = {}

suspicious_cmds = [
    "ls", "pwd", "cat", "wget", "curl", "nc", "bash", "sh", "chmod", "chown", "rm",
    "echo", "sudo", "scp", "ssh", "mv", "cp", "whoami", "ifconfig", "ip a", "netstat",
    "uname", "tar", "base64", "python", "perl"
]

def capture_traffic():
    try:
        tshark_cmd = ["tshark", "-i", interface, "-w", pcap_file, "-F", "pcapng", "-a", "duration:10"]
        subprocess.run(tshark_cmd, check=True)
        return True, "Capture complete."
    except Exception as e:
        return False, f"Capture failed: {e}"

def trace_and_kill_process(suspect_ip, suspect_port):
    try:
        netstat_cmd = f"netstat -tunp | grep {suspect_ip}:{suspect_port}"
        netstat_output = subprocess.getoutput(netstat_cmd)
        pid_match = re.search(r"\s(\d+)/", netstat_output)

        if pid_match:
            pid = pid_match.group(1)
            lsof_cmd = f"lsof -p {pid}"
            details = subprocess.getoutput(lsof_cmd)
            os.kill(int(pid), signal.SIGKILL)
            process_info["pid"] = pid
            process_info["details"] = details
            return True
        return False
    except Exception as e:
        process_info["error"] = str(e)
        return False

def save_log_entry(log_entry):
    logs = []
    if os.path.exists(log_file):
        with open(log_file, "r") as f:
            try:
                logs = json.load(f)
                if not isinstance(logs, list):
                    logs = []
            except json.JSONDecodeError:
                logs = []
    logs.append(log_entry)
    with open(log_file, "w") as f:
        json.dump(logs, f, indent=4)

def analyze_pcap():
    global decoded_data_store, process_info
    decoded_data_store = {}
    process_info = {}
    detected_threat = None

    try:
        packets = rdpcap(pcap_file)
        for pkt in packets:
            if pkt.haslayer(TCP) and pkt[TCP].payload:
                payload = bytes(pkt[TCP].payload).decode(errors="ignore")
                src_ip = pkt[1].src
                src_port = pkt[TCP].sport
                decoded_messages = []
                hex_matches = re.findall(r'[0-9a-fA-F]{4,}', payload)

                for hex_str in hex_matches:
                    try:
                        decoded = bytes.fromhex(hex_str).decode('utf-8')
                        if decoded.isprintable():
                            decoded_messages.append(decoded)
                    except:
                        continue

                decoded_data_store[f"{src_ip}:{src_port}"] = {
                    "raw_payload": payload,
                    "decoded_hex": decoded_messages
                }

                for msg in decoded_messages:
                    for cmd in suspicious_cmds:
                        if cmd in msg:
                            detected_threat = {
                                "cmd": msg,
                                "src": f"{src_ip}:{src_port}",
                                "severity": "High" if cmd in ["bash", "nc", "python", "perl", "sh", "ssh"] else "Medium"
                            }
                            trace_and_kill_process(src_ip, src_port)
                            break
                    if detected_threat:
                        break
            if detected_threat:
                break

        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "threat": detected_threat,
            "decoded_data": decoded_data_store,
            "process_info": process_info
        }

        save_log_entry(log_entry)

        return detected_threat
    except Exception as e:
        return {"error": str(e)}

def get_interfaces():
    result = subprocess.getoutput("ip -o link show | awk -F': ' '{print $2}'")
    return result.split('\n')

def get_log_checksum():
    if not os.path.exists(log_file):
        return None
    with open(log_file, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()

@app.route("/")
def index():
    interfaces = get_interfaces()
    return render_template("index.html", interfaces=interfaces)

@app.route("/scan", methods=["POST"])
def scan():
    global interface
    interface = request.form.get("interface", "lo")
    success, msg = capture_traffic()
    if not success:
        return jsonify({"success": False, "message": msg})

    threat = analyze_pcap()
    return jsonify({
        "success": True,
        "threat": threat,
        "decoded_data": decoded_data_store,
        "process_info": process_info,
        "log_checksum": get_log_checksum()
    })

@app.route("/upload", methods=["POST"])
def upload_pcap():
    file = request.files.get('file')
    if file:
        file.save("upload.pcap")
        global pcap_file
        pcap_file = "upload.pcap"
    return redirect("/")

@app.route('/download-log')
def download_log():
    if os.path.exists(log_file):
        return send_file(log_file, as_attachment=True)
    return "No log file found.", 404

@app.route('/logs')
def view_logs():
    logs = []
    if os.path.exists(log_file):
        with open(log_file, "r") as f:
            try:
                logs = json.load(f)
                if not isinstance(logs, list):
                    logs = []
            except json.JSONDecodeError:
                logs = []
    return render_template("logs.html", logs=logs)

if __name__ == "__main__":
    app.run(debug=True)
