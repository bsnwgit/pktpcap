"""
Fix pktpcap on O2: upload fixed server.py, restart service, verify.
Run via Desktop Commander start_process with Python313.
"""
import paramiko
import sys
import time

O2_HOST = "172.23.80.5"
O2_USER = "ec2-user"
O2_KEY  = r"C:\Users\robert.barnett\.ssh\VyneCorpNetInfra.pem"
LOCAL_SERVER   = r"C:\Users\robert.barnett\My Drive\Documents\Claude\Projects\Packet Analyzer\service\server.py"
REMOTE_SERVER  = "/mnt/software/pktpcap/server.py"
LOCAL_SETTINGS = r"C:\Users\robert.barnett\My Drive\Documents\Claude\Projects\Packet Analyzer\service\templates\settings.html"
REMOTE_SETTINGS = "/mnt/software/pktpcap/templates/settings.html"

def safe_print(text):
    sys.stdout.buffer.write((text + "\n").encode("utf-8", errors="replace"))
    sys.stdout.buffer.flush()

def ssh_run(client, cmd, timeout=20):
    _, stdout, stderr = client.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode("utf-8", errors="replace").strip()
    err = stderr.read().decode("utf-8", errors="replace").strip()
    return out, err

key = paramiko.RSAKey.from_private_key_file(O2_KEY)
client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
client.connect(O2_HOST, username=O2_USER, pkey=key, timeout=15, banner_timeout=15)
safe_print("Connected to O2.")

# Check current status
safe_print("\n=== Current service status ===")
out, _ = ssh_run(client, "systemctl is-active pktpcap")
safe_print(out)

safe_print("\n=== Last 20 log lines ===")
out, _ = ssh_run(client, "sudo journalctl -u pktpcap -n 20 --no-pager --output=cat")
safe_print(out)

# Upload server.py and settings template
safe_print("\n=== Uploading files ===")
sftp = client.open_sftp()
sftp.put(LOCAL_SERVER, REMOTE_SERVER)
safe_print("Uploaded: server.py")
sftp.put(LOCAL_SETTINGS, REMOTE_SETTINGS)
safe_print("Uploaded: templates/settings.html")
sftp.close()

# Restart service
safe_print("\n=== Restarting pktpcap service ===")
out, err = ssh_run(client, "sudo systemctl restart pktpcap")
if out: safe_print("stdout: " + out)
if err: safe_print("stderr: " + err)

time.sleep(4)

# Verify
safe_print("\n=== Service status after restart ===")
out, _ = ssh_run(client, "systemctl is-active pktpcap")
safe_print("Active: " + out)

out, _ = ssh_run(client, "ss -tlnp | grep 8765")
safe_print("Listening on 8765: " + (out if out else "(not yet)"))

safe_print("\n=== Curl test ===")
out, _ = ssh_run(client, "curl -s -o /dev/null -w '%{http_code}' http://localhost:8765/")
safe_print("HTTP status: " + out)

safe_print("\n=== Last 10 log lines after restart ===")
out, _ = ssh_run(client, "sudo journalctl -u pktpcap -n 10 --no-pager --output=cat")
safe_print(out)

client.close()
safe_print("\nDone.")
