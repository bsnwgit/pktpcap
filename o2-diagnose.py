import paramiko

O2_HOST = "10.20.30.5"
O2_USER = "ec2-user"
O2_KEY  = r"C:\Users\user\.ssh\corporate_infrastructure.pem"

def ssh_run(client, cmd, timeout=20):
    _, stdout, stderr = client.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode("utf-8", errors="replace").strip()
    err = stderr.read().decode("utf-8", errors="replace").strip()
    return out, err

key = paramiko.RSAKey.from_private_key_file(O2_KEY)
client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
client.connect(O2_HOST, username=O2_USER, pkey=key, timeout=15, banner_timeout=15)
print("Connected.\n")

print("=== Service status ===")
out, _ = ssh_run(client, "systemctl is-active pktanalyzer")
print(out)

print("\n=== Last 30 log lines ===")
out, _ = ssh_run(client, "sudo journalctl -u pktanalyzer -n 30 --no-pager")
print(out)

print("\n=== Listening ports ===")
out, _ = ssh_run(client, "ss -tlnp | grep -E '8765|LISTEN'")
print(out)

print("\n=== Curl test ===")
out, _ = ssh_run(client, "curl -s -o /dev/null -w '%{http_code}' http://localhost:8765/")
print(out)

print("\n=== iptables INPUT rules ===")
out, _ = ssh_run(client, "sudo iptables -L INPUT -n | head -20")
print(out)

client.close()
