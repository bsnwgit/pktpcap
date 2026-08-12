#!/usr/bin/env python3
"""
Quick verify: SSH to a pktPCAP host and confirm the systemd service is active,
listening, and responding to HTTP.

Usage:
  PKTPCAP_SSH_HOST=<host> PKTPCAP_SSH_USER=<user> PKTPCAP_SSH_KEY=<path-to-pem> python3 verify_deploy.py
or:
  python3 verify_deploy.py --host <host> --user <user> --key <path-to-pem> [--port 8765]
"""
import argparse
import os
import sys

import paramiko

SERVICE_NAME = "pktpcap"


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default=os.environ.get("PKTPCAP_SSH_HOST"),
                         help="SSH host/IP of the pktPCAP server")
    parser.add_argument("--user", default=os.environ.get("PKTPCAP_SSH_USER"),
                         help="SSH username")
    parser.add_argument("--key", default=os.environ.get("PKTPCAP_SSH_KEY"),
                         help="Path to SSH private key (.pem)")
    parser.add_argument("--port", type=int, default=int(os.environ.get("PKTPCAP_PORT", 8765)),
                         help="Port pktPCAP listens on (default: 8765)")
    args = parser.parse_args()
    missing = [name for name, val in (("--host/PKTPCAP_SSH_HOST", args.host),
                                       ("--user/PKTPCAP_SSH_USER", args.user),
                                       ("--key/PKTPCAP_SSH_KEY", args.key)) if not val]
    if missing:
        parser.error(f"missing required value(s): {', '.join(missing)}")
    return args


def ssh_run(client, cmd, timeout=20):
    _, stdout, stderr = client.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode("utf-8", errors="replace").strip()
    err = stderr.read().decode("utf-8", errors="replace").strip()
    return out, err


def main():
    args = parse_args()

    key = paramiko.RSAKey.from_private_key_file(args.key)
    client = paramiko.SSHClient()
    # Verify the host key rather than trusting whatever is presented first.
    # AutoAddPolicy made the initial connection — the one that establishes
    # trust — unauthenticated, so anything in between could impersonate the
    # target and capture the SSH credentials. Connect once by hand to record
    # the key, or set PKT_SSH_TRUST_NEW_HOSTS=1 to accept a new one.
    client.load_system_host_keys()
    for _known in (os.environ.get("PKT_SSH_KNOWN_HOSTS"),
                   os.path.expanduser("~/.ssh/known_hosts")):
        if _known and os.path.exists(_known):
            try:
                client.load_host_keys(_known)
            except OSError:
                pass
    # RejectPolicy unconditionally. An earlier version of this fix kept an
    # AutoAddPolicy escape hatch behind an environment variable, which is
    # exactly the blind first-contact trust the fix exists to remove — it just
    # moved it behind a flag. Point PKT_SSH_KNOWN_HOSTS at a file instead: a
    # host key can be recorded deliberately, which is auditable, where
    # "accept whatever answers this time" is not.
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    client.connect(args.host, username=args.user, pkey=key, timeout=15, banner_timeout=15)
    print("Connected.\n")

    print("=== Service status ===")
    out, _ = ssh_run(client, f"systemctl is-active {SERVICE_NAME}")
    print(out)

    print("\n=== Last 30 log lines ===")
    out, _ = ssh_run(client, f"sudo journalctl -u {SERVICE_NAME} -n 30 --no-pager")
    print(out)

    print("\n=== Listening ports ===")
    out, _ = ssh_run(client, f"ss -tlnp | grep -E '{args.port}|LISTEN'")
    print(out)

    print("\n=== Curl test ===")
    out, _ = ssh_run(client, f"curl -s -o /dev/null -w '%{{http_code}}' http://localhost:{args.port}/")
    print(out)

    print("\n=== iptables INPUT rules ===")
    out, _ = ssh_run(client, "sudo iptables -L INPUT -n | head -20")
    print(out)

    client.close()


if __name__ == "__main__":
    main()
