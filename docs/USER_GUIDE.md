# pktPCAP — User Guide

This guide is for people who use pktPCAP to analyze packet captures and live traffic feeds — not for installing or administering the server. See [ADMIN_GUIDE.md](ADMIN_GUIDE.md) for setup, users, backups, and integrations.

## Logging in

Log in with your username and password, or Okta SSO if configured. If both local login and SSO are disabled by your admin, the app auto-signs everyone in as the default admin — an intentional trusted-network setup if you encounter it.

Roles: `admin`, `analyst`, `viewer` — Settings, log clearing, and admin routes are restricted to admins.

## Navigation

**Dashboard**, **Live Feeds**, **Upload**, **Analyzer**, **Logs**. **Settings** appears only for admins.

## Analyzing a capture file

1. Go to **Upload**, drag-and-drop (or browse for) a `.pcap`, `.pcapng`, or `.cap` file.
2. Click **Analyze (local)** to parse it entirely in your browser without touching the server, or **Analyze & Save** to also persist it to server storage.
3. Results appear across seven tabs on the **Analyzer** page:

| Tab | Contents |
|---|---|
| Summary | Packet count, duration, rate, total size, capture window, protocol breakdown, top talkers |
| Anomalies | Severity-tagged rule-based findings (RST rate, retransmissions, etc.) |
| Flows | All conversation flows and ports, with packet/byte counts |
| TCP | RSTs, failed handshakes, retransmissions, zero-window events, problem streams |
| UDP | Total packets/bytes, per-flow counts, one-sided-flow flagging |
| DNS | Query/answer/error counts, per-query answered status and RTT |
| Threats | Severity-tagged security findings with evidence lines |

## Live Feeds

If your network has a remote host running `tshark`, or you use Wireshark's own remote-capture feature, the **Live Feeds** page lets you build a capture command (session name, interface, BPF filter, duration) and stream pcapng data straight into pktPCAP for analysis, without manually copying files around.

## Looking up an IP address

Click any underlined IP address anywhere in the Analyzer (top talkers, flows, TCP/UDP streams, threat evidence):

- **Public IPs** open a modal combining ipinfo.io, ipapi.is, AbuseIPDB, and MXToolbox data, using **your own** API keys (Settings → User Keys).
- **Private/RFC1918 IPs** open a pktIPAM inventory lookup (subnet, DHCP lease, DNS records, ARP sightings) — if your admin has configured a Suite Integration connection to pktIPAM.

## AI Assistant

Click the floating **✦** button (bottom-right, any page) to ask a question about whatever capture is currently on screen — powered by Claude or GPT depending on what your admin has configured.

## Logs

Browse the app's own log history, with pagination.

## Your account

Manage your own password from the user menu. Your personal IP-lookup API keys live under Settings → User Keys, private to your account.
