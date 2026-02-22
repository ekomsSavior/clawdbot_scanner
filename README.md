<p align="center">
  <em> Clawdbot_Scanner</em>
</p>
<p align="center">
  <em>Clawdbot / MOLTBOT Vulnerability Scanner & Exploitation Tool</em>
</p>
<p align="center">

  <img src="https://img.shields.io/badge/ek0ms%20savi0r-yellow.svg" alt="ek0ms_savi0r">
 
</p>

A comprehensive, interactive security assessment tool for Clawdbot and MOLTBOT instances. This scanner automates the discovery and exploitation of common vulnerabilities including exposed admin interfaces, prompt injection, credential exposure, malicious skills, SSH vulnerabilities, and CVE-2026-25253.

## Features

- **Service Discovery** - Automatically finds Clawdbot instances on your network
  - Scans for port 18789/tcp (Clawdbot control interface)
  - Detects SSH services on port 22/tcp
  - mDNS service discovery for Clawdbot instances
  - Banner grabbing and service identification

- **SSH Vulnerability Assessment**
  - Tests default credentials against SSH services
  - Checks for vulnerable OpenSSH versions
  - Identifies weak cipher algorithms
  - Interactive shell access when credentials are found

- **Exposed Administrative Interfaces**
  - Scans for common admin panels and dashboards
  - Tests default credentials
  - Attempts remote command execution

- **Prompt Injection Testing**
  - Tests AI/chat endpoints for injection vulnerabilities
  - Detects sensitive data leakage
  - Identifies command execution vectors

- **Credential Exposure**
  - Scans for exposed configuration files
  - Extracts API keys, passwords, and tokens
  - Discovers SSH private keys

- **Malicious Skills/Extensions**
  - Identifies skill management endpoints
  - Attempts to upload malicious skills
  - Sets up callbacks for data exfiltration

- **CVE-2026-25253 Exploitation**
  - Tests for WebSocket token leakage vulnerability
  - Redirects bot connections to attacker-controlled server
  - Captures authentication tokens

## Installation

Clone the repository:

```bash
git clone https://github.com/ekomsSavior/clawdbot_scanner.git
cd clawdbot_scanner
```

Install dependencies:

```bash
sudo apt update
sudo apt install python3-pip avahi-utils -y
pip3 install requests paramiko --break-system-packages
```

Make the script executable:

```bash
chmod +x clawdbot_scanner.py
```

## How to Run the Tool

```bash
python3 clawdbot_scanner.py
```

## What the Tool Does (Step by Step)

When you run the tool, it will guide you through the following phases:

### Phase 1: Service Discovery
The tool will first ask how you want to discover targets:
- **Single host** - Scan one specific IP address
- **Network range** - Scan a subnet (e.g., 192.168.1.0/24)
- **Import from file** - Load targets from a text file

It will then scan for:
- Port 18789/tcp (Clawdbot HTTP control interface)
- Port 22/tcp (SSH services)
- Additional ports like 80, 443, 8080, 8443
- mDNS services advertising Clawdbot instances

### Phase 2: Target Selection
After discovery, the tool will show you all found hosts and their open ports. You can choose to scan:
- All discovered hosts
- Only confirmed Clawdbot instances
- Specific hosts by number

### Phase 3: SSH Vulnerability Assessment
For hosts with port 22 open, the tool will:
- Grab SSH banners and check for vulnerable versions
- Test default credentials against SSH (root/root, admin/admin, etc.)
- Check for weak cipher algorithms
- Report any findings with severity levels (CRITICAL, HIGH, MEDIUM, INFO)

### Phase 4: HTTP Interface Scanning
For hosts with web interfaces, the tool will scan for:
- Exposed admin panels (/admin, /dashboard, etc.)
- Chat/API endpoints vulnerable to prompt injection
- Exposed credential files (.env, .git/config, etc.)
- Skill management endpoints
- CVE-2026-25253 WebSocket vulnerabilities

### Phase 5: Exploitation
For each vulnerability found, the tool will ask if you want to attempt exploitation:
- **Admin interfaces** - Tries default passwords, then attempts RCE
- **Prompt injection** - Sends payloads to leak sensitive data
- **Exposed credentials** - Extracts and saves API keys, passwords, SSH keys
- **Malicious skills** - Attempts to upload backdoor skills
- **CVE-2026-25253** - Redirects WebSocket connections to your listener
- **SSH** - Opens interactive shells when credentials are found

## What to Expect During Scanning

### Prompts You'll See
```
Enter target IP or domain [192.168.1.100]: 
Use HTTPS? (y/n): n
Enter port (default is 18789 for Clawdbot) [18789]: 
```

### Discovery Results
```
[*] Host: 192.168.1.105
    - Port 18789/HTTP [CLAWDBOT]
      Banner: HTTP/1.1 200 OK - Server: Clawdbot/1.2.3
    - Port 22/SSH
      Banner: SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.7
```

### Vulnerability Findings
```
[CRITICAL] Default SSH Credentials: Successfully authenticated with root:root
[HIGH] Vulnerable SSH Version: Version 7.6 may be vulnerable to CVE-2018-15473
! FOUND: http://192.168.1.105:18789/admin (200 OK) - EXPOSED!
```

### Exploitation Options
```
[1] Attempt to exploit admin interfaces? (y/n): y
[2] Attempt prompt injection attacks? (y/n): y
[3] Use exposed credentials? (y/n): y
```

## What to Do With the Results

### Files Created
- **leaked_data.txt** - Contains any sensitive data extracted from successful prompt injections
- **credentials_found.txt** - Stores all discovered credentials (API keys, passwords, SSH keys)

### Listeners to Set Up
For certain exploits, you'll need to start listeners on your attacker machine:

**For HTTP exfiltration** (port 8080):
```bash
nc -lvnp 8080
```

**For reverse shells** (port 4444):
```bash
nc -lvnp 4444
```

**For WebSocket token capture** (port 8080):
```bash
python3 -m websocket-server --port 8080
```

### Post-Exploitation
- Use captured credentials to access other services
- Leverage SSH access to explore the filesystem
- Use admin panel access to modify bot behavior
- Extract tokens from CVE-2026-25253 to impersonate the bot

## Example Session Walkthrough

```
$ python3 clawdbot_scanner.py

============================================================
  MODULE 0: Clawdbot Service Discovery
============================================================
Choose scan method: (1) Single host, (2) Network range, (3) Import from file [1]: 2
Enter network range (e.g., 192.168.1.0/24): 192.168.1.0/24

[*] Scanning 192.168.1.0/24 for Clawdbot instances...
    Testing 192.168.1.105:18789... 
    Found: 192.168.1.105:18789 (HTTP)
    Testing 192.168.1.110:22...
    [*] Found SSH on 192.168.1.110:22

============================================================
  DISCOVERED SERVICES
============================================================
[*] Host: 192.168.1.105
    - Port 18789/HTTP [CLAWDBOT]
    - Port 22/SSH

[?] Which hosts would you like to scan? 
    1. All discovered hosts
    2. Only Clawdbot instances
    3. Select specific hosts
Choose option [1]: 1

============================================================
  SSH VULNERABILITY ASSESSMENT: 192.168.1.105:22
============================================================
   SSH service is accessible
   SSH Banner: SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.7
   Testing default SSH credentials...
   SUCCESS! Logged in with root:root
```

## Disclaimer

This software is provided for educational and authorized security testing purposes only. The author assumes no liability and is not responsible for any misuse or damage caused by this program. By using this software, you agree to use it responsibly and in compliance with all applicable laws and regulations.


<img width="500" height="500" alt="Untitled_Artwork" src="https://github.com/user-attachments/assets/6937c37e-d490-4e6a-bf39-1888c0c133e8" />

