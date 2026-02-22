<p align="center">
  <h1 align="center"><strong>Clawdbot_Scanner</strong></h1>
</p>

<p align="center">
  <em>Clawdbot / MOLTBOT Vulnerability Scanner & Exploitation Tool</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/ek0ms%20savi0r-white.svg" alt="ek0ms_savi0r">
</p>

<p align="center">
  <em>A comprehensive, interactive security assessment tool for Clawdbot and MOLTBOT instances. This scanner automates the discovery and exploitation of common vulnerabilities including exposed admin interfaces, prompt injection, credential exposure, malicious skills, SSH vulnerabilities, and CVE-2026-25253.</em>
</p>

<br>

<p align="center">
  <h2 align="center"><strong>Features</strong></h2>
</p>

<p align="center">
  <strong>Service Discovery</strong> - Automatically finds Clawdbot instances on a network
</p>
<p align="center">
  • Scans for port 18789/tcp (Clawdbot control interface)<br>
  • Detects SSH services on port 22/tcp<br>
  • mDNS service discovery for Clawdbot instances<br>
  • Banner grabbing and service identification
</p>

<br>

<p align="center">
  <strong>SSH Vulnerability Assessment</strong>
</p>
<p align="center">
  • Tests default credentials against SSH services<br>
  • Checks for vulnerable OpenSSH versions<br>
  • Identifies weak cipher algorithms<br>
  • Interactive shell access when credentials are found
</p>

<br>

<p align="center">
  <strong>Exposed Administrative Interfaces</strong>
</p>
<p align="center">
  • Scans for common admin panels and dashboards<br>
  • Tests default credentials<br>
  • Attempts remote command execution
</p>

<br>

<p align="center">
  <strong>Prompt Injection Testing</strong>
</p>
<p align="center">
  • Tests AI/chat endpoints for injection vulnerabilities<br>
  • Detects sensitive data leakage<br>
  • Identifies command execution vectors
</p>

<br>

<p align="center">
  <strong>Credential Exposure</strong>
</p>
<p align="center">
  • Scans for exposed configuration files<br>
  • Extracts API keys, passwords, and tokens<br>
  • Discovers SSH private keys
</p>

<br>

<p align="center">
  <strong>Malicious Skills/Extensions</strong>
</p>
<p align="center">
  • Identifies skill management endpoints<br>
  • Attempts to upload malicious skills<br>
  • Sets up callbacks for data exfiltration
</p>

<br>

<p align="center">
  <strong>CVE-2026-25253 Exploitation</strong>
</p>
<p align="center">
  • Tests for WebSocket token leakage vulnerability<br>
  • Redirects bot connections to attacker-controlled server<br>
  • Captures authentication tokens
</p>

<br>

<p align="center">
  <h2 align="center"><strong>Installation</strong></h2>
</p>

<p align="center">
  Clone the repository:
</p>

<p align="center">
  <code>git clone https://github.com/ekomsSavior/clawdbot_scanner.git</code><br>
  <code>cd clawdbot_scanner</code>
</p>

<p align="center">
  Install dependencies:
</p>

<p align="center">
  <code>sudo apt update</code><br>
  <code>sudo apt install python3-pip avahi-utils -y</code><br>
  <code>pip3 install requests paramiko --break-system-packages</code>
</p>

<p align="center">
  Make the script executable:
</p>

<p align="center">
  <code>chmod +x clawdbot_scanner.py</code>
</p>

<br>

<p align="center">
  <h2 align="center"><strong>How to Run the Tool</strong></h2>
</p>

<p align="center">
  <code>python3 clawdbot_scanner.py</code>
</p>

<br>

<p align="center">
  <h2 align="center"><strong>What the Tool Does (Step by Step)</strong></h2>
</p>

<p align="center">
  <strong>Phase 1: Service Discovery</strong>
</p>
<p align="center">
  The tool will first ask how you want to discover targets:<br>
  • <strong>Single host</strong> - Scan one specific IP address<br>
  • <strong>Network range</strong> - Scan a subnet (e.g., 192.168.1.0/24)<br>
  • <strong>Import from file</strong> - Load targets from a text file
</p>

<p align="center">
  It will then scan for:<br>
  • Port 18789/tcp (Clawdbot HTTP control interface)<br>
  • Port 22/tcp (SSH services)<br>
  • Additional ports like 80, 443, 8080, 8443<br>
  • mDNS services advertising Clawdbot instances
</p>

<br>

<p align="center">
  <strong>Phase 2: Target Selection</strong>
</p>
<p align="center">
  After discovery, the tool will show you all found hosts and their open ports. You can choose to scan:<br>
  • All discovered hosts<br>
  • Only confirmed Clawdbot instances<br>
  • Specific hosts by number
</p>

<br>

<p align="center">
  <strong>Phase 3: SSH Vulnerability Assessment</strong>
</p>
<p align="center">
  For hosts with port 22 open, the tool will:<br>
  • Grab SSH banners and check for vulnerable versions<br>
  • Test default credentials against SSH (root/root, admin/admin, etc.)<br>
  • Check for weak cipher algorithms<br>
  • Report any findings with severity levels (CRITICAL, HIGH, MEDIUM, INFO)
</p>

<br>

<p align="center">
  <strong>Phase 4: HTTP Interface Scanning</strong>
</p>
<p align="center">
  For hosts with web interfaces, the tool will scan for:<br>
  • Exposed admin panels (/admin, /dashboard, etc.)<br>
  • Chat/API endpoints vulnerable to prompt injection<br>
  • Exposed credential files (.env, .git/config, etc.)<br>
  • Skill management endpoints<br>
  • CVE-2026-25253 WebSocket vulnerabilities
</p>

<br>

<p align="center">
  <strong>Phase 5: Exploitation</strong>
</p>
<p align="center">
  For each vulnerability found, the tool will ask if you want to attempt exploitation:<br>
  • <strong>Admin interfaces</strong> - Tries default passwords, then attempts RCE<br>
  • <strong>Prompt injection</strong> - Sends payloads to leak sensitive data<br>
  • <strong>Exposed credentials</strong> - Extracts and saves API keys, passwords, SSH keys<br>
  • <strong>Malicious skills</strong> - Attempts to upload backdoor skills<br>
  • <strong>CVE-2026-25253</strong> - Redirects WebSocket connections to your listener<br>
  • <strong>SSH</strong> - Opens interactive shells when credentials are found
</p>

<br>

<p align="center">
  <h2 align="center"><strong>What to Expect During Scanning</strong></h2>
</p>

<p align="center">
  <strong>Prompts You'll See</strong>
</p>

<p align="center">
  <code>Enter target IP or domain [192.168.1.100]:</code><br>
  <code>Use HTTPS? (y/n): n</code><br>
  <code>Enter port (default is 18789 for Clawdbot) [18789]:</code>
</p>

<br>

<p align="center">
  <strong>Discovery Results</strong>
</p>

<p align="center">
  <code>[*] Host: 192.168.1.105</code><br>
  <code>    - Port 18789/HTTP [CLAWDBOT]</code><br>
  <code>      Banner: HTTP/1.1 200 OK - Server: Clawdbot/1.2.3</code><br>
  <code>    - Port 22/SSH</code><br>
  <code>      Banner: SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.7</code>
</p>

<br>

<p align="center">
  <strong>Vulnerability Findings</strong>
</p>

<p align="center">
  <code>[CRITICAL] Default SSH Credentials: Successfully authenticated with root:root</code><br>
  <code>[HIGH] Vulnerable SSH Version: Version 7.6 may be vulnerable to CVE-2018-15473</code><br>
  <code>! FOUND: http://192.168.1.105:18789/admin (200 OK) - EXPOSED!</code>
</p>

<br>

<p align="center">
  <strong>Exploitation Options</strong>
</p>

<p align="center">
  <code>[1] Attempt to exploit admin interfaces? (y/n): y</code><br>
  <code>[2] Attempt prompt injection attacks? (y/n): y</code><br>
  <code>[3] Use exposed credentials? (y/n): y</code>
</p>

<br>

<p align="center">
  <h2 align="center"><strong>What to Do With the Results</strong></h2>
</p>

<p align="center">
  <strong>Files Created</strong>
</p>
<p align="center">
  • <strong>leaked_data.txt</strong> - Contains any sensitive data extracted from successful prompt injections<br>
  • <strong>credentials_found.txt</strong> - Stores all discovered credentials (API keys, passwords, SSH keys)
</p>

<br>

<p align="center">
  <strong>Listeners to Set Up</strong>
</p>
<p align="center">
  For certain exploits, you'll need to start listeners on your attacker machine:
</p>

<p align="center">
  <strong>For HTTP exfiltration (port 8080):</strong><br>
  <code>nc -lvnp 8080</code>
</p>

<p align="center">
  <strong>For reverse shells (port 4444):</strong><br>
  <code>nc -lvnp 4444</code>
</p>

<p align="center">
  <strong>For WebSocket token capture (port 8080):</strong><br>
  <code>python3 -m websocket-server --port 8080</code>
</p>

<br>

<p align="center">
  <strong>Post-Exploitation</strong>
</p>
<p align="center">
  • Use captured credentials to access other services<br>
  • Leverage SSH access to explore the filesystem<br>
  • Use admin panel access to modify bot behavior<br>
  • Extract tokens from CVE-2026-25253 to impersonate the bot
</p>

<br>

<p align="center">
  <h2 align="center"><strong>Example Session Walkthrough</strong></h2>
</p>

<p align="center">
  <code>$ python3 clawdbot_scanner.py</code>
</p>

<p align="center">
  <code>============================================================</code><br>
  <code>  MODULE 0: Clawdbot Service Discovery</code><br>
  <code>============================================================</code><br>
  <code>Choose scan method: (1) Single host, (2) Network range, (3) Import from file [1]: 2</code><br>
  <code>Enter network range (e.g., 192.168.1.0/24): 192.168.1.0/24</code>
</p>

<p align="center">
  <code>[*] Scanning 192.168.1.0/24 for Clawdbot instances...</code><br>
  <code>    Testing 192.168.1.105:18789... </code><br>
  <code>    Found: 192.168.1.105:18789 (HTTP)</code><br>
  <code>    Testing 192.168.1.110:22...</code><br>
  <code>    [*] Found SSH on 192.168.1.110:22</code>
</p>

<p align="center">
  <code>============================================================</code><br>
  <code>  DISCOVERED SERVICES</code><br>
  <code>============================================================</code><br>
  <code>[*] Host: 192.168.1.105</code><br>
  <code>    - Port 18789/HTTP [CLAWDBOT]</code><br>
  <code>    - Port 22/SSH</code>
</p>

<p align="center">
  <code>[?] Which hosts would you like to scan? </code><br>
  <code>    1. All discovered hosts</code><br>
  <code>    2. Only Clawdbot instances</code><br>
  <code>    3. Select specific hosts</code><br>
  <code>Choose option [1]: 1</code>
</p>

<p align="center">
  <code>============================================================</code><br>
  <code>  SSH VULNERABILITY ASSESSMENT: 192.168.1.105:22</code><br>
  <code>============================================================</code><br>
  <code>   SSH service is accessible</code><br>
  <code>   SSH Banner: SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.7</code><br>
  <code>   Testing default SSH credentials...</code><br>
  <code>   SUCCESS! Logged in with root:root</code>
</p>

<br>

<p align="center">
  <h2 align="center"><strong>Disclaimer</strong></h2>
</p>

<p align="center">
  This software is provided for educational and authorized security testing purposes only. The author assumes no liability and is not responsible for any misuse or damage caused by this program. By using this software, you agree to use it responsibly and in compliance with all applicable laws and regulations.
</p>

<br>

<p align="center">
  <img width="400" alt="Clawdbot Scanner Art" src="https://github.com/user-attachments/assets/6937c37e-d490-4e6a-bf39-1888c0c133e8">
</p>
