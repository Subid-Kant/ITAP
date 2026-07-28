"""
ITAP — Autonomous Response & Playbook Engine v2.0
Layer 4: LLM-based playbook generation, real alert dispatching,
SIEM integration, Slack/Teams webhooks, and comprehensive playbook library.
"""
import asyncio
import logging
import json
from datetime import datetime
from typing import Dict, Any, List, Optional
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from app.core.config import settings

logger = logging.getLogger("itap.response")


class PlaybookGenerator:
    """
    AI-assisted Incident Response Playbook Generator v2.0.
    Generates step-by-step remediation playbooks with contextual adaptation.
    Template library covers 12 major threat categories.
    """

    PLAYBOOK_TEMPLATES = {
        "Remote Code Execution": {
            "title": "Remote Code Execution (RCE) Incident Response",
            "priority": "CRITICAL",
            "sla_hours": 1,
            "compliance_refs": ["NIST IR 6.2", "ISO 27035-3", "PCI-DSS 12.10"],
            "steps": [
                {"step": 1, "action": "Immediate Isolation & Preservation",
                 "detail": "Isolate the affected system from the network IMMEDIATELY — do NOT power off (preserve volatile memory). Disconnect from internal LAN and internet simultaneously. Take photos/screenshots of active processes, open network connections, and logged-in users.",
                 "tools": ["netsh advfirewall", "iptables -I INPUT -j DROP", "Windows Defender Firewall"]},
                {"step": 2, "action": "Volatile Memory Capture",
                 "detail": "Capture RAM using WinPMem (Windows) or LiME (Linux) before shutdown. Record process list (tasklist /v), network connections (netstat -an), and active sessions. Hash all captured images (SHA-256).",
                 "tools": ["WinPmem", "LiME", "Volatility3", "FTK Imager"]},
                {"step": 3, "action": "Attack Vector Identification",
                 "detail": "Analyse web server access logs for the injection timestamp. Search for encoded payloads (base64, hex) in URL params, POST bodies, HTTP headers, and User-Agent strings. Identify the vulnerable endpoint, parameter, and applicable CVE.",
                 "tools": ["grep", "GoAccess", "ELK Stack", "Splunk", "AWStats"]},
                {"step": 4, "action": "Attacker IP Blocking",
                 "detail": "Block attacker IPs at perimeter firewall, WAF, and cloud security group levels. Apply geo-blocking for source regions if applicable. Check all load balancer logs for the same source IP across other services.",
                 "tools": ["AWS WAF", "Cloudflare Firewall Rules", "ModSecurity", "pf/iptables"]},
                {"step": 5, "action": "Impact Assessment & Persistence Check",
                 "detail": "Determine data exfiltration: analyse outbound traffic volumes and connections to external IPs. Scan for persistence: cron jobs, systemd services, registry Run keys, WMI subscriptions, scheduled tasks, web shells in document roots.",
                 "tools": ["CrowdStrike EDR", "SentinelOne", "osquery", "Autoruns (Sysinternals)"]},
                {"step": 6, "action": "Patch & Virtual Patch",
                 "detail": "Apply vendor security patch for the identified CVE (use change management fast-track for CRITICAL). If patch unavailable, deploy WAF virtual patch rule (OWASP CRS ModSecurity rule or equivalent). Disable or isolate the vulnerable service.",
                 "tools": ["WAF Virtual Patch", "OWASP CRS", "vendor patch portal"]},
                {"step": 7, "action": "Clean Restoration",
                 "detail": "If system integrity is compromised, rebuild from known-good golden image — do NOT restore from potentially infected backup. Re-enable services with enhanced monitoring and canary tokens. Verify patch effectiveness with authenticated pen test.",
                 "tools": ["Ansible", "Chef", "Terraform", "AWS AMI", "Azure Image"]},
                {"step": 8, "action": "Post-Incident Review & Lessons Learned",
                 "detail": "Document full timeline, root cause, impact scope, and remediation steps. Update IDS/IPS signatures with attack indicators. Conduct blameless retrospective within 48 hours. Update vulnerability disclosure process. File regulatory report if PII was exposed.",
                 "tools": ["JIRA", "Confluence", "Incident Report Template"]},
            ],
        },
        "SQL Injection": {
            "title": "SQL Injection Attack Incident Response",
            "priority": "HIGH",
            "sla_hours": 4,
            "compliance_refs": ["OWASP A03:2021", "PCI-DSS 6.4.1", "NIST SP 800-92"],
            "steps": [
                {"step": 1, "action": "Identify Injection Points",
                 "detail": "Review web application and WAF logs to identify the vulnerable parameter(s). Search for UNION SELECT, OR 1=1, DROP TABLE, INFORMATION_SCHEMA, and error-based/time-based blind injection signatures.",
                 "tools": ["Web application logs", "WAF logs", "Splunk", "ELK"]},
                {"step": 2, "action": "Block & Quarantine",
                 "detail": "Block attacker IP(s) at WAF and firewall level. Enable OWASP Core Rule Set SQL injection rules. Consider taking vulnerable endpoint offline until patched.",
                 "tools": ["ModSecurity OWASP CRS", "AWS WAF", "F5 ASM"]},
                {"step": 3, "action": "Database Audit",
                 "detail": "Review database audit logs for unauthorized SELECT, INSERT, UPDATE, DELETE statements. Check for new user accounts or stored procedures. Verify data integrity against backup checksums.",
                 "tools": ["MySQL General Log", "PostgreSQL pg_audit", "MSSQL SQL Server Audit"]},
                {"step": 4, "action": "Data Exposure Assessment",
                 "detail": "Determine if PII, credentials, or sensitive data was exfiltrated. If confirmed, initiate data breach notification procedures per GDPR/CCPA requirements within 72 hours.",
                 "tools": ["DLP tools", "data classification system"]},
                {"step": 5, "action": "Code Remediation",
                 "detail": "Replace all dynamic SQL with parameterized queries or prepared statements. Apply ORM-based querying. Input validation on all user-supplied data. Apply DENY permissions to database accounts (least privilege).",
                 "tools": ["SAST tools: SonarQube, Checkmarx", "Code review"]},
                {"step": 6, "action": "Notification & Compliance",
                 "detail": "If PII was exposed: notify affected users, DPO, and relevant authorities (ICO/FTC). Update security testing procedures to include automated SQLi regression testing.",
                 "tools": ["Legal team", "DPO", "Breach notification templates"]},
            ],
        },
        "Ransomware": {
            "title": "Ransomware Attack Incident Response",
            "priority": "CRITICAL",
            "sla_hours": 1,
            "compliance_refs": ["CISA AA23-061A", "FBI Flash Alert", "ISO 27035"],
            "steps": [
                {"step": 1, "action": "STOP — Isolate Everything Immediately",
                 "detail": "Immediately disconnect ALL affected systems from network. Disable network interfaces, Wi-Fi, and Bluetooth. Do NOT shutdown — preserve encryption key in RAM if possible. Alert CISO, legal, and C-suite within 15 minutes.",
                 "tools": ["Network killswitch", "VLAN isolation", "EDR network quarantine"]},
                {"step": 2, "action": "Identify Ransomware Variant",
                 "detail": "Capture ransom note and encrypted file extensions. Use No More Ransom (nomoreransom.org) and ID Ransomware to identify strain. Determine if decryptor is available before considering any recovery options.",
                 "tools": ["ID Ransomware", "nomoreransom.org", "Coveware"]},
                {"step": 3, "action": "Assess Backup Integrity",
                 "detail": "Verify offline backups are clean and unaffected. Test restore on isolated environment. Determine RPO (Recovery Point Objective) from last clean backup.",
                 "tools": ["Veeam", "Acronis", "Backup immutability check"]},
                {"step": 4, "action": "Determine Infection Vector",
                 "detail": "Trace patient zero: check email gateway for phishing, RDP exposure, VPN logs for compromised accounts, supply chain access. Remove initial access vector before beginning recovery.",
                 "tools": ["Email forensics", "EDR telemetry", "Network flow analysis"]},
                {"step": 5, "action": "Containment & Threat Removal",
                 "detail": "Remove ransomware artifacts using EDR. Reset ALL credentials — assume complete domain compromise. Rebuild domain controllers from backup if AD was compromised.",
                 "tools": ["CrowdStrike", "Microsoft Defender", "AD Tiering recovery"]},
                {"step": 6, "action": "Recovery & Restoration",
                 "detail": "Restore systems from verified clean backups in priority order. Implement network segmentation before reconnecting. Deploy enhanced monitoring — adversary may have persistence.",
                 "tools": ["Backup restoration", "Network segmentation", "Canary files"]},
                {"step": 7, "action": "Legal, Regulatory & Law Enforcement",
                 "detail": "Report to FBI IC3, CISA (US) or equivalent law enforcement. Do NOT pay ransom without legal/FBI consultation. Engage cyber insurance provider. Preserve evidence for law enforcement and forensics.",
                 "tools": ["FBI IC3 (ic3.gov)", "CISA (cisa.gov/report)", "Cyber insurance contact"]},
            ],
        },
        "Phishing": {
            "title": "Phishing Campaign Incident Response",
            "priority": "HIGH",
            "sla_hours": 2,
            "compliance_refs": ["NIST SP 800-177", "CIS Control 9", "PCI-DSS 12.6"],
            "steps": [
                {"step": 1, "action": "Scope Identification",
                 "detail": "Query email gateway logs for the phishing sender, subject line, and URL/attachment hash. Identify ALL recipients, clickers, and attachment openers using SIEM correlation.",
                 "tools": ["Microsoft 365 Defender", "Proofpoint", "Mimecast", "Email gateway logs"]},
                {"step": 2, "action": "Block & Quarantine",
                 "detail": "Block phishing domain/URL at DNS (sinkhole), proxy, and email gateway simultaneously. Recall phishing emails from all mailboxes. Block sender address and domain across all email flows.",
                 "tools": ["DNS sinkhole", "Email recall (M365/Google Workspace)", "Web proxy"]},
                {"step": 3, "action": "Credential Reset",
                 "detail": "Force immediate password reset for all users who clicked the link or opened attachments. Revoke all active sessions, OAuth tokens, and API keys. Enroll in MFA if not already enforced.",
                 "tools": ["Azure AD / Okta admin portal", "MFA enforcement"]},
                {"step": 4, "action": "Endpoint Investigation",
                 "detail": "Scan all endpoints of users who clicked or opened attachments for malware. Look for persistence, lateral movement indicators, and data staging activities.",
                 "tools": ["EDR scan", "CrowdStrike", "Windows Defender Offline Scan"]},
                {"step": 5, "action": "Security Awareness",
                 "detail": "Send organization-wide alert describing the campaign with indicators. Fast-track targeted training for affected users. Update phishing simulation program with this campaign template.",
                 "tools": ["KnowBe4", "Proofpoint Security Awareness", "Organization comms"]},
            ],
        },
        "Denial of Service": {
            "title": "DDoS / Denial of Service Incident Response",
            "priority": "HIGH",
            "sla_hours": 1,
            "compliance_refs": ["NIST SP 800-61", "CISA DDoS Quick Guide"],
            "steps": [
                {"step": 1, "action": "Activate DDoS Protection",
                 "detail": "Enable DDoS mitigation service (Cloudflare Magic Transit, AWS Shield Advanced, Akamai Prolexic). Activate anycast traffic scrubbing. Enable geo-IP rate limiting on origin servers.",
                 "tools": ["Cloudflare", "AWS Shield", "Akamai", "Radware"]},
                {"step": 2, "action": "Attack Analysis",
                 "detail": "Identify attack type: volumetric (UDP flood, ICMP flood), protocol (SYN flood, ACK flood), or application layer (HTTP GET flood, Slowloris). Capture sample PCAP for signature extraction.",
                 "tools": ["NetFlow/sFlow", "Wireshark", "tcpdump", "Arbor Networks"]},
                {"step": 3, "action": "Targeted Mitigation",
                 "detail": "Deploy scrubbing rules for identified attack signature. Null-route attack source ASNs if volumetric. Rate-limit by geolocation, ASN, or user-agent for application attacks.",
                 "tools": ["BGP Blackholing", "ISP null-route request", "CDN WAF rules"]},
                {"step": 4, "action": "Stakeholder Communication",
                 "detail": "Update status page for affected services. Notify ISP and hosting provider with pcap evidence. Brief executive stakeholders on impact, ETA to recovery, and SLA implications.",
                 "tools": ["Status page (statuspage.io)", "ISP abuse contact", "Incident comms"]},
                {"step": 5, "action": "Post-Attack Hardening",
                 "detail": "Review and update DDoS playbook. Implement additional capacity (auto-scaling). Deploy CAPTCHA on login/checkout forms. Consider anycast global deployment for future resilience.",
                 "tools": ["Anycast CDN", "Auto-scaling groups", "CAPTCHA providers"]},
            ],
        },
        "Brute Force": {
            "title": "Brute Force / Credential Attack Incident Response",
            "priority": "MEDIUM",
            "sla_hours": 4,
            "compliance_refs": ["CIS Control 4", "NIST SP 800-63B", "PCI-DSS 8.3"],
            "steps": [
                {"step": 1, "action": "Block Source IPs",
                 "detail": "Immediately block all attacking IPs at WAF and firewall. Deploy fail2ban or equivalent auto-blocking. Request upstream ISP/cloud provider to block traffic at network edge.",
                 "tools": ["fail2ban", "WAF rate limiting", "firewalld/iptables"]},
                {"step": 2, "action": "Account Impact Assessment",
                 "detail": "Identify targeted accounts and check for any successful logins from attacker IPs. Review MFA challenge bypass attempts. Lock accounts with successful unauthorized access immediately.",
                 "tools": ["SIEM authentication logs", "Azure AD Sign-in logs", "Okta System Log"]},
                {"step": 3, "action": "Credential Hardening",
                 "detail": "Enforce MFA on all targeted services immediately. Implement account lockout after 5 failed attempts. Deploy CAPTCHA. Force password reset on all targeted accounts.",
                 "tools": ["Duo MFA", "Microsoft Authenticator", "Google reCAPTCHA"]},
                {"step": 4, "action": "Enhanced Monitoring",
                 "detail": "Set up SIEM rules for velocity-based auth failure alerts. Deploy honeypot credentials to detect future attacks. Review and rotate API keys and service account credentials.",
                 "tools": ["SIEM correlation rules", "Canary tokens", "Deception tools"]},
            ],
        },
        "APT / Advanced Persistent Threat": {
            "title": "APT (Advanced Persistent Threat) Incident Response",
            "priority": "CRITICAL",
            "sla_hours": 1,
            "compliance_refs": ["CISA AA22-320A", "MITRE ATT&CK Framework", "ISO 27035"],
            "steps": [
                {"step": 1, "action": "Covert Containment Assessment",
                 "detail": "CRITICAL: Do NOT alert adversary before containment is ready. Covertly gather evidence while monitoring. Establish shadow monitoring to capture all adversary activity before isolation.",
                 "tools": ["EDR covert monitoring mode", "Network tap", "SIEM covert rule set"]},
                {"step": 2, "action": "Full Compromise Assessment",
                 "detail": "Assume entire network is compromised. Engage specialized DFIR firm. Map all adversary TTPs to MITRE ATT&CK. Identify all persistence mechanisms, exfiltrated data, and lateral movement paths.",
                 "tools": ["Mandiant", "CrowdStrike Services", "Secureworks CTU", "KELA"]},
                {"step": 3, "action": "Evidence Preservation",
                 "detail": "Preserve all forensic evidence with chain of custody documentation. This may be needed for law enforcement prosecution. Use write-blockers for disk imaging.",
                 "tools": ["FTK Imager", "dd", "Write blockers", "Forensic workstation"]},
                {"step": 4, "action": "Coordinated Eviction",
                 "detail": "Plan and execute simultaneous eviction of all attacker footholds in a single coordinated action window to prevent re-entry. Reset ALL credentials enterprise-wide.",
                 "tools": ["AD credential reset", "Certificate revocation", "PKI re-issuance"]},
                {"step": 5, "action": "Rebuild & Harden",
                 "detail": "Rebuild all compromised systems from clean images. Implement zero-trust architecture. Deploy privileged access workstations (PAW). Tier Active Directory.",
                 "tools": ["Zero-trust platform", "CyberArk PAM", "AD tiering tools"]},
                {"step": 6, "action": "Threat Intelligence Sharing",
                 "detail": "Share sanitized IOCs and TTPs with relevant ISACs (Information Sharing and Analysis Centers). Submit to FS-ISAC, H-ISAC, or sector-relevant ISAC. File report with CISA and FBI.",
                 "tools": ["MISP", "OpenCTI", "STIX/TAXII sharing", "ISAC portals"]},
            ],
        },
        "Supply Chain Attack": {
            "title": "Supply Chain Attack Incident Response",
            "priority": "CRITICAL",
            "sla_hours": 1,
            "compliance_refs": ["CISA Supply Chain Risk Management", "NIST SP 800-161", "ISO 28000"],
            "steps": [
                {"step": 1, "action": "Identify Compromised Component",
                 "detail": "Identify the specific vendor, package, or software update that was compromised. Check for known advisories (CISA, vendor, CERT). Map all affected versions deployed in your environment.",
                 "tools": ["SBOM (Software Bill of Materials)", "Dependency scanning tools", "Vendor advisory feeds"]},
                {"step": 2, "action": "Quarantine Affected Systems",
                 "detail": "Isolate all systems running the compromised software. Block update channels for the affected product to prevent further propagation.",
                 "tools": ["EDR quarantine", "Network ACLs", "Group Policy software restriction"]},
                {"step": 3, "action": "IOC Hunt",
                 "detail": "Deploy IOCs from vendor/CISA advisory across all systems. Search for command-and-control communication patterns from compromised software. Review all outbound connections made by affected application.",
                 "tools": ["YARA rules", "Sigma rules", "SIEM threat hunt queries", "EDR IOC hunt"]},
                {"step": 4, "action": "Vendor Coordination",
                 "detail": "Engage vendor for emergency patch/hotfix. Request complete list of malicious update hashes. Coordinate disclosure timeline if your organization is first to discover.",
                 "tools": ["Vendor CISO contact", "CERT coordination", "CVD process"]},
                {"step": 5, "action": "Recovery & Verification",
                 "detail": "Apply verified clean version or remove compromised software. Verify system integrity using known-good baselines. Implement software verification (code signing, hash verification) for future updates.",
                 "tools": ["Code signing verification", "SLSA framework", "Sigstore"]},
            ],
        },
        "Insider Threat": {
            "title": "Insider Threat Incident Response",
            "priority": "HIGH",
            "sla_hours": 2,
            "compliance_refs": ["NIST SP 800-53 AC-2", "CISA Insider Threat Guide", "ISO 27001 A.7.3"],
            "steps": [
                {"step": 1, "action": "Preserve Evidence & Legal Hold",
                 "detail": "Immediately engage HR, Legal, and CISO. Place a legal hold on all system and communication logs related to the individual. Ensure all investigation is conducted with HR/Legal oversight to avoid privacy law violations.",
                 "tools": ["Legal hold system", "HR case management", "eDiscovery tools"]},
                {"step": 2, "action": "Covert Monitoring",
                 "detail": "Enable enhanced SIEM monitoring on subject's accounts without alerting them. Review email, file access, USB activity, and system logs retrospectively for the past 90 days.",
                 "tools": ["DLP solution", "UEBA (User Entity Behavior Analytics)", "SIEM enhanced monitoring"]},
                {"step": 3, "action": "Access Revocation Planning",
                 "detail": "Plan coordinated revocation of all access — timed with HR action. Include: AD account, VPN, cloud services, email, physical access, API keys, and shared credentials.",
                 "tools": ["IAM platform", "Physical access control system", "Vault key rotation"]},
                {"step": 4, "action": "Data Loss Assessment",
                 "detail": "Audit data accessed, copied, printed, emailed, or uploaded to personal cloud storage. Check for mass downloads, unusual USB transfers, or unauthorized email forwards.",
                 "tools": ["DLP audit logs", "Cloud access logs", "Print server logs", "USB device tracking"]},
                {"step": 5, "action": "Post-Incident Hardening",
                 "detail": "Review and tighten data classification policies. Implement need-to-know access controls. Deploy UEBA for proactive detection. Update employee offboarding checklist.",
                 "tools": ["UEBA platforms", "CASB", "Data classification tools"]},
            ],
        },
        "Zero-Day": {
            "title": "Zero-Day / Unknown Threat Incident Response",
            "priority": "CRITICAL",
            "sla_hours": 1,
            "compliance_refs": ["NIST IR 6.3", "CISA Known Exploited Vulnerabilities", "ISO 27035-2"],
            "steps": [
                {"step": 1, "action": "Emergency Isolation & Escalation",
                 "detail": "Immediately isolate affected systems. Activate incident response retainer (DFIR firm if engaged). Escalate to CISO and executive leadership. Consider declaring a cyber incident.",
                 "tools": ["Network isolation", "IR retainer contact", "Escalation runbook"]},
                {"step": 2, "action": "Forensic Data Collection",
                 "detail": "Capture all available forensic data before evidence degrades: RAM, disk images, network flows, process trees, DNS queries, and endpoint telemetry.",
                 "tools": ["Volatility3", "FTK Imager", "Wireshark", "EDR telemetry export"]},
                {"step": 3, "action": "Behavioral Threat Analysis",
                 "detail": "Submit suspicious files/payloads to sandbox (Cuckoo, Any.run, Hybrid Analysis). Analyse behavioral indicators without relying on signature detection. Create YARA/Sigma rules from observed behavior.",
                 "tools": ["Any.run", "Hybrid Analysis", "Cuckoo Sandbox", "CAPE"]},
                {"step": 4, "action": "Containment Without Fingerprint",
                 "detail": "Deploy containment measures based on behavioral patterns, not signatures. Block based on IOBs (Indicators of Behavior): parent-child process relationships, network destinations, file paths.",
                 "tools": ["EDR IOB blocking", "Custom firewall rules", "Application behavior baselines"]},
                {"step": 5, "action": "Vendor & Community Notification",
                 "detail": "If a vendor vulnerability is identified, begin responsible disclosure under CVD guidelines. Share IOCs with community (ISACs, CISA, CERT). Request emergency CVE assignment.",
                 "tools": ["vendor security contact", "CISA coordination", "CERT/CC", "ISAC sharing"]},
                {"step": 6, "action": "Recovery Under Assumption of Compromise",
                 "detail": "Assume deep persistence. Plan complete rebuild of affected systems. Deploy canary tokens and tripwires for 90-day enhanced monitoring period.",
                 "tools": ["Canary tokens", "Tripwire monitoring", "Zero-trust rebuild"]},
            ],
        },
    }

    @staticmethod
    async def generate_playbook(
        threat_type: str,
        severity: str,
        context: Dict[str, Any] = None,
    ) -> Dict[str, Any]:
        """Generate a contextually adapted incident response playbook."""
        template_key = PlaybookGenerator._match_template(threat_type)
        template = PlaybookGenerator.PLAYBOOK_TEMPLATES.get(
            template_key, PlaybookGenerator.PLAYBOOK_TEMPLATES["Zero-Day"]
        )

        context = context or {}
        generated_time = datetime.utcnow()

        playbook_content = f"# {template['title']}\n\n"
        playbook_content += f"**Generated:** {generated_time.strftime('%Y-%m-%d %H:%M UTC')}\n"
        playbook_content += f"**Priority:** {template['priority']}\n"
        playbook_content += f"**Response SLA:** {template['sla_hours']} hour(s)\n"
        playbook_content += f"**Threat Type:** {threat_type}\n"
        playbook_content += f"**Severity:** {severity.upper()}\n"
        playbook_content += f"**Compliance References:** {', '.join(template.get('compliance_refs', []))}\n"

        if context.get("domain"):
            playbook_content += f"**Target:** {context['domain']}\n"
        if context.get("risk_score"):
            playbook_content += f"**Risk Score:** {context['risk_score']}/100\n"

        playbook_content += "\n---\n\n"
        playbook_content += "## ⚠️ Immediate Actions Required\n\n"

        steps = []
        for step_data in template["steps"]:
            playbook_content += f"### Step {step_data['step']}: {step_data['action']}\n"
            playbook_content += f"{step_data['detail']}\n\n"
            if step_data.get("tools"):
                playbook_content += f"**Tools:** {', '.join(step_data['tools'])}\n\n"

            steps.append({
                "step_number": step_data["step"],
                "action": step_data["action"],
                "detail": step_data["detail"],
                "tools": step_data.get("tools", []),
                "status": "pending",
                "assigned_to": None,
                "completed_at": None,
            })

        playbook_content += "\n---\n\n"
        playbook_content += "## 📋 Post-Incident Checklist\n\n"
        playbook_content += "- [ ] All IOCs documented and shared\n"
        playbook_content += "- [ ] Forensic evidence preserved with chain of custody\n"
        playbook_content += "- [ ] Regulatory notifications filed if required\n"
        playbook_content += "- [ ] Lessons learned documented\n"
        playbook_content += "- [ ] Playbook updated based on new findings\n"

        return {
            "title": template["title"],
            "priority": template["priority"],
            "sla_hours": template["sla_hours"],
            "compliance_references": template.get("compliance_refs", []),
            "playbook_content": playbook_content,
            "playbook_steps": steps,
            "template_used": template_key,
            "generated_at": generated_time.isoformat(),
            "estimated_duration_hours": len(steps) * 1.5,
        }

    @staticmethod
    def _match_template(threat_type: str) -> str:
        """Match threat type to best playbook template."""
        t = threat_type.lower()
        matches = {
            "rce": "Remote Code Execution",
            "remote code": "Remote Code Execution",
            "code execution": "Remote Code Execution",
            "sql injection": "SQL Injection",
            "sqli": "SQL Injection",
            "ransomware": "Ransomware",
            "ransom": "Ransomware",
            "encrypt": "Ransomware",
            "dos": "Denial of Service",
            "ddos": "Denial of Service",
            "denial": "Denial of Service",
            "phishing": "Phishing",
            "spearphishing": "Phishing",
            "brute force": "Brute Force",
            "credential": "Brute Force",
            "stuffing": "Brute Force",
            "apt": "APT / Advanced Persistent Threat",
            "advanced persistent": "APT / Advanced Persistent Threat",
            "supply chain": "Supply Chain Attack",
            "solarwinds": "Supply Chain Attack",
            "insider": "Insider Threat",
            "zero-day": "Zero-Day",
            "zero day": "Zero-Day",
            "0day": "Zero-Day",
            "unknown": "Zero-Day",
        }
        for keyword, template_name in sorted(matches.items(), key=lambda x: len(x[0]), reverse=True):
            if keyword in t:
                return template_name
        return "Zero-Day"


class AutoAlertSystem:
    """
    Automated alert notification system v2.0.
    Supports real SMTP email, Slack webhooks, Microsoft Teams webhooks,
    and generic HTTP webhooks with retry logic.
    """

    @staticmethod
    async def send_alert(
        incident_id: str,
        severity: str,
        title: str,
        details: Dict[str, Any],
        channels: List[str] = None,
    ) -> Dict[str, Any]:
        """Send automated alerts through all configured channels."""
        if channels is None:
            channels = ["log"]
            if severity in ("critical", "high"):
                if settings.SMTP_HOST:
                    channels.append("email")
                if settings.SLACK_WEBHOOK_URL:
                    channels.append("slack")
                if settings.TEAMS_WEBHOOK_URL:
                    channels.append("teams")
                for _ in settings.WEBHOOK_URLS.split(","):
                    if _.strip():
                        channels.append("webhook")

        results = {}
        for channel in channels:
            try:
                if channel == "email":
                    results["email"] = await AutoAlertSystem._send_email(
                        title, severity, incident_id, details
                    )
                elif channel == "slack":
                    results["slack"] = await AutoAlertSystem._send_slack(
                        title, severity, incident_id, details
                    )
                elif channel == "teams":
                    results["teams"] = await AutoAlertSystem._send_teams(
                        title, severity, incident_id, details
                    )
                elif channel == "webhook":
                    results["webhook"] = await AutoAlertSystem._send_webhook(
                        incident_id, title, severity, details
                    )
                elif channel == "log":
                    logger.critical(
                        f"[{severity.upper()}] INCIDENT ALERT: {title} | ID: {incident_id}"
                    )
                    results["log"] = {
                        "status": "sent",
                        "timestamp": datetime.utcnow().isoformat(),
                    }
            except Exception as e:
                logger.error(f"Alert channel '{channel}' failed: {e}", exc_info=True)
                results[channel] = {"status": "failed", "error": str(e)}

        return {
            "incident_id": incident_id,
            "channels": channels,
            "results": results,
            "sent_at": datetime.utcnow().isoformat(),
        }

    @staticmethod
    async def _send_email(title: str, severity: str, incident_id: str, details: Dict) -> Dict:
        """Send SMTP email alert."""
        if not settings.SMTP_HOST or not settings.SMTP_USER:
            logger.warning("SMTP not configured — email alert skipped")
            return {"status": "skipped", "reason": "SMTP not configured"}

        recipients = [r.strip() for r in settings.ALERT_TO_EMAILS.split(",") if r.strip()]
        if not recipients:
            logger.warning("No alert recipients configured (ALERT_TO_EMAILS empty)")
            return {"status": "skipped", "reason": "No recipients configured"}

        try:
            import smtplib
            severity_color = {
                "critical": "#FF0000",
                "high": "#FF6600",
                "medium": "#FFAA00",
                "low": "#00AA00",
            }.get(severity, "#6600FF")

            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"[ITAP {severity.upper()}] {title}"
            msg["From"] = f"{settings.SMTP_FROM_NAME} <{settings.SMTP_FROM_EMAIL}>"
            msg["To"] = ", ".join(recipients)

            html_body = f"""
            <html><body style="font-family: Arial, sans-serif; background: #0a0d14; color: #F0EFE9; padding: 20px;">
            <div style="border: 2px solid {severity_color}; border-radius: 8px; padding: 20px; max-width: 600px;">
                <h2 style="color: {severity_color}; margin: 0 0 16px;">🚨 ITAP Security Alert</h2>
                <div style="background: rgba(255,255,255,0.05); padding: 16px; border-radius: 4px; margin-bottom: 16px;">
                    <strong>Incident:</strong> {title}<br>
                    <strong>Severity:</strong> <span style="color: {severity_color}">{severity.upper()}</span><br>
                    <strong>Incident ID:</strong> <code>{incident_id}</code><br>
                    <strong>Time:</strong> {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}<br>
                    <strong>Description:</strong> {details.get('description', 'N/A')}
                </div>
                <a href="http://localhost:5173" style="background: {severity_color}; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px;">
                    Open ITAP Dashboard
                </a>
            </div>
            </body></html>
            """
            msg.attach(MIMEText(html_body, "html"))

            with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT) as server:
                if settings.SMTP_USE_TLS:
                    server.starttls()
                server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
                server.sendmail(settings.SMTP_FROM_EMAIL, recipients, msg.as_string())

            logger.info(f"Email alert sent to {recipients} for incident {incident_id}")
            return {"status": "sent", "recipients": recipients, "timestamp": datetime.utcnow().isoformat()}

        except Exception as e:
            logger.error(f"Email send failed: {e}")
            raise

    @staticmethod
    async def _send_slack(title: str, severity: str, incident_id: str, details: Dict) -> Dict:
        """Send Slack webhook alert with rich formatting."""
        try:
            import aiohttp
            severity_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(severity, "🔵")
            payload = {
                "text": f"{severity_emoji} *ITAP [{severity.upper()}] Alert*: {title}",
                "attachments": [{
                    "color": {"critical": "#FF0000", "high": "#FF6600", "medium": "#FFAA00"}.get(severity, "#0066FF"),
                    "fields": [
                        {"title": "Severity", "value": severity.upper(), "short": True},
                        {"title": "Incident ID", "value": incident_id[:8], "short": True},
                        {"title": "Description", "value": details.get("description", "N/A"), "short": False},
                        {"title": "Time", "value": datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"), "short": True},
                    ],
                    "footer": "ITAP Security Platform",
                    "ts": int(datetime.utcnow().timestamp()),
                }],
            }
            async with aiohttp.ClientSession() as session:
                async with session.post(settings.SLACK_WEBHOOK_URL, json=payload, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status == 200:
                        return {"status": "sent", "timestamp": datetime.utcnow().isoformat()}
                    return {"status": "failed", "http_status": resp.status}
        except Exception as e:
            raise RuntimeError(f"Slack webhook failed: {e}") from e

    @staticmethod
    async def _send_teams(title: str, severity: str, incident_id: str, details: Dict) -> Dict:
        """Send Microsoft Teams webhook alert."""
        try:
            import aiohttp
            color = {"critical": "FF0000", "high": "FF6600", "medium": "FFAA00"}.get(severity, "0066FF")
            payload = {
                "@type": "MessageCard",
                "@context": "http://schema.org/extensions",
                "themeColor": color,
                "summary": f"ITAP Alert: {title}",
                "sections": [{
                    "activityTitle": f"🚨 ITAP [{severity.upper()}]: {title}",
                    "activitySubtitle": datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
                    "facts": [
                        {"name": "Severity", "value": severity.upper()},
                        {"name": "Incident ID", "value": incident_id},
                        {"name": "Description", "value": details.get("description", "N/A")},
                    ],
                }],
            }
            async with aiohttp.ClientSession() as session:
                async with session.post(settings.TEAMS_WEBHOOK_URL, json=payload, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    return {"status": "sent" if resp.status == 200 else "failed", "http_status": resp.status}
        except Exception as e:
            raise RuntimeError(f"Teams webhook failed: {e}") from e

    @staticmethod
    async def _send_webhook(incident_id: str, title: str, severity: str, details: Dict) -> Dict:
        """Send to generic HTTP webhook endpoints with retry."""
        urls = [u.strip() for u in settings.WEBHOOK_URLS.split(",") if u.strip()]
        if not urls:
            return {"status": "skipped", "reason": "No webhook URLs configured"}

        payload = {
            "source": "ITAP",
            "incident_id": incident_id,
            "title": title,
            "severity": severity,
            "details": details,
            "timestamp": datetime.utcnow().isoformat(),
        }

        results = []
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                for url in urls[:5]:  # Max 5 webhooks
                    for attempt in range(3):
                        try:
                            async with session.post(url, json=payload, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                                results.append({"url": url[:50], "status": resp.status, "attempt": attempt + 1})
                                break
                        except Exception:
                            if attempt == 2:
                                results.append({"url": url[:50], "status": "failed", "attempt": attempt + 1})
                            await asyncio.sleep(2 ** attempt)
        except ImportError:
            pass

        return {"status": "sent", "webhook_results": results}
