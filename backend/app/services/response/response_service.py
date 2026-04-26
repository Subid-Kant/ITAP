"""
ITAP — Autonomous Response & Playbook Engine
Layer 4: LLM-based playbook generation, auto-alerting, 
SIEM integration, and remediation tracking.
"""
import random
from datetime import datetime
from typing import Dict, Any, List, Optional
import logging

logger = logging.getLogger("itap.response")


class PlaybookGenerator:
    """
    LLM-based Incident Response Playbook Generator.
    Generates step-by-step remediation playbooks in natural language
    based on detected threat type, severity, and context.
    
    In production, uses a fine-tuned LLM (HuggingFace Transformers).
    Demo uses comprehensive template-based generation.
    """
    
    PLAYBOOK_TEMPLATES = {
        "Remote Code Execution": {
            "title": "Remote Code Execution (RCE) Incident Response",
            "priority": "CRITICAL",
            "steps": [
                {"step": 1, "action": "Immediate Isolation", "detail": "Isolate the affected system from the network immediately. Disconnect from both internal network and internet. Do NOT power off — preserve volatile memory for forensics."},
                {"step": 2, "action": "Capture Forensic Evidence", "detail": "Take a memory dump using tools like WinPMem or LiME. Capture network logs (pcap) from the time window. Screenshot active processes and network connections."},
                {"step": 3, "action": "Identify the Attack Vector", "detail": "Review web server access logs for suspicious requests. Check for encoded payloads in URL parameters, POST bodies, or HTTP headers. Identify the vulnerable endpoint and CVE if applicable."},
                {"step": 4, "action": "Contain the Threat", "detail": "Block the attacker IP at firewall level. Revoke any compromised credentials. Disable the vulnerable service or apply a virtual patch (WAF rule)."},
                {"step": 5, "action": "Assess Impact", "detail": "Determine if exfiltration occurred by reviewing outbound traffic. Check for persistence mechanisms (cron jobs, services, registry keys). Scan for lateral movement indicators."},
                {"step": 6, "action": "Remediate", "detail": "Apply the security patch for the identified CVE. Harden the service configuration. Deploy additional WAF rules for the attack pattern."},
                {"step": 7, "action": "Recovery & Monitoring", "detail": "Restore from clean backup if system integrity is compromised. Re-enable services with enhanced monitoring. Set up alerting for the specific attack signature."},
                {"step": 8, "action": "Post-Incident Review", "detail": "Document timeline, impact, and root cause. Update incident playbooks. Conduct a blameless retrospective within 48 hours."}
            ]
        },
        "SQL Injection": {
            "title": "SQL Injection Attack Response",
            "priority": "HIGH",
            "steps": [
                {"step": 1, "action": "Identify Injection Point", "detail": "Review web application logs to identify the vulnerable parameter. Check for UNION, OR 1=1, DROP, and other SQL keywords in request logs."},
                {"step": 2, "action": "Block Attacker", "detail": "Block the attacker's IP address at WAF/firewall level. Enable SQL injection rule sets in your WAF (OWASP CRS)."},
                {"step": 3, "action": "Assess Data Exposure", "detail": "Determine if any data was exfiltrated. Check database query logs for unauthorized SELECT statements. Review for data modification (UPDATE/DELETE/INSERT)."},
                {"step": 4, "action": "Patch the Application", "detail": "Replace dynamic SQL queries with parameterised queries/prepared statements. Implement input validation and output encoding. Apply principle of least privilege to database accounts."},
                {"step": 5, "action": "Database Integrity Check", "detail": "Verify database integrity against known-good backups. Check for backdoor accounts created via injection. Audit stored procedures for modifications."},
                {"step": 6, "action": "Notify & Document", "detail": "If PII was exposed, initiate data breach notification procedures. Document all findings and remediation steps. Update security testing to include SQLi checks."}
            ]
        },
        "Denial of Service": {
            "title": "DDoS / Denial of Service Response",
            "priority": "HIGH",
            "steps": [
                {"step": 1, "action": "Activate DDoS Protection", "detail": "Enable DDoS mitigation services (CloudFlare, AWS Shield, etc.). Activate rate limiting on edge servers. Enable GeoIP blocking for suspicious source regions."},
                {"step": 2, "action": "Analyse Attack Pattern", "detail": "Identify attack type: volumetric, protocol, or application layer. Capture sample traffic for analysis. Determine source IP ranges and ASNs."},
                {"step": 3, "action": "Implement Mitigation", "detail": "Configure scrubbing rules based on attack signature. Blackhole route if necessary. Scale infrastructure to absorb traffic."},
                {"step": 4, "action": "Communication", "detail": "Notify ISP/hosting provider. Update status page for affected services. Inform stakeholders of impact and ETA."},
                {"step": 5, "action": "Post-Attack Hardening", "detail": "Review and update DDoS response plan. Implement anycast if not already in use. Deploy additional edge nodes for resilience."}
            ]
        },
        "Phishing": {
            "title": "Phishing Campaign Response",
            "priority": "HIGH",
            "steps": [
                {"step": 1, "action": "Identify Scope", "detail": "Determine how many users received the phishing email. Check email gateway logs for the sender/subject/attachment hash. Identify who clicked the link or opened the attachment."},
                {"step": 2, "action": "Contain", "detail": "Block the phishing domain/URL at DNS and proxy level. Quarantine the email from all mailboxes. Block the sender address and domain."},
                {"step": 3, "action": "Credential Reset", "detail": "Force password reset for all affected users. Revoke active sessions and OAuth tokens. Enable MFA if not already enforced."},
                {"step": 4, "action": "Endpoint Check", "detail": "Scan endpoints of users who clicked for malware. Check for persistence mechanisms. Review for data exfiltration."},
                {"step": 5, "action": "Awareness", "detail": "Send organisation-wide alert about the campaign. Conduct targeted security awareness training. Update phishing simulation program."}
            ]
        },
        "Brute Force": {
            "title": "Brute Force / Credential Attack Response",
            "priority": "MEDIUM",
            "steps": [
                {"step": 1, "action": "Block Source IPs", "detail": "Immediately block attacking IP addresses at firewall/WAF level. Review failed authentication logs to identify all source IPs."},
                {"step": 2, "action": "Account Lockout Review", "detail": "Check which accounts were targeted. Lock any accounts showing successful compromise. Force password reset on targeted accounts."},
                {"step": 3, "action": "Strengthen Authentication", "detail": "Enforce MFA on all targeted services. Implement account lockout policies (e.g., 5 failed attempts). Deploy CAPTCHAs on login forms."},
                {"step": 4, "action": "Monitor", "detail": "Set up enhanced monitoring for the targeted service. Deploy fail2ban or equivalent. Review for any successful logins from suspicious IPs."}
            ]
        },
        "Zero-Day": {
            "title": "Zero-Day / Unknown Threat Response",
            "priority": "CRITICAL",
            "steps": [
                {"step": 1, "action": "Emergency Isolation", "detail": "Immediately isolate affected systems. Activate incident response team. Escalate to CSIRT/management."},
                {"step": 2, "action": "Threat Analysis", "detail": "Capture all available forensic data. Analyse the unknown pattern using sandbox environment. Document behavioral indicators for signature creation."},
                {"step": 3, "action": "Containment", "detail": "Deploy network segmentation to limit blast radius. Block all associated IOCs. Monitor for lateral movement."},
                {"step": 4, "action": "Vendor Notification", "detail": "If a product vulnerability is suspected, notify the vendor. Request CVE assignment. Share IOCs with threat intelligence sharing communities (ISACs)."},
                {"step": 5, "action": "Custom Detection", "detail": "Create custom IDS/IPS signatures based on observed behavior. Deploy YARA rules for file-based detection. Update SIEM with new correlation rules."},
                {"step": 6, "action": "Recovery Planning", "detail": "Plan recovery with assumption of persistence. Rebuild affected systems from known-good images. Enhanced monitoring for 90 days."}
            ]
        }
    }
    
    @staticmethod
    async def generate_playbook(
        threat_type: str,
        severity: str,
        context: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """Generate an incident response playbook."""
        
        # Match threat to best template
        template_key = PlaybookGenerator._match_template(threat_type)
        template = PlaybookGenerator.PLAYBOOK_TEMPLATES.get(template_key, 
            PlaybookGenerator.PLAYBOOK_TEMPLATES["Zero-Day"])
        
        # Contextualise the playbook
        playbook_content = f"# {template['title']}\n\n"
        playbook_content += f"**Priority:** {template['priority']}\n"
        playbook_content += f"**Threat Type:** {threat_type}\n"
        playbook_content += f"**Severity:** {severity}\n"
        playbook_content += f"**Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}\n\n"
        
        if context:
            playbook_content += f"**Context:** Target: {context.get('domain', 'N/A')}, "
            playbook_content += f"Risk Score: {context.get('risk_score', 'N/A')}\n\n"
        
        playbook_content += "---\n\n"
        
        steps = []
        for step in template["steps"]:
            playbook_content += f"### Step {step['step']}: {step['action']}\n"
            playbook_content += f"{step['detail']}\n\n"
            steps.append({
                "step_number": step["step"],
                "action": step["action"],
                "detail": step["detail"],
                "status": "pending"
            })
        
        return {
            "title": template["title"],
            "priority": template["priority"],
            "playbook_content": playbook_content,
            "playbook_steps": steps,
            "generated_at": datetime.utcnow().isoformat(),
            "template_used": template_key
        }
    
    @staticmethod
    def _match_template(threat_type: str) -> str:
        """Match threat type to best playbook template."""
        threat_lower = threat_type.lower()
        
        mapping = {
            "rce": "Remote Code Execution",
            "remote code": "Remote Code Execution",
            "sql injection": "SQL Injection",
            "sqli": "SQL Injection",
            "dos": "Denial of Service",
            "ddos": "Denial of Service",
            "denial": "Denial of Service",
            "phishing": "Phishing",
            "spearphishing": "Phishing",
            "brute force": "Brute Force",
            "credential": "Brute Force",
            "zero-day": "Zero-Day",
            "zero day": "Zero-Day",
            "unknown": "Zero-Day",
        }
        
        for keyword, template_name in mapping.items():
            if keyword in threat_lower:
                return template_name
        
        return "Zero-Day"


class AutoAlertSystem:
    """
    Automated alert notification system.
    Sends alerts via Email, Webhook, and logs.
    """
    
    @staticmethod
    async def send_alert(
        incident_id: str,
        severity: str,
        title: str,
        details: Dict[str, Any],
        channels: List[str] = None
    ) -> Dict[str, Any]:
        """Send automated alerts through configured channels."""
        if channels is None:
            channels = ["log"]
            if severity in ["critical", "high"]:
                channels.extend(["email", "webhook"])
        
        results = {}
        for channel in channels:
            try:
                if channel == "email":
                    results["email"] = await AutoAlertSystem._send_email_alert(title, details)
                elif channel == "webhook":
                    results["webhook"] = await AutoAlertSystem._send_webhook_alert(incident_id, title, details)
                elif channel == "log":
                    logger.warning(f"ALERT [{severity.upper()}]: {title} - Incident {incident_id}")
                    results["log"] = {"status": "sent", "timestamp": datetime.utcnow().isoformat()}
            except Exception as e:
                results[channel] = {"status": "failed", "error": str(e)}
        
        return {
            "incident_id": incident_id,
            "channels": channels,
            "results": results,
            "sent_at": datetime.utcnow().isoformat()
        }
    
    @staticmethod
    async def _send_email_alert(title: str, details: Dict) -> Dict:
        """Send email alert (demo - logs instead of sending)."""
        logger.info(f"EMAIL ALERT: {title}")
        return {"status": "sent", "method": "email", "timestamp": datetime.utcnow().isoformat()}
    
    @staticmethod
    async def _send_webhook_alert(incident_id: str, title: str, details: Dict) -> Dict:
        """Send webhook alert (demo - logs instead of sending)."""
        logger.info(f"WEBHOOK ALERT: {incident_id} - {title}")
        return {"status": "sent", "method": "webhook", "timestamp": datetime.utcnow().isoformat()}
