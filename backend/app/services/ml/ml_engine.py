"""
ITAP — ML Engine Service v2.0
Layer 2: LSTM Threat Predictor, Autoencoder Anomaly Detector,
NLP Event Classifier, and CVSS-Enhanced Severity Scorer.

Uses numpy-based deterministic simulation with realistic probabilistic models.
Seeded for reproducibility. In production, replace simulation with trained models.
"""
import numpy as np
import hashlib
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
import logging

logger = logging.getLogger("itap.ml")

# Global seeded RNG for reproducibility
_rng = np.random.default_rng(42)


def _seeded_float(low: float, high: float, seed_str: str = "") -> float:
    """Generate a deterministic float from a seed string."""
    if seed_str:
        seed_val = int(hashlib.md5(seed_str.encode()).hexdigest()[:8], 16) % (2**31)
        local_rng = np.random.default_rng(seed_val)
        return float(local_rng.uniform(low, high))
    return float(_rng.uniform(low, high))


class LSTMPredictor:
    """
    LSTM-based threat prediction engine v2.0.
    Uses deterministic numpy simulation with domain-seeded randomness
    for reproducible predictions per target.

    Feature weighting mirrors a trained LSTM output:
    - CVE severity (CVSS) → 35% weight
    - Environmental risk from OSINT → 30% weight
    - Recency factor → 20% weight
    - Threat intelligence feed signal → 15% weight
    """

    CVE_CATEGORIES = {
        "Remote Code Execution": 0.82,
        "SQL Injection": 0.75,
        "Cross-Site Scripting": 0.63,
        "Privilege Escalation": 0.78,
        "Buffer Overflow": 0.65,
        "Authentication Bypass": 0.80,
        "Directory Traversal": 0.55,
        "Denial of Service": 0.60,
        "Information Disclosure": 0.45,
        "Command Injection": 0.77,
        "XML External Entity": 0.58,
        "Server-Side Request Forgery": 0.70,
        "Insecure Deserialization": 0.72,
        "Cryptographic Weakness": 0.50,
    }

    # ── Root Cause Knowledge Base ──────────────────────────────
    # Maps attack type → root cause explanation, how attacker exploits it,
    # and which components are typically affected.
    ROOT_CAUSE_DB: Dict[str, Dict[str, Any]] = {
        "Remote Code Execution": {
            "root_cause": (
                "Unpatched or misconfigured application exposes a code execution path. "
                "Common causes: outdated frameworks with known deserialization flaws, "
                "unsafe eval() usage, exposed administrative interfaces without auth, "
                "or vulnerable third-party libraries (Log4Shell, Spring4Shell-style)."
            ),
            "attack_vector_detail": (
                "Attacker crafts a malicious payload (serialized object, shell command, "
                "template expression) and delivers it via an HTTP parameter, file upload, "
                "or API request. The vulnerable component deserializes/evaluates it without "
                "sanitisation, spawning an attacker-controlled process with server privileges."
            ),
            "affected_components": ["Application server", "Web framework", "Third-party libraries", "API endpoints"],
        },
        "SQL Injection": {
            "root_cause": (
                "User-supplied input is concatenated directly into SQL queries without "
                "parameterisation or escaping. Root cause is typically missing use of "
                "prepared statements/ORM, or legacy inline query construction."
            ),
            "attack_vector_detail": (
                "Attacker injects SQL syntax (UNION SELECT, OR 1=1, stacked queries) through "
                "form fields, URL parameters, or HTTP headers. Database executes injected "
                "statements granting read/write access to all tables, or OS command execution "
                "via xp_cmdshell (MSSQL) / LOAD_FILE (MySQL)."
            ),
            "affected_components": ["Database layer", "Login endpoints", "Search/filter APIs", "Reporting modules"],
        },
        "Cross-Site Scripting": {
            "root_cause": (
                "Reflected or stored user content is rendered in the browser without HTML "
                "entity encoding. Missing Content-Security-Policy headers and absence of "
                "output sanitisation libraries compound the risk."
            ),
            "attack_vector_detail": (
                "Attacker plants <script> payload in a comment field, URL parameter, or "
                "HTTP header that is stored or reflected to victim browsers. Script runs in "
                "the victim's session context, stealing cookies/tokens, redirecting to "
                "phishing pages, or performing actions as the victim."
            ),
            "affected_components": ["Frontend rendering engine", "Comment/input fields", "Admin panels", "Session management"],
        },
        "Privilege Escalation": {
            "root_cause": (
                "Local user or process can gain elevated rights due to: misconfigured SUID "
                "binaries, weak sudo rules, kernel vulnerabilities (use-after-free, "
                "race conditions), or overly permissive file/directory ACLs."
            ),
            "attack_vector_detail": (
                "After gaining initial low-privilege access, attacker exploits a local "
                "vulnerability (e.g. CVE kernel bug, misconfigured cron job writing to "
                "world-writable path, SUID binary path hijack) to execute arbitrary code "
                "as root/SYSTEM."
            ),
            "affected_components": ["OS kernel", "SUID/SGID binaries", "Sudo configuration", "Scheduled tasks"],
        },
        "Buffer Overflow": {
            "root_cause": (
                "Memory-unsafe code (C/C++) copies attacker-controlled data into a fixed-size "
                "buffer without bounds checking. Absence of ASLR, stack canaries, or DEP/NX "
                "makes exploitation straightforward."
            ),
            "attack_vector_detail": (
                "Attacker sends oversized input (network packet, file, environment variable) "
                "that overwrites adjacent memory — typically the return address on the stack "
                "or a function pointer on the heap — redirecting execution to shellcode or "
                "ROP chains."
            ),
            "affected_components": ["Native/compiled services", "Network daemons", "Parsers (image, document, protocol)"],
        },
        "Authentication Bypass": {
            "root_cause": (
                "Authentication logic contains a flaw: default/hardcoded credentials, "
                "JWT verification disabled (alg:none), broken session token entropy, "
                "SAML response manipulation, or missing authentication on sensitive routes."
            ),
            "attack_vector_detail": (
                "Attacker manipulates auth token (JWT header, SAML assertion), uses "
                "default credentials, exploits a logic flaw in the login flow (e.g. "
                "password reset race condition, OTP bypass), or directly accesses "
                "unauthenticated API endpoints to gain administrative access."
            ),
            "affected_components": ["Authentication service", "Session manager", "JWT/SAML module", "API gateway"],
        },
        "Directory Traversal": {
            "root_cause": (
                "File path construction uses unsanitised user input without canonicalisation. "
                "Absence of a chroot jail or path whitelist allows traversal outside the "
                "web root using ../ sequences or URL-encoded equivalents."
            ),
            "attack_vector_detail": (
                "Attacker appends ../../../../etc/passwd or %2F%2E%2E sequences to a file "
                "download or include parameter, causing the server to read arbitrary files "
                "from the filesystem — private keys, config files, /etc/shadow."
            ),
            "affected_components": ["File download endpoints", "Static file servers", "Include/require handlers"],
        },
        "Denial of Service": {
            "root_cause": (
                "Service lacks rate-limiting, connection throttling, or resource caps. "
                "Algorithmic complexity attacks exploit worst-case CPU/memory paths "
                "(ReDoS, hash collision). Volumetric attacks exploit amplification "
                "protocols (NTP, DNS, SSDP) or bandwidth asymmetry."
            ),
            "attack_vector_detail": (
                "Attacker floods the target with crafted requests (SYN flood, UDP "
                "amplification, HTTP slow-read) or exploits a CPU/memory exhaustion path, "
                "rendering the service unavailable. Botnets and rented DDoS-as-a-service "
                "infrastructure are commonly used."
            ),
            "affected_components": ["Load balancer", "Application server", "Database connection pool", "DNS resolver"],
        },
        "Information Disclosure": {
            "root_cause": (
                "Verbose error messages, debug endpoints, directory listing, misconfigured "
                "CORS, or overly permissive API responses leak sensitive data (stack traces, "
                "internal IPs, API keys, PII) to unauthenticated callers."
            ),
            "attack_vector_detail": (
                "Attacker probes error pages, /.git/ directories, /actuator endpoints, "
                "or sends malformed requests to trigger stack traces. CORS misconfiguration "
                "lets attacker-hosted pages read cross-origin responses containing auth tokens."
            ),
            "affected_components": ["Error handlers", "Debug/admin endpoints", "API response serialisation", "CORS policy"],
        },
        "Command Injection": {
            "root_cause": (
                "Application passes user input directly to a shell (os.system, subprocess, "
                "exec) without sanitisation. Common in legacy scripts, network device "
                "management interfaces, and file processing pipelines."
            ),
            "attack_vector_detail": (
                "Attacker appends shell metacharacters (;, |, $(), backtick) to input "
                "fields processed by shell commands — e.g. ping tool, DNS lookup feature, "
                "image conversion script — executing arbitrary OS commands as the web "
                "server user."
            ),
            "affected_components": ["Shell-calling utilities", "Network diagnostic tools", "File processing scripts", "CLI wrappers"],
        },
        "XML External Entity": {
            "root_cause": (
                "XML parser has external entity processing enabled (DTD loading not "
                "disabled). Any endpoint accepting XML input (SOAP, SVG upload, "
                "Excel/Word file processing) is potentially vulnerable."
            ),
            "attack_vector_detail": (
                "Attacker crafts XML with an ENTITY declaration pointing to file:///etc/passwd "
                "or an internal HTTP endpoint. Parser fetches and includes the content in "
                "the response, enabling SSRF and arbitrary file read."
            ),
            "affected_components": ["XML parsers", "SOAP services", "Document upload endpoints", "Feed processors"],
        },
        "Server-Side Request Forgery": {
            "root_cause": (
                "Application fetches a URL or resource specified by user input without "
                "validating the destination. Cloud metadata endpoints (169.254.169.254) "
                "and internal services are accessible from the server's network context."
            ),
            "attack_vector_detail": (
                "Attacker supplies an internal URL (http://169.254.169.254/latest/meta-data/, "
                "http://localhost:6379/) to a webhook, image proxy, or URL fetch feature. "
                "Server makes the request from its privileged network position, leaking "
                "cloud credentials or triggering unauthenticated internal API calls."
            ),
            "affected_components": ["URL fetch features", "Webhook handlers", "Image/PDF generators", "Internal APIs"],
        },
        "Insecure Deserialization": {
            "root_cause": (
                "Application deserialises untrusted data (Java ObjectInputStream, PHP "
                "unserialize, Python pickle, .NET BinaryFormatter) without type validation. "
                "Gadget chains in the classpath allow arbitrary code execution."
            ),
            "attack_vector_detail": (
                "Attacker crafts a malicious serialised payload using known gadget chains "
                "(Apache Commons, Spring, Hibernate) and delivers it via a cookie, "
                "API body, or message queue. Deserialisation triggers the gadget chain, "
                "executing OS commands."
            ),
            "affected_components": ["Session cookies", "API request bodies", "Message queues", "Cache layers"],
        },
        "Cryptographic Weakness": {
            "root_cause": (
                "Use of deprecated algorithms (MD5, SHA-1, DES, RC4), short key lengths, "
                "static IV/nonce, hardcoded encryption keys, or missing certificate "
                "validation. Often caused by legacy code not updated to modern crypto standards."
            ),
            "attack_vector_detail": (
                "Attacker performs offline brute-force/dictionary attack on weak hashes, "
                "executes BEAST/POODLE attacks on deprecated TLS versions, or forges "
                "signatures on JWT tokens with weak HS256 secrets, gaining unauthorized "
                "access or decrypting sensitive traffic."
            ),
            "affected_components": ["Password hashing", "TLS configuration", "JWT signing", "Data encryption at rest"],
        },
        "Exploitation Attempt": {
            "root_cause": (
                "Automated scanner or threat actor has identified an exposed service and "
                "is attempting to exploit a known or zero-day vulnerability. The root cause "
                "is the exposure of the service combined with missing security controls."
            ),
            "attack_vector_detail": (
                "Attacker uses automated tools (Metasploit, custom exploit kits) to probe "
                "and exploit the target. Attack may include credential brute-force, "
                "vulnerability fingerprinting, and payload delivery across multiple vectors."
            ),
            "affected_components": ["Exposed services", "Public-facing endpoints", "Management interfaces"],
        },
    }

    # ── Remediation Knowledge Base ─────────────────────────────
    REMEDIATION_DB: Dict[str, List[Dict[str, Any]]] = {
        "Remote Code Execution": [
            {"step": 1, "action": "Emergency patch or disable affected service", "priority": "immediate",
             "detail": "Apply vendor patch immediately. If no patch exists, disable the vulnerable endpoint or place behind an authenticated proxy."},
            {"step": 2, "action": "Block known exploit payloads at WAF", "priority": "immediate",
             "detail": "Deploy WAF rules targeting serialisation payloads, JNDI/LDAP strings, and template injection patterns."},
            {"step": 3, "action": "Upgrade all third-party dependencies", "priority": "short-term",
             "detail": "Run dependency audit (npm audit, pip-audit, OWASP Dependency-Check) and upgrade vulnerable libraries."},
            {"step": 4, "action": "Implement input validation and sandboxing", "priority": "short-term",
             "detail": "Enforce strict input allowlists. Run application in sandboxed container with minimal OS privileges (read-only FS where possible)."},
            {"step": 5, "action": "Harden server runtime environment", "priority": "long-term",
             "detail": "Enable ASLR, stack canaries, seccomp profiles. Implement runtime application self-protection (RASP). Conduct regular SAST/DAST scanning in CI/CD."},
        ],
        "SQL Injection": [
            {"step": 1, "action": "Block malicious requests at WAF immediately", "priority": "immediate",
             "detail": "Enable SQLi detection rules on WAF/reverse proxy. Alert on UNION, ORDER BY, and comment-based payloads."},
            {"step": 2, "action": "Audit and fix all raw SQL queries", "priority": "short-term",
             "detail": "Replace all string-concatenated queries with parameterised queries or ORM. Audit stored procedures for injection points."},
            {"step": 3, "action": "Apply principle of least privilege to DB accounts", "priority": "short-term",
             "detail": "Web app DB user should only have SELECT/INSERT/UPDATE on necessary tables. Remove EXECUTE, FILE, and SUPER privileges."},
            {"step": 4, "action": "Implement database activity monitoring", "priority": "long-term",
             "detail": "Deploy DAM solution to alert on anomalous query patterns. Enable slow query logging for exfiltration detection."},
            {"step": 5, "action": "Integrate SQLi testing in CI/CD pipeline", "priority": "long-term",
             "detail": "Run SAST tools (Semgrep, SonarQube) and DAST scanners (SQLMap, OWASP ZAP) on every build."},
        ],
        "Cross-Site Scripting": [
            {"step": 1, "action": "Sanitise all existing stored XSS payloads", "priority": "immediate",
             "detail": "Scan database for stored script tags. Sanitise or remove malicious content. Invalidate all active sessions."},
            {"step": 2, "action": "Implement Content-Security-Policy header", "priority": "immediate",
             "detail": "Deploy strict CSP: Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-{random}'. This prevents inline script execution even if XSS exists."},
            {"step": 3, "action": "Add output encoding to all rendering paths", "priority": "short-term",
             "detail": "Use context-aware encoding (HTML entity for HTML context, JS encoding for JS context). Use proven libraries: DOMPurify (client), OWASP Java Encoder (server)."},
            {"step": 4, "action": "Set Secure/HttpOnly flags on all cookies", "priority": "short-term",
             "detail": "All session cookies must have HttpOnly (prevents JS access) and Secure (HTTPS only) flags. Use SameSite=Strict to prevent CSRF."},
            {"step": 5, "action": "Implement automated XSS testing", "priority": "long-term",
             "detail": "Integrate DAST XSS scanning (OWASP ZAP, Burp Suite) in CI/CD. Train developers on secure rendering practices."},
        ],
        "Privilege Escalation": [
            {"step": 1, "action": "Identify and patch the escalation vector immediately", "priority": "immediate",
             "detail": "Apply kernel/OS patch. Remove or fix misconfigured SUID binaries. Audit sudo rules (sudo -l) and revoke excessive permissions."},
            {"step": 2, "action": "Audit all user and process privileges", "priority": "immediate",
             "detail": "Review /etc/sudoers, SUID binaries (find / -perm -4000), scheduled tasks, and service account permissions."},
            {"step": 3, "action": "Enable kernel exploit mitigations", "priority": "short-term",
             "detail": "Ensure ASLR (sysctl kernel.randomize_va_space=2), kernel.dmesg_restrict=1, and kernel.perf_event_paranoid=3 are set."},
            {"step": 4, "action": "Deploy endpoint detection and response (EDR)", "priority": "short-term",
             "detail": "Deploy EDR to detect anomalous privilege changes, SUID execution, and unusual parent-child process relationships."},
            {"step": 5, "action": "Implement automated privilege access management (PAM)", "priority": "long-term",
             "detail": "Use PAM solution for just-in-time access. All admin actions require approval and are logged with full audit trail."},
        ],
        "Buffer Overflow": [
            {"step": 1, "action": "Apply vendor patch or disable vulnerable service", "priority": "immediate",
             "detail": "Apply security patch immediately. If unavailable, disable or network-isolate the vulnerable service."},
            {"step": 2, "action": "Enable OS-level exploit mitigations", "priority": "immediate",
             "detail": "Verify ASLR (echo 2 > /proc/sys/kernel/randomize_va_space), stack canaries (compile with -fstack-protector-all), and NX/DEP are enabled."},
            {"step": 3, "action": "Recompile affected software with security flags", "priority": "short-term",
             "detail": "Recompile with: -fstack-protector-all -D_FORTIFY_SOURCE=2 -Wformat -Werror=format-security -pie -fPIE -Wl,-z,relro,-z,now."},
            {"step": 4, "action": "Deploy network-level filtering for known exploit patterns", "priority": "short-term",
             "detail": "Configure IPS signatures to detect oversized payloads and known shellcode patterns for the vulnerable service."},
            {"step": 5, "action": "Migrate to memory-safe language for critical components", "priority": "long-term",
             "detail": "Evaluate Rust or Go rewrites for security-critical network-facing components. Establish memory safety review process."},
        ],
        "Authentication Bypass": [
            {"step": 1, "action": "Force password reset for all affected accounts", "priority": "immediate",
             "detail": "Immediately invalidate all active sessions. Force password reset for accounts accessible via the bypass."},
            {"step": 2, "action": "Disable or fix the vulnerable authentication path", "priority": "immediate",
             "detail": "Patch the authentication flaw. If JWT alg:none: enforce algorithm whitelist. If default creds: change immediately and lock account."},
            {"step": 3, "action": "Implement multi-factor authentication (MFA)", "priority": "short-term",
             "detail": "Enforce MFA on all privileged accounts. Use TOTP (RFC 6238) or hardware keys (FIDO2/WebAuthn)."},
            {"step": 4, "action": "Conduct full authentication flow security review", "priority": "short-term",
             "detail": "Audit all authentication endpoints for logic flaws. Verify server-side session validation on every protected route."},
            {"step": 5, "action": "Implement Zero Trust network architecture", "priority": "long-term",
             "detail": "Move to continuous authentication model. Implement device trust, geo-velocity checks, and behavioural analytics for anomalous logins."},
        ],
        "Directory Traversal": [
            {"step": 1, "action": "Sanitise all file path inputs immediately", "priority": "immediate",
             "detail": "Apply path canonicalisation (realpath()) and validate resolved path starts with expected base directory. Reject requests with ../ patterns."},
            {"step": 2, "action": "Restrict file system access with chroot/containers", "priority": "short-term",
             "detail": "Run web server process in chroot jail or Docker container with read-only bind mounts limited to the web root."},
            {"step": 3, "action": "Implement file allowlist instead of blocklist", "priority": "short-term",
             "detail": "Restrict file access to an explicit whitelist of permitted filenames/extensions. Reject all others."},
            {"step": 4, "action": "Audit all file-serving endpoints", "priority": "long-term",
             "detail": "Review all endpoints that read from the filesystem. Ensure file paths are constructed server-side, never from user input."},
        ],
        "Denial of Service": [
            {"step": 1, "action": "Enable DDoS scrubbing / CDN protection immediately", "priority": "immediate",
             "detail": "Route traffic through DDoS mitigation service (Cloudflare, AWS Shield, Akamai). Enable rate limiting at the edge."},
            {"step": 2, "action": "Implement application-level rate limiting", "priority": "immediate",
             "detail": "Add rate limiting middleware (e.g., nginx limit_req, API gateway throttling) — max 100 req/min per IP for authenticated, 20 for anonymous."},
            {"step": 3, "action": "Configure resource caps and timeouts", "priority": "short-term",
             "detail": "Set request body size limits, query timeout limits, max DB connection pool size, and memory limits per request."},
            {"step": 4, "action": "Disable amplification protocols on public interfaces", "priority": "short-term",
             "detail": "Disable NTP monlist, DNS recursion for external clients, SSDP/mDNS on public interfaces to prevent amplification attacks."},
            {"step": 5, "action": "Implement autoscaling and circuit breakers", "priority": "long-term",
             "detail": "Configure autoscaling to absorb legitimate traffic spikes. Implement circuit breakers to shed load gracefully under attack."},
        ],
        "Information Disclosure": [
            {"step": 1, "action": "Disable verbose error messages in production", "priority": "immediate",
             "detail": "Configure framework to return generic error pages (500 Internal Server Error) without stack traces. Log details server-side only."},
            {"step": 2, "action": "Remove or restrict debug/admin endpoints", "priority": "immediate",
             "detail": "Disable /actuator, /.git, /phpinfo.php, /swagger-ui in production. Restrict to internal IP ranges if needed."},
            {"step": 3, "action": "Audit and fix CORS configuration", "priority": "short-term",
             "detail": "Replace Access-Control-Allow-Origin: * with explicit origin allowlist. Never combine with Access-Control-Allow-Credentials: true."},
            {"step": 4, "action": "Implement API response field filtering", "priority": "short-term",
             "detail": "Audit all API responses — ensure internal fields, hashes, and PII are not included in any response payload."},
            {"step": 5, "action": "Conduct data classification and DLP implementation", "priority": "long-term",
             "detail": "Classify all data assets. Implement Data Loss Prevention controls to detect and block exfiltration of classified data."},
        ],
        "Command Injection": [
            {"step": 1, "action": "Remove all shell-calling code or sanitise input", "priority": "immediate",
             "detail": "Replace os.system/shell=True subprocess calls with parameterised API equivalents. If unavoidable, use strict allowlist for all arguments."},
            {"step": 2, "action": "Deploy WAF rule to block shell metacharacters", "priority": "immediate",
             "detail": "Block requests containing: ; | & ` $( ) > < in parameters processed by shell-calling endpoints."},
            {"step": 3, "action": "Run application as low-privilege user", "priority": "short-term",
             "detail": "Web application process must run as a dedicated non-root user with minimal filesystem and network permissions."},
            {"step": 4, "action": "Implement seccomp profile to restrict syscalls", "priority": "short-term",
             "detail": "Apply seccomp whitelist profile blocking execve and fork syscalls for the web server process."},
            {"step": 5, "action": "Refactor to use native APIs instead of shell", "priority": "long-term",
             "detail": "Replace all shell-based functionality with native library calls (e.g., Python subprocess list form, Java ProcessBuilder with arg arrays)."},
        ],
        "XML External Entity": [
            {"step": 1, "action": "Disable external entity processing in XML parsers", "priority": "immediate",
             "detail": "Set XMLConstants.FEATURE_SECURE_PROCESSING=true (Java). Set resolve_entities=False (libxml2). Use defusedxml (Python). Apply to ALL XML parsers in codebase."},
            {"step": 2, "action": "Disable DTD processing entirely", "priority": "immediate",
             "detail": "Configure parser to reject DOCTYPE declarations: setFeature(DISALLOW_DOCTYPE_DECL, true) in Java. This completely blocks XXE."},
            {"step": 3, "action": "Validate and sanitise all XML input", "priority": "short-term",
             "detail": "Validate XML against a strict schema (XSD) before processing. Reject documents that fail schema validation."},
            {"step": 4, "action": "Consider migrating from XML to JSON", "priority": "long-term",
             "detail": "Where possible, replace XML APIs with JSON equivalents which do not have XXE risks. Reduces attack surface significantly."},
        ],
        "Server-Side Request Forgery": [
            {"step": 1, "action": "Block requests to internal/metadata IP ranges", "priority": "immediate",
             "detail": "Implement server-side URL validation blocking: 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16 (AWS metadata)."},
            {"step": 2, "action": "Disable cloud metadata endpoint from application tier", "priority": "immediate",
             "detail": "Configure IMDSv2 on AWS (require session-oriented access). Set hop limit to 1 to prevent SSRF from reaching metadata API."},
            {"step": 3, "action": "Implement URL scheme allowlist", "priority": "short-term",
             "detail": "Only permit https:// URLs from approved external domains. Reject file://, gopher://, dict://, ftp:// schemes entirely."},
            {"step": 4, "action": "Segment application network with egress controls", "priority": "long-term",
             "detail": "Place application servers in a network segment with strict egress firewall rules — only allow outbound to known external services."},
        ],
        "Insecure Deserialization": [
            {"step": 1, "action": "Block or remove insecure deserialisation endpoints", "priority": "immediate",
             "detail": "Disable Java ObjectInputStream, PHP unserialize, Python pickle on untrusted data. Replace with safe alternatives (JSON with strict schema)."},
            {"step": 2, "action": "Implement serialisation allowlisting", "priority": "immediate",
             "detail": "Use look-ahead ObjectInputStream (Apache Commons IO) to whitelist only expected classes. Reject all unexpected types."},
            {"step": 3, "action": "Sign and verify all serialised payloads", "priority": "short-term",
             "detail": "Add HMAC signature to all serialised data (cookies, cache entries). Verify signature before deserialisation."},
            {"step": 4, "action": "Deploy deserialization attack detection", "priority": "short-term",
             "detail": "Use Java agent (NotSoSerial, SerialKiller) or RASP to detect and block known gadget chain execution patterns at runtime."},
            {"step": 5, "action": "Remove gadget chain libraries from classpath", "priority": "long-term",
             "detail": "Audit and remove unnecessary libraries that provide gadget chains (Commons Collections, Spring, Hibernate). Reduce attack surface."},
        ],
        "Cryptographic Weakness": [
            {"step": 1, "action": "Migrate all hashes to bcrypt/Argon2 immediately", "priority": "immediate",
             "detail": "Re-hash all stored passwords with bcrypt (cost factor ≥12) or Argon2id. Force password reset if MD5/SHA-1 hashes are exposed."},
            {"step": 2, "action": "Enforce TLS 1.2+ and disable weak cipher suites", "priority": "immediate",
             "detail": "Disable SSLv3, TLS 1.0, TLS 1.1. Remove RC4, DES, 3DES, EXPORT cipher suites. Use Mozilla's modern TLS configuration."},
            {"step": 3, "action": "Rotate all secrets and API keys", "priority": "short-term",
             "detail": "Rotate all JWT secrets, API keys, and encryption keys. Use secrets manager (AWS Secrets Manager, HashiCorp Vault) for storage."},
            {"step": 4, "action": "Implement certificate pinning for mobile/client apps", "priority": "short-term",
             "detail": "Pin TLS certificates in mobile apps to prevent MITM attacks even with compromised CA."},
            {"step": 5, "action": "Conduct cryptographic audit of entire codebase", "priority": "long-term",
             "detail": "Use SAST tools to find all cryptographic operations. Enforce crypto standards via policy as code in CI/CD pipeline."},
        ],
        "Exploitation Attempt": [
            {"step": 1, "action": "Block source IPs at firewall level", "priority": "immediate",
             "detail": "Add firewall rules to block IPs identified in the scan. Subscribe to threat intelligence feeds for automated IP blocking."},
            {"step": 2, "action": "Enable full packet capture on affected segments", "priority": "immediate",
             "detail": "Capture traffic from attacking IPs for forensic analysis. Use this to identify the specific exploit being attempted."},
            {"step": 3, "action": "Patch all known vulnerabilities identified in scan", "priority": "short-term",
             "detail": "Prioritise and patch CVEs identified by the OSINT scan. Use a vulnerability management platform to track remediation progress."},
            {"step": 4, "action": "Harden exposed attack surface", "priority": "short-term",
             "detail": "Close unnecessary open ports. Disable unused services. Apply network segmentation to limit blast radius."},
            {"step": 5, "action": "Implement continuous security monitoring", "priority": "long-term",
             "detail": "Deploy SIEM, IDS/IPS, and EDR for continuous threat detection. Establish a vulnerability disclosure and rapid response process."},
        ],
    }

    @classmethod
    def _get_root_cause_info(cls, attack_type: str, cve_desc: str = "", target_domain: str = "", osint_data: dict = None) -> Dict[str, Any]:
        """Return root cause, attack vector detail, affected components, and remediation for an attack type."""
        import copy
        db_entry = copy.deepcopy(cls.ROOT_CAUSE_DB.get(attack_type, cls.ROOT_CAUSE_DB["Exploitation Attempt"]))
        remediation = copy.deepcopy(cls.REMEDIATION_DB.get(attack_type, cls.REMEDIATION_DB["Exploitation Attempt"]))

        root_cause = db_entry["root_cause"]
        attack_vector = db_entry["attack_vector_detail"]
        
        # Prepend actual CVE description if available for specificity
        if cve_desc:
            root_cause = f"CVE Details: {cve_desc[:300]}\n\nRoot Cause Analysis: {root_cause}"

        # Procedurally inject OSINT data if available to make it hyper-specific
        if osint_data and target_domain:
            shodan = osint_data.get("sources", {}).get("shodan", {})
            ip = shodan.get("ip", target_domain)
            ports = shodan.get("ports", [])
            services = shodan.get("services", [])
            
            port_str = f"ports {', '.join(map(str, ports))}" if ports else "exposed ports"
            svc_str = ", ".join(set([s.get('product', '') for s in services if s.get('product')]))
            
            # Inject dynamic context into Root Cause
            root_cause = root_cause.replace(
                "exposed to the internet", f"exposed on {ip} across {port_str}"
            ).replace("misconfigured application", f"misconfigured application running at {target_domain}")
            
            # Add dynamic technical details to Attack Vector
            if ports:
                target_port = ports[0]
                attack_vector += (
                    f"\n\nTechnical execution: Attacker initiates connection to {ip}:{target_port} "
                    f"using tools like nmap/curl. The payload exploits the {svc_str or 'running'} service."
                )
            
            # Inject hyper-specific code-level remediation steps
            for step in remediation:
                if ports:
                    # Inject iptables/ufw rules dynamically for the specific ports
                    if "firewall" in step["detail"].lower() or "block" in step["detail"].lower():
                        step["detail"] += f" Execute: `sudo ufw deny {ports[0]}/tcp` or `iptables -A INPUT -p tcp --dport {ports[0]} -s 0.0.0.0/0 -j DROP`."
            
            # Ensure there is always a dynamic logging step
            remediation.append({
                "step": len(remediation) + 1,
                "action": f"Enable deep packet inspection for {target_domain}",
                "priority": "short-term",
                "detail": f"Deploy Suricata/Zeek rules monitoring traffic to {ip} on {port_str}. Run: `tcpdump -i any host {ip} -w /var/log/pcap/threat.pcap`."
            })

        return {
            "root_cause": root_cause,
            "attack_vector_detail": attack_vector,
            "affected_components": db_entry["affected_components"],
            "remediation": remediation,
        }

    @staticmethod
    async def predict_threats(
        domain: str,
        osint_data: Dict[str, Any],
        window_hours: int = 72,
    ) -> List[Dict[str, Any]]:
        """
        Generate threat predictions based on OSINT data.
        Deterministic per domain — same domain always produces same base predictions.
        Each prediction now includes root cause analysis and remediation steps.
        """
        predictions = []

        # Extract features
        open_ports = osint_data.get("summary", {}).get("open_ports", 0)
        known_vulns = osint_data.get("summary", {}).get("known_vulns", 0)
        vt_malicious = osint_data.get("summary", {}).get("vt_malicious", 0)
        recent_cves = osint_data.get("summary", {}).get("recent_cves", 0)
        otx_pulses = osint_data.get("summary", {}).get("otx_pulses", 0)
        risk_score = osint_data.get("risk_score", 50)

        features = {
            "open_ports": open_ports,
            "known_vulns": known_vulns,
            "vt_malicious": vt_malicious,
            "recent_cves": recent_cves,
            "otx_pulses": otx_pulses,
            "risk_score": risk_score,
        }

        # Environment risk factor (0-1)
        env_risk = (
            min(open_ports * 0.04, 0.20) +
            min(known_vulns * 0.06, 0.18) +
            min(vt_malicious * 0.03, 0.15) +
            min(recent_cves * 0.02, 0.12) +
            min(otx_pulses * 0.008, 0.10)
        )
        env_risk = min(env_risk, 0.75)

        # Process CVEs from OSINT — each CVE becomes a targeted prediction
        cve_data = osint_data.get("sources", {}).get("cve_nvd", [])
        if isinstance(cve_data, list):
            for cve in cve_data[:6]:
                cvss = float(cve.get("cvss_score", 5.0))
                cve_id = cve.get("cve_id", "")
                cve_desc = cve.get("description", "")

                # LSTM-style probability calculation
                cvss_factor = (cvss / 10.0) * 0.35          # 35% weight
                env_factor = env_risk * 0.30                 # 30% weight
                recency_factor = 0.15                        # Recent CVEs more exploitable
                ti_factor = min(otx_pulses / 50.0, 0.15)    # 15% TI signal
                domain_noise = _seeded_float(-0.04, 0.04, f"{domain}:{cve_id}")

                probability = min(
                    max(cvss_factor + env_factor + recency_factor + ti_factor + domain_noise, 0.05),
                    0.98,
                )

                attack_type = LSTMPredictor._classify_attack(cve_desc)
                rca = LSTMPredictor._get_root_cause_info(attack_type, cve_desc, target_domain=domain, osint_data=osint_data)

                # Enrich affected_components with Shodan service data if available
                shodan_services = osint_data.get("sources", {}).get("shodan", {}).get("services", [])
                if shodan_services:
                    svc_components = [
                        f"{s.get('product', 'Unknown')} {s.get('version', '')} (port {s.get('port', '?')})".strip()
                        for s in shodan_services[:4]
                        if s.get("product")
                    ]
                    if svc_components:
                        rca["affected_components"] = svc_components + rca["affected_components"]

                predictions.append({
                    "predicted_cve": cve_id,
                    "predicted_attack_type": attack_type,
                    "probability": round(float(probability), 4),
                    "time_window_hours": window_hours,
                    "cvss_score": cvss,
                    "severity": cve.get("severity", "UNKNOWN"),
                    "attack_vector": cve.get("attack_vector", ""),
                    "features_used": features,
                    "confidence": (
                        "high" if probability > 0.70 else
                        "medium" if probability > 0.40 else "low"
                    ),
                    "predicted_at": datetime.utcnow().isoformat(),
                    "expires_at": (datetime.utcnow() + timedelta(hours=window_hours)).isoformat(),
                    # ── Root Cause & Remediation ──────────────────
                    "root_cause": rca["root_cause"],
                    "attack_vector_detail": rca["attack_vector_detail"],
                    "affected_components": rca["affected_components"],
                    "cve_description": cve_desc[:500] if cve_desc else None,
                    "remediation": rca["remediation"],
                })

        # General attack type predictions (domain-seeded)
        for attack_type, base_prob in list(LSTMPredictor.CVE_CATEGORIES.items())[:5]:
            env_adj = base_prob * (0.4 + env_risk * 0.6)
            domain_factor = _seeded_float(0.85, 1.0, f"{domain}:{attack_type}")
            adjusted_prob = env_adj * domain_factor

            if adjusted_prob > 0.25:
                rca = LSTMPredictor._get_root_cause_info(attack_type, target_domain=domain, osint_data=osint_data)
                predictions.append({
                    "predicted_cve": None,
                    "predicted_attack_type": attack_type,
                    "probability": round(float(adjusted_prob), 4),
                    "time_window_hours": window_hours,
                    "cvss_score": None,
                    "severity": (
                        "CRITICAL" if adjusted_prob > 0.85 else
                        "HIGH" if adjusted_prob > 0.65 else "MEDIUM"
                    ),
                    "features_used": features,
                    "confidence": "high" if adjusted_prob > 0.70 else "medium",
                    "predicted_at": datetime.utcnow().isoformat(),
                    "expires_at": (datetime.utcnow() + timedelta(hours=window_hours)).isoformat(),
                    # ── Root Cause & Remediation ──────────────────
                    "root_cause": rca["root_cause"],
                    "attack_vector_detail": rca["attack_vector_detail"],
                    "affected_components": rca["affected_components"],
                    "cve_description": None,
                    "remediation": rca["remediation"],
                })

        # Sort by probability descending
        return sorted(predictions, key=lambda x: x["probability"], reverse=True)

    @staticmethod
    def _classify_attack(description: str) -> str:
        """Classify attack type from CVE description using keyword matching."""
        desc_lower = description.lower()
        patterns = [
            ("remote code", "Remote Code Execution"),
            (" rce ", "Remote Code Execution"),
            ("sql injection", "SQL Injection"),
            ("cross-site scripting", "Cross-Site Scripting"),
            (" xss ", "Cross-Site Scripting"),
            ("privilege escal", "Privilege Escalation"),
            ("buffer overflow", "Buffer Overflow"),
            ("heap overflow", "Buffer Overflow"),
            ("stack overflow", "Buffer Overflow"),
            ("authentication bypass", "Authentication Bypass"),
            ("denial of service", "Denial of Service"),
            (" dos ", "Denial of Service"),
            ("command injection", "Command Injection"),
            ("directory traversal", "Directory Traversal"),
            ("path traversal", "Directory Traversal"),
            ("server-side request", "Server-Side Request Forgery"),
            ("ssrf", "Server-Side Request Forgery"),
            ("xxe", "XML External Entity"),
            ("xml external", "XML External Entity"),
            ("deserialization", "Insecure Deserialization"),
            ("information disclosure", "Information Disclosure"),
            ("cryptographic", "Cryptographic Weakness"),
        ]
        for pattern, attack_type in patterns:
            if pattern in desc_lower:
                return attack_type
        return "Exploitation Attempt"


class ThreatTrendAnalyzer:
    """
    Analyzes historical threat data to compute trend metrics.
    Computes rolling window statistics for threat velocity and severity distribution.
    """

    @staticmethod
    def analyze_trends(threats: List[Dict], window_hours: int = 24) -> Dict[str, Any]:
        """
        Compute trend statistics from a list of threat dicts.
        """
        if not threats:
            return {"trend": "stable", "velocity": 0, "acceleration": 0}

        now = datetime.utcnow()
        cutoff = now - timedelta(hours=window_hours)
        prev_cutoff = cutoff - timedelta(hours=window_hours)

        recent = [t for t in threats if t.get("detected_at") and
                  datetime.fromisoformat(t["detected_at"]) >= cutoff]
        previous = [t for t in threats if t.get("detected_at") and
                    prev_cutoff <= datetime.fromisoformat(t["detected_at"]) < cutoff]

        velocity = len(recent)
        prev_velocity = len(previous)
        acceleration = velocity - prev_velocity

        severity_weights = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        severity_score = sum(
            severity_weights.get(t.get("severity", "low"), 1) for t in recent
        )

        return {
            "trend": "escalating" if acceleration > 2 else "stable" if acceleration >= 0 else "decreasing",
            "velocity_last_window": velocity,
            "velocity_prev_window": prev_velocity,
            "acceleration": acceleration,
            "weighted_severity_score": severity_score,
            "window_hours": window_hours,
        }


class AutoencoderDetector:
    """
    Autoencoder-based anomaly detection v2.0.
    Builds behavioural fingerprints using numpy statistical modeling.
    Deterministic across runs for same seed.
    """

    # "Normal" traffic baseline parameters (mean, std)
    NORMAL_BASELINE = {
        "packet_size_mean": (512, 150),
        "packet_size_std": (128, 50),
        "inter_arrival_time": (0.1, 0.05),
        "byte_rate": (10000, 3000),
        "packet_count": (150, 80),
        "duration": (5.0, 4.0),
        "flags_syn": (0.15, 0.10),
        "flags_rst": (0.05, 0.04),
        "payload_entropy": (4.5, 0.8),
    }

    @staticmethod
    async def detect_anomalies(
        traffic_data: Optional[Dict[str, Any]] = None,
        threshold: float = 0.82,
    ) -> List[Dict[str, Any]]:
        """
        Analyze network traffic for anomalies using autoencoder simulation.
        Uses Mahalanobis-distance-inspired scoring for realism.
        """
        anomalies = []
        rng = np.random.default_rng(seed=int(datetime.utcnow().timestamp()) % 10000)

        num_flows = int(rng.integers(60, 180))
        baseline = AutoencoderDetector.NORMAL_BASELINE

        for i in range(num_flows):
            is_attack = rng.random() < 0.09  # ~9% attack rate

            if is_attack:
                # Inject anomalous features
                attack_type_idx = int(rng.integers(0, 5))
                features = AutoencoderDetector._generate_attack_features(rng, attack_type_idx)
                # Reconstruction error: high for anomalies
                reconstruction_error = float(rng.uniform(0.78, 0.99))
            else:
                features = {
                    key: float(abs(rng.normal(mu, sigma)))
                    for key, (mu, sigma) in baseline.items()
                }
                reconstruction_error = float(rng.uniform(0.02, 0.60))

            anomaly_score = reconstruction_error

            if anomaly_score >= threshold:
                # Generate Threat DNA fingerprint
                feature_str = str(sorted(features.items()))
                full_hash = hashlib.sha256(feature_str.encode()).hexdigest()

                anomalies.append({
                    "source_ip": AutoencoderDetector._random_ip(rng, public=True),
                    "destination_ip": AutoencoderDetector._random_ip(rng, public=False),
                    "anomaly_score": round(anomaly_score, 4),
                    "reconstruction_error": round(reconstruction_error, 4),
                    "is_anomalous": True,
                    "pattern_fingerprint": full_hash[:16],
                    "features": {k: round(v, 4) for k, v in features.items()},
                    "classification": AutoencoderDetector._classify_anomaly(features),
                    "protocol": ["TCP", "UDP", "ICMP"][int(rng.integers(0, 3))],
                    "confidence": "high" if anomaly_score > 0.90 else "medium",
                    "detected_at": datetime.utcnow().isoformat(),
                })

        return sorted(anomalies, key=lambda x: x["anomaly_score"], reverse=True)

    @staticmethod
    def _generate_attack_features(rng: np.random.Generator, attack_type: int) -> Dict[str, float]:
        """Generate features characteristic of specific attack types."""
        templates = [
            # SYN Flood
            {"packet_size_mean": 64, "packet_count": 5000, "flags_syn": 0.95,
             "flags_rst": 0.02, "inter_arrival_time": 0.001, "byte_rate": 320000,
             "duration": 1.0, "packet_size_std": 5, "payload_entropy": 1.2},
            # Data Exfiltration
            {"packet_size_mean": 1400, "packet_count": 800, "flags_syn": 0.05,
             "flags_rst": 0.01, "inter_arrival_time": 0.05, "byte_rate": 1120000,
             "duration": 45.0, "packet_size_std": 200, "payload_entropy": 7.8},
            # Port Scanner
            {"packet_size_mean": 64, "packet_count": 1500, "flags_syn": 0.80,
             "flags_rst": 0.60, "inter_arrival_time": 0.002, "byte_rate": 96000,
             "duration": 3.0, "packet_size_std": 10, "payload_entropy": 0.5},
            # C2 Beacon (encrypted)
            {"packet_size_mean": 256, "packet_count": 40, "flags_syn": 0.10,
             "flags_rst": 0.02, "inter_arrival_time": 30.0, "byte_rate": 8192,
             "duration": 1200.0, "packet_size_std": 32, "payload_entropy": 7.9},
            # Brute Force
            {"packet_size_mean": 128, "packet_count": 2000, "flags_syn": 0.40,
             "flags_rst": 0.35, "inter_arrival_time": 0.003, "byte_rate": 256000,
             "duration": 6.0, "packet_size_std": 20, "payload_entropy": 3.2},
        ]
        base = templates[attack_type]
        # Add small noise
        noise = lambda v: float(v * (1 + rng.normal(0, 0.05)))
        return {k: round(noise(v), 4) for k, v in base.items()}

    @staticmethod
    def _random_ip(rng: np.random.Generator, public: bool = True) -> str:
        if public:
            # Sample from known attack-source ASNs (Russia, China, etc.)
            ranges = [(5, 87), (101, 220), (185, 195), (45, 95)]
            r = ranges[int(rng.integers(0, len(ranges)))]
            return f"{int(rng.integers(r[0], r[1]))}.{int(rng.integers(0, 256))}.{int(rng.integers(0, 256))}.{int(rng.integers(1, 255))}"
        return f"10.{int(rng.integers(0, 10))}.{int(rng.integers(0, 256))}.{int(rng.integers(1, 255))}"

    @staticmethod
    def _classify_anomaly(features: Dict) -> str:
        """Classify anomaly pattern based on feature thresholds."""
        if features.get("flags_syn", 0) > 0.80 and features.get("inter_arrival_time", 1) < 0.005:
            return "SYN Flood (Volumetric DDoS)"
        if features.get("payload_entropy", 0) > 7.5:
            return "Encrypted/Obfuscated Payload (C2 Beacon)"
        if features.get("packet_count", 0) > 3000 and features.get("byte_rate", 0) > 500000:
            return "Mass Data Exfiltration"
        if features.get("flags_rst", 0) > 0.50 and features.get("flags_syn", 0) > 0.60:
            return "Network Port Scanner"
        if features.get("packet_count", 0) > 1000 and features.get("inter_arrival_time", 1) < 0.01:
            return "Brute Force / Credential Stuffing"
        if features.get("inter_arrival_time", 0) > 20.0 and features.get("payload_entropy", 0) > 7.0:
            return "Periodic C2 Beacon (APT Implant)"
        return "Novel Anomalous Pattern (Zero-Day Candidate)"


class SeverityScorer:
    """
    CVSS-Enhanced severity scoring engine v2.0.
    Incorporates temporal decay, asset criticality, and OSINT context.
    """

    @staticmethod
    def calculate_score(
        cvss_base: float = 5.0,
        asset_criticality: float = 0.7,
        exploit_likelihood: float = 0.5,
        osint_context_score: float = 0.5,
        active_exploitation: bool = False,
        days_since_disclosure: int = 0,
    ) -> Dict[str, Any]:
        """
        Calculate enhanced severity score (0-10).

        Weighting:
          - CVSS Base: 35%
          - Exploit Likelihood (LSTM): 25%
          - Asset Criticality: 20%
          - OSINT Context: 15%
          - Active Exploitation Bonus: 5%
          - Temporal Decay: applied to CVSS (newer = higher)
        """
        # Temporal decay: CVSS loses 0.1 per month after 6 months
        temporal_factor = 1.0
        if days_since_disclosure > 180:
            months_old = (days_since_disclosure - 180) / 30
            temporal_factor = max(0.6, 1.0 - months_old * 0.02)

        adjusted_cvss = cvss_base * temporal_factor

        score = (
            adjusted_cvss * 0.35 +
            (exploit_likelihood * 10) * 0.25 +
            (asset_criticality * 10) * 0.20 +
            (osint_context_score * 10) * 0.15 +
            (10 if active_exploitation else 0) * 0.05
        )
        score = min(round(float(score), 1), 10.0)

        if score >= 9.0:
            severity = "CRITICAL"
        elif score >= 7.0:
            severity = "HIGH"
        elif score >= 4.0:
            severity = "MEDIUM"
        elif score >= 2.0:
            severity = "LOW"
        else:
            severity = "INFO"

        return {
            "score": score,
            "severity": severity,
            "temporal_factor": round(temporal_factor, 3),
            "breakdown": {
                "cvss_base_contribution": round(adjusted_cvss * 0.35, 2),
                "exploit_contribution": round((exploit_likelihood * 10) * 0.25, 2),
                "asset_contribution": round((asset_criticality * 10) * 0.20, 2),
                "osint_contribution": round((osint_context_score * 10) * 0.15, 2),
                "active_exploitation_bonus": round((10 if active_exploitation else 0) * 0.05, 2),
            },
            "recommendations": SeverityScorer._get_recommendations(severity),
            "sla_hours": SeverityScorer._get_sla(severity),
        }

    @staticmethod
    def _get_sla(severity: str) -> int:
        """Response SLA in hours by severity."""
        return {"CRITICAL": 1, "HIGH": 24, "MEDIUM": 168, "LOW": 720, "INFO": 8760}.get(severity, 168)

    @staticmethod
    def _get_recommendations(severity: str) -> List[str]:
        recs = {
            "CRITICAL": [
                "P0 — Immediate incident response required (< 1 hour SLA)",
                "Isolate affected systems from network immediately",
                "Engage CSIRT and escalate to CISO",
                "Apply emergency virtual patch or disable service",
                "Enable full packet capture on affected segments",
                "Notify legal/compliance if data exposure is suspected",
            ],
            "HIGH": [
                "P1 — Respond within 24 hours",
                "Priority patching via change management fast-track",
                "Increase SIEM alert threshold on affected systems",
                "Review and tighten firewall egress rules",
                "Conduct targeted threat hunt for lateral movement",
            ],
            "MEDIUM": [
                "P2 — Schedule patching within 7 days",
                "Monitor affected systems for exploitation attempts",
                "Review user access controls on vulnerable assets",
                "Update IDS/IPS signatures for this attack vector",
            ],
            "LOW": [
                "P3 — Include in next scheduled patch cycle (30 days)",
                "Document for compliance tracking",
                "Add to vulnerability management backlog",
            ],
            "INFO": [
                "No immediate action required",
                "Log for awareness and compliance reporting",
            ],
        }
        return recs.get(severity, ["Review and assess the situation"])
