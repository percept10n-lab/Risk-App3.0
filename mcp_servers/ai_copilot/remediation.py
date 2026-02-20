"""Remediation advisor for AI Defense Copilot.

Provides evidence-grounded remediation suggestions using a comprehensive
knowledge base. All suggestions are labeled as Proposed and never presented
as definitive instructions. Works entirely rule-based with no external LLM.
"""

import re

import structlog

logger = structlog.get_logger()

# --------------------------------------------------------------------------- #
# Remediation Knowledge Base
# --------------------------------------------------------------------------- #
# Keyed by pattern tuples: (keyword_list, category_hint).
# Each entry maps to a remediation template dict.

_REMEDIATION_KB: list[dict] = [
    # 1. SSH password authentication
    {
        "id": "ssh_password_auth",
        "patterns": ["ssh password auth", "password authentication", "ssh brute"],
        "categories": ["misconfig", "vuln"],
        "summary": "Disable SSH password authentication and enforce key-based access.",
        "steps": [
            "Generate an SSH key pair: ssh-keygen -t ed25519 -C 'admin@org'",
            "Copy the public key to the server: ssh-copy-id user@host",
            "Edit /etc/ssh/sshd_config and set: PasswordAuthentication no",
            "Set: ChallengeResponseAuthentication no",
            "Set: UsePAM no (or configure PAM to not allow password)",
            "Restart the SSH service: systemctl restart sshd",
            "Verify by attempting password login (should be rejected)",
        ],
        "difficulty": "easy",
        "references": [
            "https://man.openbsd.org/sshd_config",
            "https://www.ssh.com/academy/ssh/keygen",
        ],
        "verification": "Attempt SSH login with password - connection should be refused. Verify with: ssh -o PreferredAuthentications=password user@host",
        "alternative_mitigations": [
            "If password auth cannot be disabled immediately, enforce strong passwords and enable fail2ban",
            "Restrict SSH access to specific IP ranges via firewall rules",
            "Enable MFA for SSH using Google Authenticator or Duo",
        ],
    },
    # 2. Missing HTTP security headers
    {
        "id": "missing_http_headers",
        "patterns": [
            "missing header", "http header", "x-frame-options",
            "x-content-type-options", "strict-transport-security",
            "content-security-policy", "x-xss-protection",
            "referrer-policy", "permissions-policy",
        ],
        "categories": ["misconfig", "exposure"],
        "summary": "Configure missing HTTP security headers on the web server.",
        "steps": [
            "Identify which headers are missing from the scan results",
            "For Nginx, add to server block:\n"
            "  add_header X-Frame-Options 'SAMEORIGIN' always;\n"
            "  add_header X-Content-Type-Options 'nosniff' always;\n"
            "  add_header Strict-Transport-Security 'max-age=31536000; includeSubDomains' always;\n"
            "  add_header Content-Security-Policy \"default-src 'self'\" always;\n"
            "  add_header Referrer-Policy 'strict-origin-when-cross-origin' always;\n"
            "  add_header Permissions-Policy 'geolocation=(), microphone=()' always;",
            "For Apache, add to .htaccess or VirtualHost:\n"
            "  Header always set X-Frame-Options 'SAMEORIGIN'\n"
            "  Header always set X-Content-Type-Options 'nosniff'\n"
            "  Header always set Strict-Transport-Security 'max-age=31536000; includeSubDomains'\n"
            "  Header always set Content-Security-Policy \"default-src 'self'\"\n"
            "  Header always set Referrer-Policy 'strict-origin-when-cross-origin'",
            "Test the configuration: nginx -t / apachectl configtest",
            "Reload the web server: systemctl reload nginx / systemctl reload apache2",
        ],
        "difficulty": "easy",
        "references": [
            "https://owasp.org/www-project-secure-headers/",
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers",
            "https://securityheaders.com/",
        ],
        "verification": "Use curl -I https://target or securityheaders.com to verify all headers are present.",
        "alternative_mitigations": [
            "Deploy a reverse proxy or WAF (e.g., Cloudflare, AWS WAF) that injects security headers",
            "Use a CDN that automatically adds security headers",
        ],
    },
    # 3. Weak TLS configuration
    {
        "id": "weak_tls",
        "patterns": [
            "weak tls", "tls 1.0", "tls 1.1", "ssl 3", "sslv3",
            "weak cipher", "weak ssl", "poodle", "beast", "sweet32",
            "rc4", "des", "3des", "null cipher", "export cipher",
        ],
        "categories": ["vuln", "misconfig"],
        "summary": "Update TLS configuration to disable weak protocols and ciphers.",
        "steps": [
            "Identify current TLS configuration and weak protocols/ciphers from scan results",
            "For Nginx, update ssl settings:\n"
            "  ssl_protocols TLSv1.2 TLSv1.3;\n"
            "  ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
            "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';\n"
            "  ssl_prefer_server_ciphers on;\n"
            "  ssl_session_timeout 1d;\n"
            "  ssl_session_cache shared:SSL:10m;",
            "For Apache, update ssl.conf:\n"
            "  SSLProtocol all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1\n"
            "  SSLCipherSuite 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
            "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384'\n"
            "  SSLHonorCipherOrder on",
            "Test configuration and reload the web server",
            "Verify with: nmap --script ssl-enum-ciphers -p 443 target",
        ],
        "difficulty": "moderate",
        "references": [
            "https://wiki.mozilla.org/Security/Server_Side_TLS",
            "https://ssl-config.mozilla.org/",
            "https://www.ssllabs.com/ssltest/",
        ],
        "verification": "Run SSL Labs test (ssllabs.com/ssltest) or testssl.sh against the target. Ensure A or A+ rating.",
        "alternative_mitigations": [
            "Place a TLS-terminating reverse proxy in front of the service",
            "Use a managed load balancer with strong TLS defaults (AWS ALB, Cloudflare)",
        ],
    },
    # 4. Self-signed certificate
    {
        "id": "self_signed_cert",
        "patterns": [
            "self-signed", "self signed", "untrusted cert",
            "certificate not trusted", "invalid certificate",
            "expired certificate", "cert expired",
        ],
        "categories": ["misconfig", "exposure"],
        "summary": "Replace self-signed or expired certificate with a trusted CA-issued certificate.",
        "steps": [
            "For public-facing services, use Let's Encrypt:\n"
            "  apt install certbot python3-certbot-nginx\n"
            "  certbot --nginx -d yourdomain.com",
            "For internal services, request a certificate from your internal CA",
            "Install the new certificate and private key in the web server configuration",
            "Configure automatic renewal: certbot renew --dry-run",
            "Update certificate monitoring to alert before expiration",
        ],
        "difficulty": "easy",
        "references": [
            "https://letsencrypt.org/getting-started/",
            "https://certbot.eff.org/",
        ],
        "verification": "Browse to the service and verify no certificate warnings. Check with: openssl s_client -connect host:443",
        "alternative_mitigations": [
            "If using internal CA, distribute the CA root certificate to all clients via GPO or MDM",
            "Use ACME protocol with an internal CA like step-ca or Vault PKI",
        ],
    },
    # 5. Open recursive DNS
    {
        "id": "open_recursive_dns",
        "patterns": [
            "open dns", "recursive dns", "dns recursion",
            "open resolver", "dns amplification",
        ],
        "categories": ["misconfig", "exposure"],
        "summary": "Restrict DNS recursion to authorized clients only.",
        "steps": [
            "Identify the DNS server software (BIND, Unbound, Windows DNS, etc.)",
            "For BIND, edit named.conf and restrict recursion:\n"
            "  acl internal { 10.0.0.0/8; 172.16.0.0/12; 192.168.0.0/16; };\n"
            "  options {\n"
            "    recursion yes;\n"
            "    allow-recursion { internal; };\n"
            "    allow-query-cache { internal; };\n"
            "  };",
            "For Unbound, set access-control to allow only internal nets:\n"
            "  access-control: 10.0.0.0/8 allow\n"
            "  access-control: 0.0.0.0/0 refuse",
            "Restart the DNS service and verify",
            "Test from an external host to confirm recursion is refused",
        ],
        "difficulty": "moderate",
        "references": [
            "https://www.isc.org/bind/",
            "https://nlnetlabs.nl/projects/unbound/about/",
            "https://www.cisa.gov/news-events/alerts/2013/03/29/dns-amplification-attacks",
        ],
        "verification": "From an external IP: dig @target example.com +recurse - should be refused or timeout.",
        "alternative_mitigations": [
            "Block incoming DNS queries (port 53) from untrusted networks at the firewall",
            "Implement DNS rate limiting to reduce amplification attack impact",
        ],
    },
    # 6. UPnP enabled
    {
        "id": "upnp_enabled",
        "patterns": ["upnp", "universal plug and play", "ssdp"],
        "categories": ["misconfig", "exposure"],
        "summary": "Disable UPnP on network devices to prevent unauthorized port forwarding.",
        "steps": [
            "Log in to the router or device administration interface",
            "Navigate to the UPnP or advanced network settings section",
            "Disable UPnP / SSDP service",
            "Save and apply the configuration",
            "Verify no UPnP responses: nmap -sU -p 1900 --script=upnp-info target",
        ],
        "difficulty": "easy",
        "references": [
            "https://www.us-cert.gov/ncas/alerts/TA14-017A",
            "https://www.rapid7.com/blog/post/2013/01/29/security-flaws-in-universal-plug-and-play/",
        ],
        "verification": "Scan for SSDP on port 1900 - should receive no response.",
        "alternative_mitigations": [
            "Block SSDP (UDP port 1900) at the network firewall",
            "Use network segmentation to isolate devices that require UPnP",
        ],
    },
    # 7. Default credentials
    {
        "id": "default_credentials",
        "patterns": [
            "default credential", "default password", "default login",
            "factory default", "admin/admin", "admin/password",
        ],
        "categories": ["vuln", "misconfig"],
        "summary": "Change default credentials immediately and enable multi-factor authentication.",
        "steps": [
            "Log in with the current default credentials",
            "Change the password to a strong, unique passphrase (16+ characters)",
            "Change the default username if possible",
            "Enable multi-factor authentication (MFA) if supported",
            "Document the new credentials in a secrets manager (e.g., Vault, 1Password)",
            "Audit all devices/services for additional default credentials",
            "Implement a policy requiring credential changes upon deployment",
        ],
        "difficulty": "easy",
        "references": [
            "https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-103a",
            "https://cwe.mitre.org/data/definitions/798.html",
        ],
        "verification": "Attempt login with the old default credentials - should be rejected.",
        "alternative_mitigations": [
            "If MFA is not available, restrict access to the management interface by IP or VLAN",
            "Deploy a PAM (Privileged Access Management) solution for shared credentials",
        ],
    },
    # 8. Outdated software / unpatched
    {
        "id": "outdated_software",
        "patterns": [
            "outdated", "out of date", "end of life", "eol",
            "unsupported version", "unpatched", "missing patch",
            "vulnerable version", "upgrade required",
        ],
        "categories": ["vuln"],
        "summary": "Update software to the latest supported version with current security patches.",
        "steps": [
            "Identify the exact current version and the latest available version",
            "Review the release notes and changelog for security fixes",
            "Test the upgrade in a staging or development environment first",
            "Create a backup/snapshot of the system before upgrading",
            "Apply the update during a maintenance window:\n"
            "  - For Linux packages: apt update && apt upgrade <package>\n"
            "  - For Windows: Apply via WSUS or manual update\n"
            "  - For applications: Follow vendor upgrade procedures",
            "Verify the service is running correctly after the upgrade",
            "Confirm the version number matches the expected target version",
        ],
        "difficulty": "moderate",
        "references": [
            "https://cvefeed.io/",
            "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        ],
        "verification": "Verify the new version: check with version command, banner, or re-scan with vulnerability scanner.",
        "alternative_mitigations": [
            "If immediate upgrade is not possible, apply virtual patching via WAF or IPS rules",
            "Isolate the affected system behind additional network controls",
            "Implement compensating controls (disable vulnerable features, restrict access)",
        ],
    },
    # 9. Exposed admin interface
    {
        "id": "exposed_admin_ui",
        "patterns": [
            "admin interface", "admin panel", "management interface",
            "admin console", "web console exposed", "management ui",
            "admin portal", "admin page",
        ],
        "categories": ["exposure", "misconfig"],
        "summary": "Restrict access to the administrative interface by IP allowlist or VPN.",
        "steps": [
            "Identify all administrative interfaces and their URLs/ports",
            "Configure IP-based access restrictions:\n"
            "  Nginx: allow 10.0.0.0/8; deny all;\n"
            "  Apache: Require ip 10.0.0.0/8",
            "Move admin interface to a non-standard port if applicable",
            "Require VPN access for all administrative functions",
            "Enable MFA for administrative logins",
            "Add rate limiting to prevent brute-force attacks",
            "Configure audit logging for all admin access",
        ],
        "difficulty": "moderate",
        "references": [
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information",
        ],
        "verification": "Attempt to access admin interface from an unauthorized IP - should be blocked.",
        "alternative_mitigations": [
            "Deploy a zero-trust access proxy (e.g., Cloudflare Access, Tailscale) in front of admin UIs",
            "Disable the web admin interface entirely and manage via CLI or API only",
        ],
    },
    # 10. FTP/Telnet in use
    {
        "id": "ftp_telnet",
        "patterns": [
            "ftp", "telnet", "cleartext protocol", "unencrypted protocol",
            "plain text protocol",
        ],
        "categories": ["vuln", "misconfig", "exposure"],
        "summary": "Replace insecure cleartext protocols (FTP/Telnet) with encrypted alternatives.",
        "steps": [
            "Inventory all systems using FTP or Telnet and their purposes",
            "For FTP, migrate to SFTP or SCP:\n"
            "  - Install/enable OpenSSH server if not present\n"
            "  - Configure SFTP subsystem in sshd_config:\n"
            "    Subsystem sftp /usr/lib/openssh/sftp-server\n"
            "  - Update all clients and scripts to use SFTP",
            "For Telnet, migrate to SSH:\n"
            "  - Ensure SSH server is installed and running\n"
            "  - Update all management scripts and procedures to use SSH",
            "Disable FTP and Telnet services:\n"
            "  systemctl stop vsftpd && systemctl disable vsftpd\n"
            "  systemctl stop telnet.socket && systemctl disable telnet.socket",
            "Block FTP (port 21) and Telnet (port 23) at the firewall",
        ],
        "difficulty": "moderate",
        "references": [
            "https://www.ssh.com/academy/ssh/sftp",
            "https://www.cisecurity.org/benchmark/",
        ],
        "verification": "Port scan: nmap -p 21,23 target - ports should be closed or filtered. Verify SFTP/SSH works.",
        "alternative_mitigations": [
            "If FTP/Telnet cannot be removed immediately, restrict access to a management VLAN only",
            "Use FTPS (FTP over TLS) as an intermediate step before full SFTP migration",
        ],
    },
    # 11. Weak SSH algorithms
    {
        "id": "weak_ssh_algorithms",
        "patterns": [
            "weak ssh", "ssh algorithm", "ssh cipher",
            "ssh mac", "ssh kex", "diffie-hellman-group1",
            "arcfour", "hmac-md5", "cbc cipher", "ssh-dss",
        ],
        "categories": ["vuln", "misconfig"],
        "summary": "Update SSH configuration to use strong key exchange, cipher, and MAC algorithms.",
        "steps": [
            "Review current SSH algorithms: ssh -vvv user@host 2>&1 | grep 'kex\\|cipher\\|mac'",
            "Edit /etc/ssh/sshd_config with strong algorithms:\n"
            "  KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,"
            "diffie-hellman-group-exchange-sha256\n"
            "  Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,"
            "aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr\n"
            "  MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,"
            "hmac-sha2-512,hmac-sha2-256",
            "Remove small Diffie-Hellman moduli:\n"
            "  awk '$5 >= 3071' /etc/ssh/moduli > /etc/ssh/moduli.safe\n"
            "  mv /etc/ssh/moduli.safe /etc/ssh/moduli",
            "Restart SSH: systemctl restart sshd",
            "Test connectivity from all management workstations before closing current session",
        ],
        "difficulty": "moderate",
        "references": [
            "https://www.ssh-audit.com/",
            "https://man.openbsd.org/sshd_config",
            "https://infosec.mozilla.org/guidelines/openssh",
        ],
        "verification": "Run ssh-audit against the server. All algorithms should be rated 'good' or better.",
        "alternative_mitigations": [
            "If legacy clients require weak algorithms, create a separate SSH listener on a restricted port with weaker settings",
            "Use a jump host with strong SSH as a gateway to systems needing legacy support",
        ],
    },
    # 12. DNS zone transfer
    {
        "id": "dns_zone_transfer",
        "patterns": [
            "zone transfer", "axfr", "dns zone transfer",
            "ixfr", "dns enumeration",
        ],
        "categories": ["misconfig", "exposure"],
        "summary": "Restrict DNS zone transfers (AXFR) to authorized secondary DNS servers only.",
        "steps": [
            "Identify all authorized secondary DNS servers and their IPs",
            "For BIND, update named.conf:\n"
            "  zone \"example.com\" {\n"
            "    type master;\n"
            "    file \"example.com.zone\";\n"
            "    allow-transfer { 10.0.0.2; 10.0.0.3; };\n"
            "  };",
            "For Windows DNS, configure zone transfer restrictions in DNS Manager:\n"
            "  Zone Properties > Zone Transfers > Allow only to specific servers",
            "Consider using TSIG keys for authenticated zone transfers:\n"
            "  key \"transfer-key\" { algorithm hmac-sha256; secret \"...\"; };",
            "Restart DNS and verify transfers are restricted",
        ],
        "difficulty": "easy",
        "references": [
            "https://www.isc.org/bind/",
            "https://learn.microsoft.com/en-us/windows-server/networking/dns/",
        ],
        "verification": "From an unauthorized host: dig @target example.com AXFR - should return 'Transfer failed'.",
        "alternative_mitigations": [
            "Block TCP port 53 from unauthorized sources at the firewall (AXFR uses TCP)",
            "Use DNS-over-TLS between primary and secondary servers",
        ],
    },
    # 13. Missing DNSSEC
    {
        "id": "missing_dnssec",
        "patterns": [
            "dnssec", "dns security", "dns signing",
            "dns spoofing", "dns poisoning",
        ],
        "categories": ["misconfig"],
        "summary": "Enable DNSSEC validation to protect against DNS spoofing and cache poisoning.",
        "steps": [
            "For BIND resolvers, enable DNSSEC validation in named.conf:\n"
            "  options {\n"
            "    dnssec-validation auto;\n"
            "  };",
            "For Unbound, enable DNSSEC:\n"
            "  server:\n"
            "    auto-trust-anchor-file: '/var/lib/unbound/root.key'\n"
            "    val-clean-additional: yes",
            "For authoritative zones, sign the zone with dnssec-keygen and dnssec-signzone",
            "Publish DS records with your domain registrar",
            "Monitor DNSSEC with: dig +dnssec example.com",
        ],
        "difficulty": "hard",
        "references": [
            "https://www.isc.org/dnssec/",
            "https://www.icann.org/resources/pages/dnssec-what-is-it-why-important-2019-03-05-en",
            "https://dnsviz.net/",
        ],
        "verification": "Check with dig +dnssec or use dnsviz.net to verify DNSSEC chain of trust.",
        "alternative_mitigations": [
            "Use DNS-over-HTTPS (DoH) or DNS-over-TLS (DoT) for transport security as an interim measure",
            "Implement response rate limiting to reduce cache poisoning risk",
        ],
    },
    # 14. SNMP default community string
    {
        "id": "snmp_default_community",
        "patterns": [
            "snmp community", "snmp default", "snmp public",
            "snmp private", "community string",
        ],
        "categories": ["misconfig", "vuln"],
        "summary": "Change default SNMP community strings and upgrade to SNMPv3 with authentication.",
        "steps": [
            "Inventory all devices using SNMP and their current versions",
            "Upgrade to SNMPv3 with authPriv (authentication + encryption):\n"
            "  - Create SNMPv3 user with strong credentials\n"
            "  - Use SHA-256 for authentication and AES-256 for privacy",
            "If SNMPv3 is not supported, change community strings:\n"
            "  - Use long random strings (20+ characters)\n"
            "  - Configure read-only access where possible\n"
            "  - Restrict SNMP to specific management IPs",
            "Disable SNMPv1 and SNMPv2c where possible",
            "Block SNMP (UDP 161/162) from untrusted networks at the firewall",
        ],
        "difficulty": "moderate",
        "references": [
            "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/snmp/configuration/xe-16/snmp-xe-16-book.html",
            "https://net-snmp.sourceforge.io/wiki/index.php/TUT:SNMPv3",
        ],
        "verification": "Test with: snmpwalk -v2c -c public target - should be rejected. SNMPv3 queries should succeed.",
        "alternative_mitigations": [
            "Use firewall ACLs to restrict SNMP to management network only",
            "Consider replacing SNMP monitoring with agent-based solutions (e.g., Prometheus exporters)",
        ],
    },
    # 15. Open database port
    {
        "id": "open_database_port",
        "patterns": [
            "open database", "database exposed", "mysql exposed",
            "postgres exposed", "mongodb exposed", "redis exposed",
            "elasticsearch exposed", "port 3306", "port 5432",
            "port 27017", "port 6379", "port 9200", "database port",
        ],
        "categories": ["exposure", "misconfig"],
        "summary": "Restrict database access to authorized application servers and admin workstations only.",
        "steps": [
            "Identify which database ports are exposed and to which networks",
            "Configure the database to listen only on localhost or internal interfaces:\n"
            "  MySQL: bind-address = 127.0.0.1 in my.cnf\n"
            "  PostgreSQL: listen_addresses = 'localhost' in postgresql.conf\n"
            "  MongoDB: bindIp = 127.0.0.1 in mongod.conf\n"
            "  Redis: bind 127.0.0.1 in redis.conf",
            "Use firewall rules to restrict access to database ports:\n"
            "  iptables -A INPUT -p tcp --dport 3306 -s 10.0.1.0/24 -j ACCEPT\n"
            "  iptables -A INPUT -p tcp --dport 3306 -j DROP",
            "Enable authentication and use strong credentials",
            "Enable TLS/SSL for database connections",
            "Audit database users and remove unnecessary accounts",
        ],
        "difficulty": "moderate",
        "references": [
            "https://dev.mysql.com/doc/refman/8.0/en/security.html",
            "https://www.postgresql.org/docs/current/auth-pg-hba-conf.html",
            "https://www.mongodb.com/docs/manual/security/",
        ],
        "verification": "Port scan from untrusted network: nmap -p 3306,5432,27017,6379,9200 target - all should be filtered.",
        "alternative_mitigations": [
            "Use an SSH tunnel or VPN for remote database administration",
            "Deploy a database proxy (e.g., ProxySQL, PgBouncer) with access controls",
        ],
    },
    # 16. CORS misconfiguration
    {
        "id": "cors_misconfig",
        "patterns": [
            "cors", "cross-origin", "access-control-allow-origin",
            "origin wildcard", "cors wildcard",
        ],
        "categories": ["misconfig", "vuln"],
        "summary": "Restrict CORS policy to specific trusted origins instead of wildcard.",
        "steps": [
            "Review current CORS configuration and identify overly permissive settings",
            "Replace wildcard (*) with specific allowed origins:\n"
            "  Nginx: add_header Access-Control-Allow-Origin 'https://app.example.com';\n"
            "  Express.js: cors({ origin: ['https://app.example.com'] })",
            "Restrict allowed methods and headers to what is actually needed",
            "Never reflect the Origin header back without validation",
            "Ensure credentials (cookies) are not sent with wildcard origins",
            "Test with: curl -H 'Origin: https://evil.com' -I https://target",
        ],
        "difficulty": "easy",
        "references": [
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS",
            "https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny",
        ],
        "verification": "Send request with unauthorized Origin header - should not receive Access-Control-Allow-Origin in response.",
        "alternative_mitigations": [
            "Use a WAF to enforce CORS policies at the edge",
            "Implement server-side origin validation middleware",
        ],
    },
    # 17. Unencrypted data in transit
    {
        "id": "unencrypted_transit",
        "patterns": [
            "unencrypted", "http only", "no https", "no tls",
            "plaintext", "clear text", "cleartext transmission",
        ],
        "categories": ["vuln", "exposure"],
        "summary": "Enable TLS encryption for all data in transit and enforce HTTPS redirects.",
        "steps": [
            "Obtain a TLS certificate (Let's Encrypt or internal CA)",
            "Configure HTTPS on the web server with the certificate",
            "Redirect all HTTP traffic to HTTPS:\n"
            "  Nginx: return 301 https://$server_name$request_uri;\n"
            "  Apache: RewriteRule ^(.*)$ https://%{HTTP_HOST}$1 [R=301,L]",
            "Enable HSTS header: Strict-Transport-Security: max-age=31536000",
            "Update all internal links and references to use https://",
            "Configure application to set Secure flag on all cookies",
        ],
        "difficulty": "moderate",
        "references": [
            "https://letsencrypt.org/",
            "https://hstspreload.org/",
            "https://ssl-config.mozilla.org/",
        ],
        "verification": "Access http://target - should redirect to https://. Verify with: curl -v http://target and check for 301.",
        "alternative_mitigations": [
            "If backend cannot support TLS, terminate TLS at a reverse proxy or load balancer",
            "Use a service mesh (e.g., Istio) for automatic mTLS between microservices",
        ],
    },
    # 18. Information disclosure / version exposure
    {
        "id": "info_disclosure",
        "patterns": [
            "information disclosure", "version disclosure",
            "server banner", "software version", "tech stack",
            "error message", "stack trace", "debug mode",
            "verbose error", "directory listing",
        ],
        "categories": ["info", "exposure"],
        "summary": "Suppress server version banners, error details, and directory listings.",
        "steps": [
            "Nginx - hide version: server_tokens off;",
            "Apache - hide version:\n"
            "  ServerTokens Prod\n"
            "  ServerSignature Off",
            "Disable directory listing:\n"
            "  Nginx: autoindex off;\n"
            "  Apache: Options -Indexes",
            "Configure custom error pages to avoid information leakage",
            "Disable debug mode in production applications",
            "Remove X-Powered-By and similar headers:\n"
            "  Nginx: proxy_hide_header X-Powered-By;\n"
            "  Express.js: app.disable('x-powered-by');",
        ],
        "difficulty": "easy",
        "references": [
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/",
            "https://cwe.mitre.org/data/definitions/200.html",
        ],
        "verification": "Check response headers with curl -I and verify no version information is disclosed.",
        "alternative_mitigations": [
            "Use a WAF or reverse proxy to strip sensitive headers",
            "Deploy custom error handling middleware in the application layer",
        ],
    },
]


class RemediationAdvisor:
    """Rule-based remediation advisor for security findings."""

    def __init__(self) -> None:
        self._kb = _REMEDIATION_KB
        logger.info(
            "RemediationAdvisor initialized",
            knowledge_base_entries=len(self._kb),
        )

    def suggest(self, finding: dict, asset: dict | None = None) -> dict:
        """Return a remediation plan for a given finding.

        Args:
            finding: Finding dict with at least title, description, severity,
                     category, source_check.
            asset: Optional asset context dict.

        Returns:
            Dict with keys: summary, steps, difficulty, references,
            verification, alternative_mitigations, ai_label, evidence.
        """
        logger.info(
            "Generating remediation suggestion",
            finding_title=finding.get("title", "unknown"),
        )

        # Build the search text from finding fields
        search_text = (
            finding.get("title", "")
            + " "
            + finding.get("description", "")
            + " "
            + finding.get("source_check", "")
            + " "
            + finding.get("category", "")
        ).lower()

        # Find the best matching knowledge base entry
        best_match: dict | None = None
        best_score = 0

        for entry in self._kb:
            score = self._match_score(search_text, entry)
            if score > best_score:
                best_score = score
                best_match = entry

        if best_match and best_score > 0:
            result = self._format_kb_entry(best_match, finding, asset)
        else:
            result = self._generate_generic(finding, asset)

        result["ai_label"] = "AI Suggestion - Proposed"
        result["evidence"] = {
            "finding_title": finding.get("title", ""),
            "finding_severity": finding.get("severity", ""),
            "match_confidence": "high" if best_score >= 2 else "medium" if best_score == 1 else "low",
            "knowledge_base_entry": best_match["id"] if best_match and best_score > 0 else None,
        }

        logger.info(
            "Remediation suggestion generated",
            match_score=best_score,
            kb_entry=best_match["id"] if best_match and best_score > 0 else "generic",
        )

        return result

    def _match_score(self, search_text: str, entry: dict) -> int:
        """Score how well a KB entry matches the search text."""
        score = 0
        for pattern in entry["patterns"]:
            if pattern.lower() in search_text:
                score += 1
        # Bonus for category match
        for cat in entry.get("categories", []):
            if cat.lower() in search_text:
                score += 0.5
        return int(score)

    def _format_kb_entry(
        self, entry: dict, finding: dict, asset: dict | None
    ) -> dict:
        """Format a knowledge base entry into a remediation result."""
        steps = list(entry["steps"])

        # Add asset-specific context if available
        if asset:
            ip = asset.get("ip_address", "")
            hostname = asset.get("hostname", "")
            os_guess = asset.get("os_guess", "")

            context_note = "Proposed context: "
            if hostname:
                context_note += f"Target host: {hostname} "
            if ip:
                context_note += f"({ip}) "
            if os_guess:
                context_note += f"running {os_guess}"

            if context_note != "Proposed context: ":
                steps.insert(0, context_note.strip())

        return {
            "summary": f"Proposed: {entry['summary']}",
            "steps": steps,
            "difficulty": entry["difficulty"],
            "references": entry["references"],
            "verification": f"Proposed verification: {entry['verification']}",
            "alternative_mitigations": entry["alternative_mitigations"],
        }

    def _generate_generic(self, finding: dict, asset: dict | None) -> dict:
        """Generate a generic remediation when no KB entry matches."""
        title = finding.get("title", "the identified finding")
        severity = finding.get("severity", "unknown")
        description = finding.get("description", "")
        existing_remediation = finding.get("remediation", "")

        steps = [
            f"Review the finding details: '{title}' (severity: {severity})",
            "Identify the root cause based on the finding description",
        ]

        if existing_remediation:
            steps.append(
                f"Follow the scanner-provided remediation guidance: {existing_remediation}"
            )

        steps.extend([
            "Test the fix in a non-production environment first",
            "Apply the fix during a scheduled maintenance window",
            "Verify the fix by re-running the original scan or check",
            "Document the change and update the risk register",
        ])

        if asset:
            ip = asset.get("ip_address", "")
            if ip:
                steps.insert(0, f"Proposed context: Affected asset at {ip}")

        difficulty = "moderate"
        if severity in ("critical", "high"):
            difficulty = "hard"
        elif severity in ("low", "info"):
            difficulty = "easy"

        return {
            "summary": (
                f"Proposed: Address '{title}' ({severity} severity) "
                f"following vendor guidance and security best practices."
            ),
            "steps": steps,
            "difficulty": difficulty,
            "references": [
                "https://cvefeed.io/",
                "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                "https://owasp.org/",
            ],
            "verification": (
                "Proposed verification: Re-run the original vulnerability scan "
                "to confirm the finding is no longer present."
            ),
            "alternative_mitigations": [
                "Apply network-level controls (firewall rules, segmentation) as a compensating measure",
                "Increase monitoring and alerting for the affected system",
                "Accept the risk with documented justification if remediation is not feasible",
            ],
        }
