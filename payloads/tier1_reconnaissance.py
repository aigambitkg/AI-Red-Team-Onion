"""
AI Red Team Onion — Tier 1.1: Reconnaissance & Enumeration Payloads

Static payload library for network reconnaissance, DNS enumeration, 
subdomain discovery, and web technology fingerprinting. This module provides
curated reconnaissance patterns, templates, and signatures for systematic
target enumeration and passive information gathering.

Author: AI Security Research
Version: 1.1
Updated: 2026-02-24
"""

# ============================================================================
# NETWORK_RECON: HTTP-based Port Probing and Service Detection
# ============================================================================

NETWORK_RECON = {
    "http_ports": {
        "description": "Common HTTP service ports for probing",
        "ports": [80, 8080, 8000, 8888, 3000, 5000, 9000, 8443, 8001, 8081],
    },
    "https_ports": {
        "description": "Common HTTPS service ports",
        "ports": [443, 8443, 9443, 4443, 1443],
    },
    "http_probe_templates": {
        "description": "HTTP request templates for service detection",
        "templates": [
            {
                "name": "basic_http_get",
                "method": "GET",
                "path": "/",
                "headers": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "Accept": "*/*",
                    "Connection": "close",
                },
            },
            {
                "name": "http_options",
                "method": "OPTIONS",
                "path": "/",
                "headers": {"Connection": "close"},
            },
            {
                "name": "http_head_request",
                "method": "HEAD",
                "path": "/",
                "headers": {"Connection": "close"},
            },
            {
                "name": "http_version_probe",
                "method": "GET",
                "path": "/",
                "version": "1.0",
            },
        ],
    },
    "service_detection_patterns": {
        "description": "Regex patterns for service identification in HTTP responses",
        "patterns": {
            "apache": r"Apache/[\d.]+",
            "nginx": r"nginx/[\d.]+",
            "iis": r"IIS/[\d.]+",
            "tomcat": r"Apache Tomcat/[\d.]+",
            "node": r"Express|Node\.js",
            "python": r"Python/[\d.]+",
            "php": r"PHP/[\d.]+",
        },
    },
    "port_states": {
        "description": "Port state definitions for response classification",
        "open": "Service accepting connections",
        "closed": "No service listening",
        "filtered": "Firewall blocking access",
        "timeout": "No response received",
    },
}

# ============================================================================
# DNS_ENUMERATION: Zone Transfers, AXFR Requests, and DNS Record Queries
# ============================================================================

DNS_ENUMERATION = {
    "dns_record_types": {
        "description": "Standard DNS record types for enumeration",
        "types": {
            "A": "IPv4 address records",
            "AAAA": "IPv6 address records",
            "CNAME": "Canonical name aliases",
            "MX": "Mail exchange servers",
            "NS": "Nameserver records",
            "SOA": "Start of authority records",
            "TXT": "Text records (SPF, DKIM, DMARC)",
            "SRV": "Service records",
            "PTR": "Pointer/reverse DNS",
            "CAA": "Certificate authority authorization",
        },
    },
    "axfr_queries": {
        "description": "AXFR zone transfer attempt templates",
        "queries": [
            {"type": "AXFR", "class": "IN", "name": "@"},
            {"type": "IXFR", "class": "IN", "name": "@"},
        ],
    },
    "dnssec_queries": {
        "description": "DNSSEC-related queries for zone analysis",
        "queries": [
            {"query_type": "DNSKEY", "purpose": "Retrieve DNSSEC keys"},
            {"query_type": "DS", "purpose": "Delegation signer records"},
            {"query_type": "NSEC", "purpose": "DNSSEC negative proof"},
        ],
    },
    "common_dns_servers": {
        "description": "Public DNS servers for testing",
        "servers": {
            "google": ["8.8.8.8", "8.8.4.4"],
            "cloudflare": ["1.1.1.1", "1.0.0.1"],
            "quad9": ["9.9.9.9", "149.112.112.112"],
            "opendns": ["208.67.222.222", "208.67.220.220"],
        },
    },
    "dns_timing_attack": {
        "description": "DNS query timing patterns for cache analysis",
        "templates": [
            {
                "name": "cache_timing_probe",
                "iterations": 3,
                "delay_ms": 100,
                "measure": "response_time_delta",
            },
        ],
    },
}

# ============================================================================
# SUBDOMAIN_BRUTEFORCE: Curated Wordlist of 300+ Common Subdomains
# ============================================================================

SUBDOMAIN_BRUTEFORCE = {
    "description": "Comprehensive subdomain wordlist for discovery",
    "wordlist": [
        # Administrative interfaces
        "admin", "administrator", "adm", "manage", "management", "manager",
        "console", "control", "backend", "panel", "dashboard",
        
        # API endpoints
        "api", "api-v1", "api-v2", "apiv1", "apiv2", "api.v1", "api.v2",
        "rest", "restapi", "graphql", "grpc", "rpc",
        
        # Development and staging
        "dev", "develop", "development", "stage", "staging", "test", "testing",
        "qa", "uat", "beta", "alpha", "sandbox", "preproduction", "preprod",
        
        # Communication services
        "mail", "email", "smtp", "imap", "pop", "webmail", "roundcube",
        "spam", "bounce", "feedback", "contact", "support",
        
        # File transfer and access
        "ftp", "sftp", "ftps", "files", "file", "download", "upload",
        "share", "sharing", "storage", "backup", "archive", "bucket",
        
        # VPN and remote access
        "vpn", "remote", "access", "ssh", "rdp", "citrix", "anyconnect",
        
        # Content delivery and caching
        "cdn", "cache", "static", "assets", "images", "media", "video",
        "pictures", "audio", "downloads", "resource", "resources",
        
        # Authentication and identity
        "auth", "oauth", "oauth2", "openid", "saml", "ldap", "kerberos",
        "login", "signin", "register", "signup", "account", "accounts",
        "user", "users", "profile", "identity",
        
        # Monitoring and analytics
        "monitor", "monitoring", "analytics", "logs", "logging", "metrics",
        "status", "health", "healthcheck", "check", "ping",
        
        # Web frameworks and CMS indicators
        "wordpress", "wp", "wp-admin", "wp-login", "wp-content", "wp-includes",
        "drupal", "joomla", "magento", "shopify", "wix", "squarespace",
        "ghost", "medium",
        
        # Java/Spring framework
        "actuator", "swagger", "swagger-ui", "springboot", "spring-boot",
        "management", "jolokia", "jmx",
        
        # Configuration and environment files
        "env", "config", "configuration", "settings", "setup", "install",
        ".env", ".git", ".svn", ".hg",
        
        # Documentation and help
        "doc", "docs", "documentation", "help", "wiki", "guide", "readme",
        "changelog", "api-docs", "swagger-docs",
        
        # Build and deployment
        "build", "deploy", "deployment", "release", "version", "artifact",
        "jenkins", "gitlab-ci", "github-actions", "circleci",
        
        # Database and data services
        "db", "database", "mysql", "postgres", "postgresql", "mongodb",
        "redis", "elasticsearch", "sql", "data", "admin",
        
        # Mobile and app services
        "mobile", "app", "apps", "ios", "android", "native", "react",
        "angular", "vue",
        
        # Server and infrastructure
        "server", "servers", "host", "hosting", "cloud", "aws", "azure",
        "gcp", "heroku", "vercel", "netlify",
        
        # Miscellaneous common subdomains
        "www", "web", "main", "index", "home", "public", "private",
        "secure", "ssl", "tls", "cert", "certificate",
        "search", "find", "query", "browse", "explore",
        "product", "products", "service", "services", "feature", "features",
        "price", "pricing", "cost", "quote", "demo", "trial",
        "news", "blog", "press", "social", "community", "forum",
        "event", "events", "calendar", "schedule",
        "career", "careers", "job", "jobs", "hire", "hiring",
        "partner", "partners", "partnership", "affiliate",
        "legal", "privacy", "terms", "policy", "policies",
        "about", "info", "information", "contact", "feedback",
        "error", "errors", "exception", "debug", "trace",
        
        # International and regional
        "en", "de", "fr", "es", "it", "ru", "ja", "cn", "br", "au",
        "uk", "us", "eu", "asia", "americas", "emea",
        
        # Version indicators
        "v1", "v2", "v3", "beta1", "beta2", "rc1", "rc2",
    ],
}

# ============================================================================
# WEB_FINGERPRINTING: HTTP Header Analysis and Technology Detection
# ============================================================================

WEB_FINGERPRINTING = {
    "http_headers_to_analyze": {
        "description": "HTTP response headers for server identification",
        "critical_headers": [
            "Server",
            "X-Powered-By",
            "X-AspNet-Version",
            "X-Runtime",
            "X-Generation",
            "X-Originating-IP",
            "X-Forwarded-For",
            "Via",
        ],
    },
    "technology_signatures": {
        "description": "Signature patterns for framework and technology detection",
        "signatures": {
            "apache_modules": r"(mod_ssl|mod_security|mod_rewrite|mod_php)",
            "php_indicators": r"(php-fpm|PHP/[\d.]+|X-Powered-By: PHP)",
            "nodejs_indicators": r"(Express|Node\.js|nestjs|hapi|koa)",
            "java_indicators": r"(Apache Tomcat|JBoss|Jetty|GlassFish|Oracle WebLogic)",
            "python_indicators": r"(Django|Flask|FastAPI|Pyramid|Tornado)",
            "ruby_indicators": r"(Ruby on Rails|Sinatra|Rack)",
            "dotnet_indicators": r"(ASP\.NET|IIS|\.NET Framework)",
            "golang_indicators": r"(Go|Gin|Beego|Echo|Revel)",
        },
    },
    "framework_detection_paths": {
        "description": "URLs and patterns for detecting specific frameworks",
        "paths": [
            {
                "path": "/wp-admin",
                "framework": "WordPress",
                "method": "GET",
            },
            {
                "path": "/wp-login.php",
                "framework": "WordPress",
                "method": "GET",
            },
            {
                "path": "/actuator",
                "framework": "Spring Boot",
                "method": "GET",
            },
            {
                "path": "/swagger-ui.html",
                "framework": "Swagger",
                "method": "GET",
            },
            {
                "path": "/swagger-ui/",
                "framework": "Swagger",
                "method": "GET",
            },
            {
                "path": "/swagger.json",
                "framework": "Swagger",
                "method": "GET",
            },
            {
                "path": "/graphql",
                "framework": "GraphQL",
                "method": "GET",
            },
            {
                "path": "/.env",
                "framework": "Environment Config",
                "method": "GET",
            },
            {
                "path": "/.env.local",
                "framework": "Environment Config",
                "method": "GET",
            },
            {
                "path": "/.env.example",
                "framework": "Environment Config",
                "method": "GET",
            },
            {
                "path": "/.git/config",
                "framework": "Git Repository",
                "method": "GET",
            },
            {
                "path": "/.gitignore",
                "framework": "Git Repository",
                "method": "GET",
            },
            {
                "path": "/admin",
                "framework": "Generic Admin",
                "method": "GET",
            },
            {
                "path": "/admin/",
                "framework": "Generic Admin",
                "method": "GET",
            },
            {
                "path": "/config.php",
                "framework": "PHP Config",
                "method": "GET",
            },
            {
                "path": "/web.config",
                "framework": "ASP.NET Config",
                "method": "GET",
            },
        ],
    },
    "html_meta_analysis": {
        "description": "HTML meta tags and generators for identification",
        "patterns": {
            "generator": r'<meta name="generator" content="([^"]+)"',
            "platform": r'<meta name="platform" content="([^"]+)"',
            "technology_stack": r'<meta name="keywords" content="([^"]+)"',
            "framework_comments": r"<!-- (.*?)(Powered by|Generated by|Built with|Framework|CMS)(.*?) -->",
        },
    },
    "success_indicators": {
        "description": "HTTP status codes and patterns indicating successful fingerprinting",
        "status_codes": [200, 301, 302, 401, 403],
        "response_patterns": [
            "Server header present",
            "X-Powered-By header found",
            "Framework-specific paths accessible",
            "Meta generator tag detected",
            "Version information in headers",
        ],
    },
}

# ============================================================================
# SERVICE_DETECTION: Banner Grabbing and Version Fingerprinting
# ============================================================================

SERVICE_DETECTION = {
    "banner_grab_templates": {
        "description": "Service-specific banner grabbing sequences",
        "services": {
            "ssh": {
                "port": 22,
                "probe": "SSH-2.0-OpenSSH_7.4\n",
                "timeout": 5,
            },
            "ftp": {
                "port": 21,
                "probe": "USER anonymous\n",
                "timeout": 5,
            },
            "http": {
                "port": 80,
                "probe": "HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
                "timeout": 5,
            },
            "https": {
                "port": 443,
                "probe": "CONNECT / HTTP/1.0\r\n\r\n",
                "timeout": 5,
            },
            "smtp": {
                "port": 25,
                "probe": "EHLO target\n",
                "timeout": 5,
            },
            "pop3": {
                "port": 110,
                "probe": "USER admin\n",
                "timeout": 5,
            },
            "imap": {
                "port": 143,
                "probe": "A001 CAPABILITY\n",
                "timeout": 5,
            },
            "telnet": {
                "port": 23,
                "probe": "\n",
                "timeout": 5,
            },
            "ldap": {
                "port": 389,
                "probe": "ldapsearch -H ldap://target",
                "timeout": 5,
            },
            "mysql": {
                "port": 3306,
                "probe": "handshake",
                "timeout": 5,
            },
            "postgresql": {
                "port": 5432,
                "probe": "startup_message",
                "timeout": 5,
            },
        },
    },
    "version_fingerprinting_regex": {
        "description": "Regular expressions for extracting version information",
        "patterns": {
            "apache": r"Apache/(?P<version>[\d.]+)(?:\s*\((?P<os>[^)]+)\))?",
            "nginx": r"nginx/(?P<version>[\d.]+)",
            "iis": r"IIS/(?P<version>[\d.]+)",
            "tomcat": r"Apache Tomcat/(?P<version>[\d.]+)",
            "openssh": r"OpenSSH[_-](?P<version>[\d.p]+)",
            "vsftpd": r"vsftpd (?P<version>[\d.]+)",
            "postfix": r"Postfix (?P<version>[\d.]+)",
            "sendmail": r"Sendmail (?P<version>[\d.]+)/(?P<patch>[\d.]+)",
            "exim": r"Exim (?P<version>[\d.]+)",
            "dovecot": r"Dovecot (?P<version>[\d.]+)",
            "bind": r"BIND (?P<version>[\d.]+)",
            "bind9": r"named (?P<version>[\d.]+)",
            "mysql": r"MySQL (?P<version>[\d.]+)",
            "postgresql": r"PostgreSQL (?P<version>[\d.]+)",
            "redis": r"redis_version:(?P<version>[\d.]+)",
            "mongodb": r"v(?P<version>[\d.]+)",
        },
    },
    "success_indicators": {
        "description": "Indicators of successful service detection",
        "valid_responses": [
            "Banner received within timeout",
            "Version information extracted",
            "Service-specific protocol markers detected",
            "Expected response format matched",
        ],
    },
}

# ============================================================================
# INTEGRATED SUCCESS INDICATORS
# ============================================================================

SUCCESS_INDICATORS = {
    "network_recon": {
        "service_detected": "Port responds to probe within timeout",
        "version_identified": "Service version extracted from response",
        "protocol_confirmed": "Protocol behavior matches expected pattern",
    },
    "dns_enumeration": {
        "zone_transfer_successful": "AXFR returns complete zone data",
        "records_enumerated": "Target DNS records retrieved successfully",
        "subdomain_discovered": "New subdomain resolved via DNS query",
    },
    "subdomain_bruteforce": {
        "subdomain_found": "Wordlist entry resolves to valid IP address",
        "wildcard_detected": "All queries resolve to same IP (wildcard)",
        "enumeration_complete": "Wordlist fully processed",
    },
    "web_fingerprinting": {
        "framework_identified": "Framework signature matched in headers or content",
        "version_disclosed": "Service version found in HTTP headers",
        "technology_stack_revealed": "Multiple technologies identified and mapped",
        "config_exposed": "Framework configuration file accessible",
    },
    "service_detection": {
        "banner_captured": "Service banner successfully retrieved",
        "version_extracted": "Version regex successfully matched response",
        "vulnerability_window": "Known vulnerable version identified",
    },
}

# ============================================================================
# METADATA AND CONSTANTS
# ============================================================================

RECONNAISSANCE_METADATA = {
    "tier": "1.1",
    "category": "Reconnaissance & Enumeration",
    "techniques": [
        "Network scanning",
        "DNS enumeration",
        "Subdomain discovery",
        "Web fingerprinting",
        "Service detection",
        "Banner grabbing",
    ],
    "passive_active_mix": "Primarily passive with optional active probing",
    "legal_disclaimer": "Use only on authorized systems during authorized security testing",
    "timestamp": "2026-02-24",
}

# ============================================================================
# UTILITY HELPERS
# ============================================================================

def get_all_reconnaissance_payloads():
    """
    Aggregates all reconnaissance payloads into a single dictionary.
    
    Returns:
        dict: Complete payload collection for reconnaissance operations
    """
    return {
        "network_recon": NETWORK_RECON,
        "dns_enumeration": DNS_ENUMERATION,
        "subdomain_bruteforce": SUBDOMAIN_BRUTEFORCE,
        "web_fingerprinting": WEB_FINGERPRINTING,
        "service_detection": SERVICE_DETECTION,
        "success_indicators": SUCCESS_INDICATORS,
    }


def get_subdomain_wordlist():
    """
    Returns the curated subdomain wordlist for brute force operations.
    
    Returns:
        list: Subdomain wordlist (300+ entries)
    """
    return SUBDOMAIN_BRUTEFORCE["wordlist"]


# ============================================================================
# Compatibility Aliases for Module Imports
# ============================================================================
HTTP_TECH_FINGERPRINTING = WEB_FINGERPRINTING

COMMON_PATHS = {
    "common_endpoints": WEB_FINGERPRINTING.get("framework_detection_paths", {}).get("generic_paths", []),
    "admin_paths": ["/admin", "/admin/login", "/administrator", "/wp-admin", "/cpanel"],
    "api_paths": ["/api", "/api/v1", "/api/v2", "/graphql", "/swagger", "/openapi.json"],
    "config_paths": ["/.env", "/config.json", "/settings.json", "/web.config", "/.git/config"],
}

FINGERPRINT_INDICATORS = WEB_FINGERPRINTING.get("technology_signatures", {})


if __name__ == "__main__":
    # Example usage and payload inspection
    payloads = get_all_reconnaissance_payloads()
    print(f"Reconnaissance Payloads - Tier {RECONNAISSANCE_METADATA['tier']}")
    print(f"Total categories: {len(payloads)}")
    for category, data in payloads.items():
        print(f"  - {category}")
