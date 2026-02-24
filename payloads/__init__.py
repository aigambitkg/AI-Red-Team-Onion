"""
Payloads Registry Module

Provides a centralized registry and access point for all threat payloads
organized by tier (1, 2, 3) and category (SQL injection, XSS, etc).
"""

import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# Define tier categories mapping
TIER_CATEGORIES = {
    1: [
        "credentials",
        "reconnaissance", 
        "web_attacks",
        "cve_database",
    ],
    2: [
        "privilege_escalation",
        "persistence",
        "evasion",
        "lateral_movement",
    ],
    3: [
        "custom",
        "advanced",
        "experimental",
    ]
}

# Payload category mappings
PAYLOAD_CATEGORIES = {
    "credentials": "Authentication and credential-based attacks",
    "reconnaissance": "Information gathering and target discovery",
    "web_attacks": "Web application and API attacks",
    "cve_database": "Known vulnerability exploitation",
    "privilege_escalation": "Techniques to elevate access privileges",
    "persistence": "Methods to maintain access",
    "evasion": "Detection and defensive measure evasion",
    "lateral_movement": "Techniques to move within networks",
    "custom": "Custom payload definitions",
    "advanced": "Advanced exploitation techniques",
    "experimental": "Experimental and research payloads",
}

# Module references dictionary
_tier_modules = {
    "tier1": {},
    "tier2": {},
    "tier3": {},
}

# Attempt to import all tier modules
try:
    from payloads import tier1_credentials
    _tier_modules["tier1"]["credentials"] = tier1_credentials
    logger.debug("Loaded tier1_credentials module")
except ImportError as e:
    logger.warning(f"Could not import tier1_credentials: {e}")

try:
    from payloads import tier1_reconnaissance
    _tier_modules["tier1"]["reconnaissance"] = tier1_reconnaissance
    logger.debug("Loaded tier1_reconnaissance module")
except ImportError as e:
    logger.warning(f"Could not import tier1_reconnaissance: {e}")

try:
    from payloads import tier1_web_attacks
    _tier_modules["tier1"]["web_attacks"] = tier1_web_attacks
    logger.debug("Loaded tier1_web_attacks module")
except ImportError as e:
    logger.warning(f"Could not import tier1_web_attacks: {e}")

try:
    from payloads import tier1_cve_database
    _tier_modules["tier1"]["cve_database"] = tier1_cve_database
    logger.debug("Loaded tier1_cve_database module")
except ImportError as e:
    logger.warning(f"Could not import tier1_cve_database: {e}")

try:
    from payloads import tier2_privilege_escalation
    _tier_modules["tier2"]["privilege_escalation"] = tier2_privilege_escalation
    logger.debug("Loaded tier2_privilege_escalation module")
except ImportError as e:
    logger.debug(f"Tier 2 modules not yet available: {e}")

try:
    from payloads import tier2_persistence
    _tier_modules["tier2"]["persistence"] = tier2_persistence
    logger.debug("Loaded tier2_persistence module")
except ImportError as e:
    logger.debug(f"Tier 2 modules not yet available: {e}")

try:
    from payloads import tier3_custom
    _tier_modules["tier3"]["custom"] = tier3_custom
    logger.debug("Loaded tier3_custom module")
except ImportError as e:
    logger.debug(f"Tier 3 modules not yet available: {e}")


def get_all_tier1_payloads() -> Dict:
    """
    Get merged dictionary of all Tier 1 payloads.
    
    Tier 1 payloads are static, pre-defined attack patterns and credentials.
    
    Returns:
        Dict: Merged dictionary containing all Tier 1 payloads from all categories.
              Returns empty dict if no modules are loaded.
    """
    merged_payloads = {}

    # Map category → main export names
    _CATEGORY_EXPORTS = {
        "credentials": ["DEFAULT_CREDENTIALS", "COMMON_PASSWORDS", "API_KEY_PATTERNS", "UNSECURED_ENDPOINTS"],
        "reconnaissance": ["NETWORK_RECON", "DNS_ENUMERATION", "SUBDOMAIN_BRUTEFORCE", "WEB_FINGERPRINTING", "SERVICE_DETECTION"],
        "web_attacks": ["SQL_INJECTION", "CROSS_SITE_SCRIPTING", "COMMAND_INJECTION", "SSRF", "PATH_TRAVERSAL", "TEMPLATE_INJECTION"],
        "cve_database": ["CVE_REGISTRY", "SERVICE_CVE_MAP"],
    }

    for category, module in _tier_modules.get("tier1", {}).items():
        if module is None:
            continue
        try:
            # First try PAYLOADS attribute
            payloads = getattr(module, "PAYLOADS", None)
            if payloads:
                merged_payloads.update(payloads)
            else:
                # Fallback: collect known exports for this category
                export_names = _CATEGORY_EXPORTS.get(category, [])
                for name in export_names:
                    val = getattr(module, name, None)
                    if val is not None:
                        merged_payloads[name.lower()] = val
            logger.debug(f"Merged payloads from tier1_{category}")
        except Exception as e:
            logger.error(f"Error merging tier1_{category} payloads: {e}")

    return merged_payloads


def get_payloads_by_category(category: str) -> Dict:
    """
    Get payloads for a specific category.
    
    Args:
        category: Category name like "sql_injection", "xss", "credentials", etc.
                 Can be a tier1/tier2/tier3 subcategory.
    
    Returns:
        Dict: Payloads matching the specified category, or empty dict if not found.
    """
    # Search through all tiers
    for tier_name, modules in _tier_modules.items():
        for cat_name, module in modules.items():
            # Match category by exact name or partial match
            if cat_name == category or category in cat_name:
                if module is None:
                    return {}
                try:
                    return getattr(module, "PAYLOADS", {})
                except Exception as e:
                    logger.error(f"Error retrieving payloads from {tier_name}_{cat_name}: {e}")
                    return {}
    
    logger.warning(f"Category '{category}' not found in any tier modules")
    return {}


def get_tier_modules() -> Dict[str, List]:
    """
    Get dictionary of tier modules and their available categories.
    
    Returns:
        Dict: Structure like:
        {
            "tier1": ["credentials", "reconnaissance", "web_attacks", ...],
            "tier2": ["privilege_escalation", "persistence", ...],
            "tier3": ["custom", "advanced", ...],
        }
    """
    tier_structure = {}
    
    for tier_name, modules in _tier_modules.items():
        tier_structure[tier_name] = list(modules.keys())
    
    return tier_structure


def get_payload_count(tier: Optional[int] = None) -> int:
    """
    Get total count of payloads, optionally filtered by tier.
    
    Args:
        tier: Optional tier number (1, 2, or 3). If None, returns total across all tiers.
    
    Returns:
        int: Number of payloads matching criteria.
    """
    count = 0
    
    if tier is None:
        # Count all tiers
        for tier_name, modules in _tier_modules.items():
            for module in modules.values():
                if module is not None:
                    payloads = getattr(module, "PAYLOADS", {})
                    count += len(payloads)
    else:
        # Count specific tier
        tier_key = f"tier{tier}"
        if tier_key in _tier_modules:
            for module in _tier_modules[tier_key].values():
                if module is not None:
                    payloads = getattr(module, "PAYLOADS", {})
                    count += len(payloads)
    
    return count


def is_module_available(tier: int, category: str) -> bool:
    """
    Check if a specific tier/category module is available.
    
    Args:
        tier: Tier number (1, 2, or 3)
        category: Category name
    
    Returns:
        bool: True if module is loaded and available, False otherwise.
    """
    tier_key = f"tier{tier}"
    return (tier_key in _tier_modules and 
            category in _tier_modules[tier_key] and 
            _tier_modules[tier_key][category] is not None)


# Public API exports
__all__ = [
    "get_all_tier1_payloads",
    "get_payloads_by_category",
    "get_tier_modules",
    "get_payload_count",
    "is_module_available",
    "TIER_CATEGORIES",
    "PAYLOAD_CATEGORIES",
]
