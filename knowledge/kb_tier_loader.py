"""
KB Tier Loader Module

Bulk-loads Tier 1 static payloads into the Knowledge Base on startup.
Provides efficient initialization of payload entries for quick access and retrieval.
"""

import logging
from typing import Optional

from knowledge.knowledge_base import KnowledgeBase

# Configure logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


def load_tier1_into_kb(kb: Optional[KnowledgeBase] = None) -> int:
    """
    Load all Tier 1 static payloads into the Knowledge Base.
    
    This function:
    1. Creates a KB instance if none provided
    2. Checks if already loaded via sentinel entry
    3. Iterates through all Tier 1 payload categories
    4. Adds them as KB entries with proper metadata
    5. Creates sentinel entry to prevent duplicate loading
    6. Returns count of entries added
    
    Args:
        kb: Optional existing KnowledgeBase instance. If None, creates a new one.
        
    Returns:
        int: Number of entries added to the knowledge base.
    """
    
    # Create KB instance if not provided
    if kb is None:
        kb = KnowledgeBase()
        logger.info("Created new KnowledgeBase instance for tier1 loading")
    
    # Check if already loaded via sentinel entry
    sentinel_query = kb.search(title="tier1_loaded")
    if sentinel_query and len(sentinel_query) > 0:
        logger.info("Tier 1 payloads already loaded into KB, skipping")
        return 0
    
    logger.info("Starting Tier 1 payload loading into Knowledge Base")
    
    entries_added = 0
    tier1_modules = {
        "credentials": None,
        "reconnaissance": None,
        "web_attacks": None,
        "cve_database": None,
    }
    
    # Try to import all tier1 payload modules
    try:
        from payloads import tier1_credentials
        tier1_modules["credentials"] = tier1_credentials
        logger.debug("Successfully imported tier1_credentials")
    except ImportError as e:
        logger.warning(f"Could not import tier1_credentials: {e}")
    
    try:
        from payloads import tier1_reconnaissance
        tier1_modules["reconnaissance"] = tier1_reconnaissance
        logger.debug("Successfully imported tier1_reconnaissance")
    except ImportError as e:
        logger.warning(f"Could not import tier1_reconnaissance: {e}")
    
    try:
        from payloads import tier1_web_attacks
        tier1_modules["web_attacks"] = tier1_web_attacks
        logger.debug("Successfully imported tier1_web_attacks")
    except ImportError as e:
        logger.warning(f"Could not import tier1_web_attacks: {e}")
    
    try:
        from payloads import tier1_cve_database
        tier1_modules["cve_database"] = tier1_cve_database
        logger.debug("Successfully imported tier1_cve_database")
    except ImportError as e:
        logger.warning(f"Could not import tier1_cve_database: {e}")
    
    # Load entries from each module
    for category, module in tier1_modules.items():
        if module is None:
            logger.warning(f"Skipping {category} - module not available")
            continue
        
        try:
            # Get payload data from module
            payloads_data = getattr(module, "PAYLOADS", {})
            
            for payload_name, payload_info in payloads_data.items():
                try:
                    # Extract metadata from payload info
                    title = payload_name
                    description = payload_info.get("description", "")
                    severity = payload_info.get("severity", "medium")
                    target_types = payload_info.get("target_types", [])
                    
                    # Add entry to KB
                    kb.add_entry(
                        title=title,
                        content=description,
                        category="payload",
                        subcategory=category,
                        target_types=target_types,
                        severity=severity,
                        metadata={"tier": 1, "module": category}
                    )
                    entries_added += 1
                    logger.debug(f"Added Tier 1 entry: {title} from {category}")
                    
                except Exception as e:
                    logger.error(f"Error adding entry {payload_name} from {category}: {e}")
                    continue
        
        except Exception as e:
            logger.error(f"Error processing {category} module: {e}")
            continue
    
    # Create sentinel entry to mark completion
    try:
        kb.add_entry(
            title="tier1_loaded",
            content="Tier 1 payloads have been loaded into the knowledge base",
            category="system",
            subcategory="loader",
            metadata={"tier": 1, "is_sentinel": True, "entries_loaded": entries_added}
        )
        logger.info(f"Created sentinel entry. Total Tier 1 entries loaded: {entries_added}")
    except Exception as e:
        logger.error(f"Error creating sentinel entry: {e}")
    
    logger.info(f"Tier 1 payload loading complete. Added {entries_added} entries")
    return entries_added


if __name__ == "__main__":
    # Example usage
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    count = load_tier1_into_kb()
    print(f"Loaded {count} Tier 1 entries into Knowledge Base")
