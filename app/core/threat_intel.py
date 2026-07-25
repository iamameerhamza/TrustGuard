import os
import logging

# Set up logger
logger = logging.getLogger(__name__)

_blacklist = frozenset()

def load_blacklist(filepath: str = "data/blacklist.txt") -> bool:
    """Load URLs from blacklist file into memory for fast lookups.
    
    Args:
        filepath: Path to the blacklist file
        
    Returns:
        bool: True if blacklist loaded successfully, False otherwise
    """
    global _blacklist
    try:
        if not os.path.exists(filepath):
            logger.warning(f"Blacklist file {filepath} not found. Threat intel disabled.")
            _blacklist = frozenset()
            return False
        
        with open(filepath, 'r', encoding='utf-8') as f:
            # Load all non-empty lines into a set for O(1) lookups
            urls = {line.strip() for line in f if line.strip()}
        
        _blacklist = frozenset(urls)
        logger.info(f"Loaded {len(_blacklist)} URLs into the blacklist from {filepath}")
        return True
        
    except FileNotFoundError:
        logger.error(f"Blacklist file not found: {filepath}")
        _blacklist = frozenset()
        return False
    except PermissionError:
        logger.error(f"Permission denied reading blacklist file: {filepath}")
        _blacklist = frozenset()
        return False
    except Exception as e:
        logger.error(f"Failed to load blacklist from {filepath}: {e}")
        _blacklist = frozenset()
        return False

def check_blacklist(url: str) -> bool:
    """Check if URL is present in the blacklist.
    
    Args:
        url: The URL to check
        
    Returns:
        bool: True if URL is blacklisted, False otherwise
    """
    # A simple exact match check. Could be expanded to domain-level checks.
    return url in _blacklist