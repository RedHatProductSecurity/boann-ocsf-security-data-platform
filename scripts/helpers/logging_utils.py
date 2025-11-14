import logging


def setup_logging(log_level: str) -> None:
    """Configures the logging for the script."""
    log_level = log_level.upper()

    # Try to get the log level using public API
    numeric_level = getattr(logging, log_level, None)

    # If exact match fails, try common abbreviations
    if numeric_level is None:
        level_map = {
            "CRIT": logging.CRITICAL,
            "ERR": logging.ERROR,
            "WARN": logging.WARNING,
            "INFO": logging.INFO,
            "DBG": logging.DEBUG,
        }
        # Try to find a matching abbreviation
        for abbrev, level in level_map.items():
            if abbrev.startswith(log_level):
                numeric_level = level
                break

    # Default to INFO if still not found
    if numeric_level is None:
        logging.warning(f"Invalid log level '{log_level}'. Defaulting to 'INFO'")
        numeric_level = logging.INFO

    logging.basicConfig(
        level=numeric_level,
        format="%(asctime)s - [%(threadName)s] - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        force=True,  # Force reconfiguration even if handlers already exist
    )
    logging.debug("Logging has been configured.")
