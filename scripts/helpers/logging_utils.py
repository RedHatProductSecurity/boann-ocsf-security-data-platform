import logging


def setup_logging(log_level: str) -> None:
    """Configures the logging for the script."""
    log_level = log_level.upper()

    # Find the corresponding integer log level
    numeric_level = None
    for level_name, level_val in logging._nameToLevel.items():
        if level_name.startswith(log_level):
            numeric_level = level_val
            break
    else:
        logging.warning(f"Error: Invalid log level '{log_level}'. Defaulting to 'info'")
        numeric_level = logging._nameToLevel["INFO"]

    if not isinstance(numeric_level, int):
        raise ValueError(f"Invalid log level: {log_level}")

    logging.basicConfig(
        level=numeric_level,
        format="%(asctime)s - [%(threadName)s] - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        force=True,  # Force reconfiguration even if handlers already exist
    )
    logging.debug("Logging has been configured.")
