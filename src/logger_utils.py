import logging
from pathlib import Path

def setup_logger(
    log_dir: str | Path = "logs",
    log_name: str = "run.log",
    console_level: str = "INFO",
    file_level: str = "DEBUG",
) -> logging.Logger:
    """
    Create (or fetch) a root logger that…
        • writes *everything* ≥ file_level to <log_dir>/<log_name>
        • echoes messages ≥ console_level to the terminal

    Parameters
    ----------
    log_dir       : folder for the log file (created if it doesn’t exist)
    log_name      : file name (will be appended to log_dir)
    console_level : 'DEBUG' | 'INFO' | 'WARNING' | 'ERROR' | 'CRITICAL'
    file_level    : same choices; usually 'DEBUG'.

    Returns
    -------
    logger        : configured root logger (use logging.getLogger() elsewhere)
    """
    # convert strings to logging levels
    c_lvl = getattr(logging, console_level.upper(), logging.INFO)
    f_lvl = getattr(logging, file_level.upper(), logging.DEBUG)

    Path(log_dir).mkdir(parents=True, exist_ok=True)
    log_path = Path(log_dir) / log_name

    logger = logging.getLogger()             # root
    logger.setLevel(logging.DEBUG)           # capture EVERYTHING

    # flush previous handlers if this is called twice in notebooks
    if not logger.handlers:
        # ---- file handler ----
        fh = logging.FileHandler(log_path, mode="w")
        fh.setLevel(f_lvl)
        fh.setFormatter(
            logging.Formatter(
                fmt="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        )
        logger.addHandler(fh)

        # ---- console handler ----
        ch = logging.StreamHandler()
        ch.setLevel(c_lvl)
        ch.setFormatter(
            logging.Formatter(
                fmt="%(levelname)-7s | %(message)s",
            )
        )
        logger.addHandler(ch)

    logger.info(f"Logger started. Writing to {log_path}")
    return logger
