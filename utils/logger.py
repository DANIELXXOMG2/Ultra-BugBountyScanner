#!/usr/bin/env python3
"""Ultra Logger Module.

Author: danielxxomg2
"""

import logging
import os
import sys
from typing import Any, Optional

try:
    import colorama
    from colorama import Fore, Style

    colorama.init(autoreset=True)
    COLORS_AVAILABLE = True
except ImportError:
    COLORS_AVAILABLE = False

    # Fallback classes when colorama is not available
    class _Fore:
        """Fallback color codes when colorama is not available."""

        RED = ""
        GREEN = ""
        YELLOW = ""
        BLUE = ""
        MAGENTA = ""
        CYAN = ""
        WHITE = ""
        RESET = ""

    class _Style:
        """Fallback style codes when colorama is not available."""

        BRIGHT = ""
        RESET_ALL = ""

    Fore = _Fore()
    Style = _Style()


class ColoredFormatter(logging.Formatter):
    """Custom formatter with color support for console output."""

    LOG_COLORS: dict[str, str] = {
        "DEBUG": Fore.CYAN,
        "INFO": Fore.BLUE,
        "SUCCESS": Fore.GREEN,
        "WARNING": Fore.YELLOW,
        "ERROR": Fore.RED,
        "CRITICAL": Fore.MAGENTA + Style.BRIGHT,
    }

    def format(self, record: logging.LogRecord) -> str:
        """Format log record with colors."""
        # Nivel de log personalizado "SUCCESS"
        if not hasattr(record, "success"):
            record.success = False

        log_level = "SUCCESS" if getattr(record, "success") else record.levelname
        color = self.LOG_COLORS.get(log_level, Fore.WHITE)

        # Formato del mensaje
        return f"{color}[{log_level[0]}] {record.getMessage()}{Style.RESET_ALL}"


class UltraLogger(logging.Logger):
    """Logger principal personalizado para el scanner."""

    def __init__(self, name: str, level: int = logging.NOTSET) -> None:
        """Initialize the custom logger."""
        super().__init__(name, level)
        # Añadir nivel SUCCESS
        logging.addLevelName(25, "SUCCESS")

    def success(self, msg: Any, *args: Any, **kwargs: Any) -> None:
        """Log a success message."""
        if self.isEnabledFor(25):
            self._log(25, msg, args, extra={"success": True}, **kwargs)


# Configuración del singleton para el logger
_logger_instance: Optional[UltraLogger] = None


def get_logger(name: str = "scanner") -> UltraLogger:
    """Obtiene la instancia global y configurada del logger."""
    global _logger_instance
    if _logger_instance is None:
        logging.setLoggerClass(UltraLogger)
        logger = logging.getLogger(name)
        logger.setLevel(os.getenv("LOG_LEVEL", "INFO").upper())

        # Evitar duplicar handlers
        if not logger.handlers:
            # Handler para la consola
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setFormatter(ColoredFormatter())
            logger.addHandler(console_handler)

            # Puedes añadir un FileHandler aquí si lo deseas
            # file_handler = logging.FileHandler('scanner.log')
            # file_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
            # logger.addHandler(file_handler)

        _logger_instance = logger  # type: ignore[assignment]

    return _logger_instance  # type: ignore[return-value]
