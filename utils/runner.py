#!/usr/bin/env python3
"""Command Runner Utility.

Author: danielxxomg2
"""

import shlex
import subprocess  # nosec B404 - Necesario para ejecutar herramientas de seguridad
from typing import Optional, Union

from .logger import get_logger

logger = get_logger("runner")


def run_command(
    command: Union[str, list[str]], shell: bool = False, timeout: int = 3600
) -> tuple[Optional[str], Optional[str]]:
    """Ejecuta un comando de sistema de forma segura, loggeando la salida.

    Args:
        command: El comando a ejecutar (string o lista de strings).
        shell: Si es True, ejecuta el comando a través de la shell (¡usar con cuidado!).
        timeout: Timeout en segundos para el comando.

    Returns:
        Tuple con (stdout, stderr). Si hay error, stdout será None.

    Raises:
        No lanza excepciones, maneja todos los errores internamente.
    """
    cmd_str = " ".join(shlex.quote(c) for c in command) if isinstance(command, list) and not shell else command

    logger.debug(f"Executing command: {cmd_str}")

    try:
        # Usamos Popen para tener un mejor control sobre procesos largos
        # Validación de seguridad para shell=True
        if shell and isinstance(command, str):
            # Verificar que no contenga caracteres peligrosos cuando se usa shell=True
            dangerous_chars = [";", "&", "|", "`", "$", "(", ")"]
            if any(char in command for char in dangerous_chars):
                logger.error(f"Comando potencialmente peligroso detectado: {command}")
                return None, "Comando rechazado por razones de seguridad"

        process = subprocess.Popen(  # nosec B602 - shell=True controlado y validado
            cmd_str if shell else command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=shell,
            encoding="utf-8",
            errors="replace",
        )

        stdout, stderr = process.communicate(timeout=timeout)

        if stdout:
            logger.debug(f"Stdout for '{cmd_str}':\n{stdout.strip()}")

        if process.returncode != 0:
            logger.error(f"Command '{cmd_str}' failed with exit code {process.returncode}.")
            if stderr:
                logger.error(f"Stderr:\n{stderr.strip()}")
            return None, stderr

        return stdout, stderr

    except FileNotFoundError:
        cmd_name = command[0] if isinstance(command, list) else command.split()[0]
        logger.error(f"Command not found: '{cmd_name}'. Is it installed and in PATH?")
        return None, f"Command not found: {cmd_name}"
    except subprocess.TimeoutExpired:
        logger.warning(f"Command '{cmd_str}' timed out after {timeout} seconds. Killing process.")
        process.kill()
        return None, "Command timed out."
    except Exception as e:
        logger.exception(f"An unexpected error occurred while running '{cmd_str}'.")
        return None, str(e)
