#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Command Runner Utility
Author: danielxxomg2
"""
import subprocess
import shlex
from typing import Union

from .logger import get_logger

logger = get_logger('runner')

def run_command(command: Union[str, list[str]], shell=False, timeout=3600):
    """
    Ejecuta un comando de sistema de forma segura, loggeando la salida.
    
    :param command: El comando a ejecutar (string o lista de strings).
    :param shell: Si es True, ejecuta el comando a través de la shell (¡usar con cuidado!).
    :param timeout: Timeout en segundos para el comando.
    """
    if isinstance(command, list) and not shell:
        cmd_str = ' '.join(shlex.quote(c) for c in command)
    else:
        cmd_str = command
    
    logger.debug(f"Executing command: {cmd_str}")
    
    try:
        # Usamos Popen para tener un mejor control sobre procesos largos
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=shell,
            encoding='utf-8',
            errors='replace'
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
