"""Módulo de notificaciones para Discord.

Este módulo proporciona funcionalidad para enviar notificaciones
a canales de Discord usando webhooks.
"""

import logging

import requests
from requests.exceptions import ConnectionError, HTTPError, RequestException, Timeout

# Configurar logger para este módulo
logger = logging.getLogger(__name__)


def send_discord_notification(webhook_url: str, message: str, timeout: int = 10) -> bool:
    """Envía una notificación a Discord usando un webhook.

    Args:
        webhook_url: URL del webhook de Discord
        message: Mensaje a enviar
        timeout: Tiempo límite para la petición en segundos (default: 10)

    Returns:
        True si el envío fue exitoso (código 2xx), False en caso contrario

    Raises:
        ValueError: Si webhook_url o message están vacíos
    """
    # Validación de parámetros de entrada
    if not webhook_url or not webhook_url.strip():
        logger.error("webhook_url no puede estar vacío")
        raise ValueError("webhook_url no puede estar vacío")

    if not message or not message.strip():
        logger.error("message no puede estar vacío")
        raise ValueError("message no puede estar vacío")

    # Preparar el payload JSON
    payload = {"content": message.strip()}

    # Headers para la petición
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Ultra-BugBountyScanner/1.0",
    }

    try:
        logger.info(f"Enviando notificación a Discord: {message[:100]}...")

        # Realizar la petición POST
        response = requests.post(
            webhook_url.strip(),
            json=payload,
            headers=headers,
            timeout=timeout,
        )

        # Verificar el código de estado
        if 200 <= response.status_code < 300:
            logger.info(f"Notificación enviada exitosamente (código: {response.status_code})")
            return True
        logger.warning(f"Discord respondió con código {response.status_code}: {response.text[:200]}")
        return False

    except Timeout:
        logger.error(f"Timeout al enviar notificación a Discord (timeout: {timeout}s)")
        return False

    except ConnectionError:
        logger.error("Error de conexión al enviar notificación a Discord")
        return False

    except HTTPError as e:
        logger.error(f"Error HTTP al enviar notificación a Discord: {e}")
        return False

    except RequestException as e:
        logger.error(f"Error en la petición a Discord: {e}")
        return False

    except Exception as e:
        logger.error(f"Error inesperado al enviar notificación a Discord: {e}")
        return False
