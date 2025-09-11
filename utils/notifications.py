"""Módulo de notificaciones para Discord.

Este módulo proporciona funcionalidades para enviar notificaciones
a Discord mediante webhooks y formatear resúmenes de escaneos.
"""

from typing import Optional

import requests
from requests.exceptions import RequestException, Timeout

from utils.logger import UltraLogger

# Configurar logger
logger = UltraLogger("notifications")


def send_discord_notification(webhook_url: str, message: str) -> bool:
    """Envía una notificación a Discord mediante webhook.

    Args:
        webhook_url: URL del webhook de Discord
        message: Mensaje a enviar

    Returns:
        True si el envío fue exitoso (status code 2xx), False en caso contrario

    Raises:
        ValueError: Si webhook_url o message están vacíos
    """
    # Validación de entrada
    if not webhook_url or not webhook_url.strip():
        raise ValueError("webhook_url no puede estar vacío")

    if not message or not message.strip():
        raise ValueError("message no puede estar vacío")

    # Preparar payload
    payload = {"content": message.strip()}

    # Headers de seguridad
    headers = {"Content-Type": "application/json", "User-Agent": "Ultra-BugBountyScanner/1.0"}

    try:
        logger.info(f"Enviando notificación a Discord: {len(message)} caracteres")

        # Realizar petición POST con timeout
        response = requests.post(
            webhook_url,
            json=payload,
            headers=headers,
            timeout=10,  # Timeout de 10 segundos
        )

        # Verificar status code
        if 200 <= response.status_code < 300:
            logger.info(f"Notificación enviada exitosamente (status: {response.status_code})")
            return True
        logger.error(
            f"Error al enviar notificación. Status: {response.status_code}, Response: {response.text[:200]}"
        )
        return False

    except Timeout:
        logger.error("Timeout al enviar notificación a Discord")
        return False
    except RequestException as e:
        logger.error(f"Error de red al enviar notificación: {e}")
        return False
    except Exception as e:
        logger.error(f"Error inesperado al enviar notificación: {e}")
        return False


def format_scan_summary(
    domains: list[str],
    duration: float,
    output_dir: str,
    total_subdomains: Optional[int] = None,
    total_vulnerabilities: Optional[int] = None,
) -> str:
    """Formatea un resumen del escaneo para notificaciones.

    Args:
        domains: Lista de dominios escaneados
        duration: Duración del escaneo en segundos
        output_dir: Directorio de salida de los resultados
        total_subdomains: Número total de subdominios encontrados (opcional)
        total_vulnerabilities: Número total de vulnerabilidades encontradas (opcional)

    Returns:
        Mensaje formateado con el resumen del escaneo
    """
    # Formatear duración
    duration_str = f"{duration / 60:.1f} minutos" if duration >= 60 else f"{duration:.1f} segundos"

    # Construir mensaje por partes
    message_parts = [
        "🔍 **Escaneo Completado**",
        f"**Dominios:** {', '.join(domains)}",
        f"**Duración:** {duration_str}",
        f"**Resultados en:** {output_dir}",
    ]

    # Agregar estadísticas si están disponibles
    if total_subdomains is not None:
        message_parts.append(f"**Subdominios encontrados:** {total_subdomains}")

    if total_vulnerabilities is not None:
        message_parts.append(f"**Vulnerabilidades encontradas:** {total_vulnerabilities}")

    return "\n".join(message_parts)