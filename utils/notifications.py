"""Módulo de notificaciones para Discord.

Este módulo proporciona funcionalidad para enviar notificaciones
a través de webhooks de Discord.
"""

import logging
from typing import Optional

import requests

# Configurar logger
logger = logging.getLogger(__name__)


def send_discord_notification(webhook_url: str, message: str) -> bool:
    """Envía una notificación a Discord a través de un webhook.

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
        logger.error("webhook_url no puede estar vacío")
        raise ValueError("webhook_url no puede estar vacío")

    if not message or not message.strip():
        logger.error("message no puede estar vacío")
        raise ValueError("message no puede estar vacío")

    # Preparar payload
    payload = {"content": message.strip()}

    # Headers para la petición
    headers = {"Content-Type": "application/json", "User-Agent": "Ultra-BugBountyScanner/1.0"}

    try:
        logger.info(f"Enviando notificación a Discord: {message[:100]}...")

        # Realizar petición POST con timeout
        response = requests.post(
            webhook_url,
            json=payload,
            headers=headers,
            timeout=30,  # Timeout de 30 segundos
        )

        # Verificar si la respuesta fue exitosa (2xx)
        if response.status_code >= 200 and response.status_code < 300:
            logger.info(f"Notificación enviada exitosamente. Status: {response.status_code}")
            return True
        logger.error(
            f"Error al enviar notificación. Status: {response.status_code}, Response: {response.text[:200]}"
        )
        return False

    except requests.exceptions.Timeout:
        logger.error("Timeout al enviar notificación a Discord")
        return False

    except requests.exceptions.ConnectionError:
        logger.error("Error de conexión al enviar notificación a Discord")
        return False

    except requests.exceptions.RequestException as e:
        logger.error(f"Error de requests al enviar notificación: {str(e)}")
        return False

    except Exception as e:
        logger.error(f"Error inesperado al enviar notificación: {str(e)}")
        return False


def format_scan_summary(
    domains: list[str],
    duration: float,
    output_dir: str,
    total_subdomains: Optional[int] = None,
    total_ports: Optional[int] = None,
    total_vulnerabilities: Optional[int] = None,
) -> str:
    """Formatea un resumen del escaneo para Discord.

    Args:
        domains: Lista de dominios escaneados
        duration: Duración del escaneo en segundos
        output_dir: Directorio de salida de los resultados
        total_subdomains: Número total de subdominios encontrados
        total_ports: Número total de puertos abiertos
        total_vulnerabilities: Número total de vulnerabilidades encontradas

    Returns:
        Mensaje formateado para Discord
    """
    domains_str = ", ".join(domains)
    duration_formatted = f"{duration:.2f}"

    message_parts = [
        "🔍 **Escaneo Ultra-BugBountyScanner Completado**",
        f"📋 **Dominios:** {domains_str}",
        f"⏱️ **Duración:** {duration_formatted} segundos",
        f"📁 **Resultados en:** {output_dir}",
    ]

    # Añadir estadísticas si están disponibles
    if total_subdomains is not None:
        message_parts.append(f"🌐 **Subdominios encontrados:** {total_subdomains}")

    if total_ports is not None:
        message_parts.append(f"🔌 **Puertos abiertos:** {total_ports}")

    if total_vulnerabilities is not None:
        if total_vulnerabilities > 0:
            message_parts.append(f"⚠️ **Vulnerabilidades encontradas:** {total_vulnerabilities}")
        else:
            message_parts.append("✅ **No se encontraron vulnerabilidades críticas**")

    return "\n".join(message_parts)
