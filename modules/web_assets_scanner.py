#!/usr/bin/env python3
"""Módulo de descubrimiento de activos web para Ultra-BugBountyScanner v2.3.

Este módulo contiene la funcionalidad para descubrir activos web vivos
utilizando httpx y extraer URLs para análisis posteriores.

Author: Ultra-BugBountyScanner Team
"""

from pathlib import Path

from utils.logger import get_logger
from utils.runner import run_command

# Inicializar logger
logger = get_logger()


def discover_web_assets(domain: str, output_dir: Path) -> None:
    """Fase 3: Descubrimiento de Activos Web.
    
    Utiliza httpx para descubrir activos web vivos y extraer URLs
    para análisis posteriores de vulnerabilidades.
    
    Args:
        domain: Dominio objetivo para descubrimiento
        output_dir: Directorio base de salida
    """
    logger.info(f"Starting web assets discovery for {domain}")
    web_dir = output_dir / domain / "web"
    web_dir.mkdir(parents=True, exist_ok=True)

    # Verificar si existe el archivo de subdominios
    subdomains_file = output_dir / domain / "subdomains" / "all_subdomains.txt"
    if not subdomains_file.exists():
        logger.warning(f"Subdomains file not found: {subdomains_file}")
        return

    # Ejecutar httpx para descubrir activos web vivos
    httpx_output = web_dir / "httpx_live.txt"
    httpx_cmd = [
        "httpx",
        "-l",
        str(subdomains_file),
        "-o",
        str(httpx_output),
        "-silent",
        "-follow-redirects",
        "-status-code",
        "-no-color",  # Evitar códigos de color en la salida
    ]

    logger.debug("Running httpx for web asset discovery...")
    run_command(httpx_cmd)

    # Extraer URLs de httpx_live.txt y crear httpx_urls.txt para nuclei
    httpx_urls_file = web_dir / "httpx_urls.txt"
    if httpx_output.exists() and httpx_output.stat().st_size > 0:
        with httpx_output.open("r", encoding="utf-8") as f:
            lines = f.readlines()

        urls = []
        for line in lines:
            line = line.strip()
            if line and line.startswith(("http://", "https://")):
                # Extraer solo la parte de la URL (antes de cualquier código de estado o info adicional)
                url = line.split()[0] if " " in line else line
                urls.append(url)

        # Escribir URLs a httpx_urls.txt
        with httpx_urls_file.open("w", encoding="utf-8") as f:
            for url in urls:
                f.write(f"{url}\n")

        logger.info(f"Extracted {len(urls)} URLs to {httpx_urls_file}")
    else:
        logger.warning(f"No httpx results found in {httpx_output}")

    logger.success(f"Web assets discovery completed for {domain}")