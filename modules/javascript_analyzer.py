#!/usr/bin/env python3
"""Módulo de análisis de JavaScript para Ultra-BugBountyScanner v2.3.

Este módulo contiene la funcionalidad para analizar archivos JavaScript
utilizando LinkFinder para descubrir endpoints y rutas ocultas.

Author: Ultra-BugBountyScanner Team
"""

from pathlib import Path
import subprocess

from utils.logger import get_logger

# Inicializar logger
logger = get_logger()


def analyze_javascript(domain: str, output_dir: Path) -> None:
    """Fase 5: Análisis de JavaScript.
    
    Utiliza LinkFinder para analizar archivos JavaScript y descubrir
    endpoints, rutas y parámetros ocultos en el código cliente.
    
    Args:
        domain: Dominio objetivo para análisis
        output_dir: Directorio base de salida
    """
    logger.info(f"Starting JavaScript analysis for {domain}")
    javascript_dir = output_dir / domain / "javascript"
    javascript_dir.mkdir(parents=True, exist_ok=True)

    # Verificar si existe el archivo de URLs (generado por discover_web_assets)
    urls_file = output_dir / domain / "web" / "httpx_urls.txt"
    if not urls_file.exists():
        logger.warning(f"URLs file not found: {urls_file}")
        return

    # Leer URLs desde httpx_urls.txt
    try:
        with urls_file.open("r", encoding="utf-8") as f:
            urls = [line.strip() for line in f if line.strip()]
    except Exception as e:
        logger.error(f"Error reading URLs file: {e}")
        return

    if not urls:
        logger.warning(f"No URLs found in {urls_file}")
        return

    logger.debug(f"Running LinkFinder JavaScript analysis for {domain} on {len(urls)} URLs...")

    # Archivo de salida para resultados consolidados de LinkFinder
    linkfinder_output = javascript_dir / "linkfinder_results.txt"

    # Procesar cada URL con LinkFinder
    all_results = []
    for url in urls:
        try:
            logger.debug(f"Analyzing JavaScript for URL: {url}")

            # Ejecutar comando LinkFinder para cada URL
            linkfinder_cmd = [
                "python3", "-m", "linkfinder",
                "-i", url,
                "-o", "cli"
            ]

            result = subprocess.run(
                linkfinder_cmd,
                capture_output=True,
                text=True,
                timeout=60,  # 60 segundos de timeout por URL
                check=False
            )

            if result.returncode == 0 and result.stdout.strip():
                # Agregar encabezado de URL y resultados
                all_results.append(f"=== LINKFINDER RESULTS FOR {url} ===")
                all_results.append(result.stdout.strip())
                all_results.append("")  # Línea vacía para separación
                logger.debug(f"LinkFinder found endpoints for {url}")
            else:
                logger.debug(f"No JavaScript endpoints found for {url}")

        except subprocess.TimeoutExpired:
            logger.warning(f"LinkFinder timeout for URL: {url}")
        except Exception as e:
            logger.warning(f"Error running LinkFinder for {url}: {e}")

    # Escribir resultados consolidados al archivo
    if all_results:
        try:
            with linkfinder_output.open("w", encoding="utf-8") as f:
                f.write("\n".join(all_results))
            logger.success(f"LinkFinder results saved to: {linkfinder_output}")
            processed_urls = len([r for r in all_results if r.startswith('===')])
            logger.info(f"JavaScript analysis completed for {domain} - {processed_urls} URLs processed")
        except Exception as e:
            logger.error(f"Error writing LinkFinder results: {e}")
    else:
        logger.info(f"No JavaScript endpoints discovered for {domain}")
        # Crear archivo vacío para indicar que el análisis se realizó
        linkfinder_output.touch()

    logger.success(f"JavaScript analysis completed for {domain}")
