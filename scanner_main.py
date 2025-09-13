#!/usr/bin/env python3
"""Ultra-BugBountyScanner Main Module.

Author: danielxxomg2
"""

import argparse
import os
from pathlib import Path
import time

# Removed typing import as we use built-in list annotation
from dotenv import load_dotenv

from modules.javascript_analyzer import analyze_javascript
from modules.port_scanner import scan_ports

# Importar funciones de escaneo desde los módulos
from modules.subdomain_scanner import enumerate_subdomains
from modules.vulnerability_scanner import scan_vulnerabilities
from modules.web_assets_scanner import discover_web_assets
from utils.ai_analyzer import get_gemini_alert, get_gemini_summary
from utils.logger import get_logger
from utils.notifications import send_discord_notification

# Cargar variables de entorno desde .env
load_dotenv()

# Inicializar logger
logger = get_logger()


def setup_directories(output_dir: Path, domains: list[str]) -> bool:
    """Crea los directorios de salida para cada dominio."""
    logger.info("Setting up output directories...")
    try:
        # Crear el directorio base primero
        output_dir.mkdir(parents=True, exist_ok=True)

        for domain in domains:
            domain_dir = output_dir / domain
            # Crear subdirectorios para cada fase del escaneo
            subdirs = ["subdomains", "ports", "web", "content", "vulnerabilities", "screenshots", "logs", "javascript"]
            for subdir in subdirs:
                (domain_dir / subdir).mkdir(parents=True, exist_ok=True)

        # Crear directorios globales
        (output_dir / "reports").mkdir(parents=True, exist_ok=True)
        (output_dir / "temp").mkdir(parents=True, exist_ok=True)

        logger.success("Output directories created successfully.")
        return True
    except OSError as e:
        logger.critical(f"Could not create output directories: {e}")
        return False


# Las funciones de escaneo han sido movidas a módulos separados


# Función movida a modules/port_scanner.py


# Función movida a modules/web_assets_scanner.py


# Función movida a modules/vulnerability_scanner.py


# Función movida a modules/javascript_analyzer.py


def main() -> None:
    """Main function."""
    parser = argparse.ArgumentParser(
        description="Ultra-BugBountyScanner v2.2 - Advanced Bug Bounty Reconnaissance Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  python3 scanner_main.py example.com
  python3 scanner_main.py example.com target2.com --output /tmp/results
  python3 scanner_main.py example.com --quick --verbose

For more information, visit: https://github.com/danielxxomg2/Ultra-BugBountyScanner
        """,
    )
    parser.add_argument("domain", nargs="+", help="Target domain(s) to scan")
    parser.add_argument(
        "-o",
        "--output",
        default="./output",
        help="Output directory (default: ./output)",
    )
    parser.add_argument(
        "-q", "--quick", action="store_true", help="Quick mode (skip intensive tasks)"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose output"
    )

    args = parser.parse_args()

    # Sanitización directa de entradas v2.1
    import re

    # Validar nombres de dominio con regex
    domain_pattern = re.compile(
        r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
    )
    for domain in args.domain:
        if not domain_pattern.match(domain):
            logger.error(f"❌ SECURITY: Invalid domain format detected: {domain}")
            return

    # Validar ruta de salida (sin directory traversal)
    if ".." in args.output:
        logger.error("❌ SECURITY: Directory traversal detected in output path")
        return

    # Configurar nivel del logger
    if args.verbose or os.getenv("VERBOSE", "false").lower() == "true":
        logger.setLevel("DEBUG")
        logger.debug("Verbose mode enabled.")

    start_time = time.time()

    output_dir = Path(args.output).resolve()

    logger.info(f"Starting Ultra-BugBountyScanner for targets: {', '.join(args.domain)}")
    logger.info(f"Output will be saved to: {output_dir}")
    if args.quick:
        logger.warning("Quick mode is enabled. Intensive tasks will be skipped.")

    if not setup_directories(output_dir, args.domain):
        return  # Salir si no se pueden crear los directorios

    for domain in args.domain:
        logger.info(f"Processing target: {domain}")

        enumerate_subdomains(domain, output_dir)

        # Flujo Proactivo v2.2: Notificación de inicio después de enumerate_subdomains
        webhook_url = os.getenv("DISCORD_WEBHOOK_URL")
        if webhook_url and webhook_url.strip():
            start_message = f"🚀 Escaneo iniciado para {domain}..."
            send_discord_notification(webhook_url, start_message)
        scan_ports(domain, output_dir, args.quick)
        discover_web_assets(domain, output_dir)
        scan_vulnerabilities(domain, output_dir, args.quick)
        analyze_javascript(domain, output_dir)

        # Flujo Proactivo v2.2: Alertas en tiempo real después de vulnerabilidades
        gemini_api_key = os.getenv("GEMINI_API_KEY")
        nuclei_file = output_dir / domain / "vulnerabilities" / "nuclei_results.json"

        if nuclei_file.exists() and nuclei_file.stat().st_size > 0:
            try:
                import json

                with nuclei_file.open(encoding="utf-8") as f:
                    content = f.read().strip()
                    if content:
                        # Manejar tanto formato de líneas JSON como array JSON
                        if content.startswith('['):
                            nuclei_data = json.loads(content)
                        else:
                            # Formato JSONL (una línea por hallazgo)
                            nuclei_data = []
                            for line in content.split('\n'):
                                if line.strip():
                                    nuclei_data.append(json.loads(line))

                        # Procesar cada hallazgo individualmente para alertas inmediatas
                        if nuclei_data:
                            for finding in nuclei_data:
                                if gemini_api_key and gemini_api_key.strip():
                                    # Generar alerta concisa para cada hallazgo
                                    alert = get_gemini_alert(gemini_api_key, json.dumps(finding, indent=2))
                                    if alert and webhook_url and webhook_url.strip():
                                        alert_message = f"🚨 Alerta Crítica en {domain}: {alert}"
                                        send_discord_notification(webhook_url, alert_message)
            except (json.JSONDecodeError, Exception) as e:
                logger.warning(f"Error processing nuclei results for alerts: {e}")

        # Flujo Proactivo v2.1: Reporte final por dominio
        if gemini_api_key and gemini_api_key.strip():
            logger.info(f"Generating final report for {domain}...")

            # Recopilar datos de escaneo para el reporte final
            scan_data_parts = []

            # Datos de subdominios
            subdomains_file = output_dir / domain / "subdomains" / "all_subdomains.txt"
            if subdomains_file.exists() and subdomains_file.stat().st_size > 0:
                with subdomains_file.open(encoding="utf-8") as f:
                    subdomains_content = f.read().strip()
                    if subdomains_content:
                        scan_data_parts.append(f"=== SUBDOMINIOS ENCONTRADOS ===\n{subdomains_content}")

            # Datos de Nmap
            nmap_file = output_dir / domain / "ports" / "nmap.txt"
            if nmap_file.exists() and nmap_file.stat().st_size > 0:
                with nmap_file.open(encoding="utf-8") as f:
                    nmap_content = f.read().strip()
                    if nmap_content:
                        scan_data_parts.append(f"=== ESCANEO DE PUERTOS (NMAP) ===\n{nmap_content}")

            # Datos de vulnerabilidades Nuclei
            if nuclei_file.exists() and nuclei_file.stat().st_size > 0:
                with nuclei_file.open(encoding="utf-8") as f:
                    nuclei_content = f.read().strip()
                    if nuclei_content:
                        scan_data_parts.append(f"=== VULNERABILIDADES (NUCLEI) ===\n{nuclei_content}")

            # Datos de análisis de JavaScript
            javascript_file = output_dir / domain / "javascript" / "linkfinder_results.txt"
            if javascript_file.exists() and javascript_file.stat().st_size > 0:
                with javascript_file.open(encoding="utf-8") as f:
                    javascript_content = f.read().strip()
                    if javascript_content:
                        scan_data_parts.append(f"=== ANÁLISIS DE JAVASCRIPT (LINKFINDER) ===\n{javascript_content}")

            if scan_data_parts:
                scan_data = "\n\n".join(scan_data_parts)

                # Generar resumen ejecutivo completo
                ai_summary = get_gemini_summary(gemini_api_key, scan_data)

                if ai_summary:
                    # Guardar resumen en archivo
                    reports_dir = output_dir / domain / "reports"
                    reports_dir.mkdir(parents=True, exist_ok=True)
                    summary_file = reports_dir / f"{domain}_summary_ia.md"

                    with summary_file.open("w", encoding="utf-8") as f:
                        f.write(f"# Resumen Ejecutivo de IA - {domain}\n\n")
                        f.write(ai_summary)

                    logger.success(f"AI summary saved to: {summary_file}")

                    # Enviar reporte completo a Discord
                    if webhook_url and webhook_url.strip():
                        # Truncar el resumen si es muy largo para Discord
                        summary_preview = ai_summary[:1500] + "..." if len(ai_summary) > 1500 else ai_summary
                        final_report = (
                            f"📊 **Reporte Final para {domain}**\n\n{summary_preview}\n\n"
                            f"📁 Reporte completo guardado en: `{summary_file.name}`"
                        )
                        send_discord_notification(webhook_url, final_report)
                else:
                    logger.warning(f"Failed to generate AI summary for {domain}")
            else:
                logger.warning(f"No scan data available for AI analysis of {domain}")
        else:
            logger.info("GEMINI_API_KEY not configured, skipping AI analysis")

        logger.success(f"Finished processing for {domain}")

    end_time = time.time()
    duration = int(end_time - start_time)

    logger.success(f"All scans completed in {duration} seconds.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.warning("Scan interrupted by user.")
    except Exception as e:
        logger.exception(f"An unhandled exception occurred: {e}")
