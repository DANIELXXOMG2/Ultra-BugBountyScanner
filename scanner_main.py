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

from utils.ai_analyzer import format_scan_data_for_ai, get_gemini_summary, save_ai_summary
from utils.logger import get_logger
from utils.notifications import format_scan_summary, send_discord_notification
from utils.runner import run_command

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
            for subdir in ["subdomains", "ports", "web", "content", "vulnerabilities", "screenshots", "logs"]:
                (domain_dir / subdir).mkdir(parents=True, exist_ok=True)

        # Crear directorios globales
        (output_dir / "reports").mkdir(parents=True, exist_ok=True)
        (output_dir / "temp").mkdir(parents=True, exist_ok=True)

        logger.success("Output directories created successfully.")
        return True
    except OSError as e:
        logger.critical(f"Could not create output directories: {e}")
        return False


def enumerate_subdomains(domain: str, output_dir: Path) -> None:
    """Fase 1: Enumeración de Subdominios."""
    logger.info(f"Starting subdomain enumeration for {domain}")
    domain_out = output_dir / domain / "subdomains"
    all_subs_file = domain_out / "all_subdomains.txt"

    # Herramientas y sus archivos de salida
    tools = {
        "subfinder": domain_out / "subfinder.txt",
        "amass": domain_out / "amass.txt",
        "crtsh": domain_out / "crtsh.txt",
    }

    # Subfinder
    logger.debug("Running Subfinder...")
    subfinder_cmd = ["subfinder", "-d", domain, "-o", str(tools["subfinder"]), "-silent"]
    run_command(subfinder_cmd)

    # Amass
    logger.debug("Running Amass...")
    amass_cmd = ["amass", "enum", "-d", domain, "-o", str(tools["amass"]), "-silent"]
    run_command(amass_cmd)

    # Certificate Transparency (crt.sh)
    logger.debug("Querying crt.sh...")
    # Esta es una llamada directa a un servicio, se puede mejorar con 'requests' en el futuro
    crtsh_cmd = f"curl -s \"https://crt.sh/?q=%25.{domain}&output=json\" | jq -r '.[].name_value' | sed 's/\\*\\.//g' | sort -u > {tools['crtsh']}"
    run_command(crtsh_cmd, shell=True)

    # Consolidar resultados
    logger.info("Consolidating subdomain results...")
    all_subdomains = set()
    for tool_file in tools.values():
        if tool_file.exists():
            with open(tool_file) as f:
                subdomains = {line.strip() for line in f if line.strip()}
                all_subdomains.update(subdomains)

    with open(all_subs_file, "w") as f:
        for sub in sorted(list(all_subdomains)):
            f.write(f"{sub}\n")

    logger.success(f"Found {len(all_subdomains)} unique subdomains for {domain}")


def scan_ports(domain: str, output_dir: Path, quick_mode: bool) -> None:
    """Fase 2: Escaneo de Puertos."""
    logger.info(f"Starting port scanning for {domain}")
    subdomains_file = output_dir / domain / "subdomains" / "all_subdomains.txt"
    ports_out = output_dir / domain / "ports"

    if not subdomains_file.exists():
        logger.warning(f"Subdomains file not found for {domain}, skipping port scan.")
        return

    # Naabu para escaneo rápido
    naabu_file = ports_out / "naabu.txt"
    logger.debug("Running Naabu for fast port scan...")
    naabu_cmd = ["naabu", "-list", str(subdomains_file), "-o", str(naabu_file), "-silent", "-rate", "1000"]
    run_command(naabu_cmd)

    if quick_mode:
        logger.info("Quick mode enabled, skipping detailed Nmap scan.")
        return

    # Nmap para detección de servicios
    if naabu_file.exists() and naabu_file.stat().st_size > 0:
        logger.debug("Running Nmap for service detection...")
        nmap_txt = ports_out / "nmap.txt"
        nmap_xml = ports_out / "nmap.xml"
        nmap_cmd = [
            "nmap",
            "-iL",
            str(naabu_file),
            "-sV",
            "-sC",
            "-oN",
            str(nmap_txt),
            "-oX",
            str(nmap_xml),
            "--max-retries",
            "2",
            "--max-rtt-timeout",
            "1000ms",
        ]
        run_command(nmap_cmd)
    else:
        logger.warning("No open ports found by Naabu, skipping Nmap.")

    logger.success(f"Port scanning completed for {domain}")


def discover_web_assets(domain: str, output_dir: Path) -> None:
    """Fase 3: Descubrimiento de Assets Web."""
    logger.info(f"Starting web asset discovery for {domain}")
    subdomains_file = output_dir / domain / "subdomains" / "all_subdomains.txt"
    web_out = output_dir / domain / "web"

    if not subdomains_file.exists():
        logger.warning(f"Subdomains file not found for {domain}, skipping web discovery.")
        return

    # HTTPx para encontrar servidores web vivos
    httpx_file = web_out / "httpx_live.txt"
    logger.debug("Running HTTPx to find live web servers...")
    httpx_cmd = [
        "httpx",
        "-l",
        str(subdomains_file),
        "-o",
        str(httpx_file),
        "-silent",
        "-follow-redirects",
        "-status-code",
        "-title",
        "-tech-detect",
        "-threads",
        "50",
    ]
    run_command(httpx_cmd)

    logger.success(f"Web asset discovery completed for {domain}")


def scan_vulnerabilities(domain: str, output_dir: Path, quick_mode: bool) -> None:
    """Fase 4: Escaneo de Vulnerabilidades."""
    logger.info(f"Starting vulnerability scanning for {domain}")

    if quick_mode:
        logger.info("Quick mode enabled, skipping vulnerability scanning.")
        return

    web_file = output_dir / domain / "web" / "httpx_live.txt"
    vuln_out = output_dir / domain / "vulnerabilities"

    if not web_file.exists():
        logger.warning(f"Web assets file not found for {domain}, skipping vulnerability scan.")
        return

    # Nuclei para escaneo de vulnerabilidades
    nuclei_file = vuln_out / "nuclei_results.json"
    logger.debug("Running Nuclei for vulnerability scanning...")
    nuclei_cmd = [
        "nuclei",
        "-l",
        str(web_file),
        "-o",
        str(nuclei_file),
        "-json",
        "-severity",
        "high,critical",
        "-silent",
        "-rate-limit",
        "150",
        "-bulk-size",
        "25",
        "-timeout",
        "10",
    ]
    run_command(nuclei_cmd)

    logger.success(f"Vulnerability scanning completed for {domain}")


def main() -> None:
    """Punto de entrada principal del scanner."""
    parser = argparse.ArgumentParser(description="Ultra-BugBountyScanner v1.1.0 - Python Refactor")
    parser.add_argument("-d", "--domain", action="append", required=True, help="Target domain(s) to scan.")
    parser.add_argument("-o", "--output", default=os.getenv("OUTPUT_DIR", "output"), help="Output directory.")
    parser.add_argument("-q", "--quick", action="store_true", help="Enable quick scan mode.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose/debug output.")

    args = parser.parse_args()

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
        scan_ports(domain, output_dir, args.quick)
        discover_web_assets(domain, output_dir)
        scan_vulnerabilities(domain, output_dir, args.quick)

        # Análisis con IA si está configurado
        gemini_api_key = os.getenv("GEMINI_API_KEY")
        if gemini_api_key:
            logger.info(f"Generating AI analysis for {domain}...")
            try:
                # Preparar archivos de datos
                subdomains_file = output_dir / domain / "subdomains" / "all_subdomains.txt"
                ports_file = output_dir / domain / "ports" / "nmap.txt"
                vulnerabilities_file = output_dir / domain / "vulnerabilities" / "nuclei_results.json"
                web_assets_file = output_dir / domain / "web" / "httpx_live.txt"

                # Formatear datos para IA
                scan_data = format_scan_data_for_ai(
                    subdomains_file=str(subdomains_file) if subdomains_file.exists() else None,
                    ports_file=str(ports_file) if ports_file.exists() else None,
                    vulnerabilities_file=str(vulnerabilities_file) if vulnerabilities_file.exists() else None,
                    web_assets_file=str(web_assets_file) if web_assets_file.exists() else None,
                )

                # Generar resumen con IA
                ai_summary = get_gemini_summary(gemini_api_key, scan_data)
                if ai_summary:
                    logger.info("AI analysis generated successfully")
                    print(f"\n{'=' * 60}")
                    print(f"AI ANALYSIS FOR {domain.upper()}")
                    print(f"{'=' * 60}")
                    print(ai_summary)
                    print(f"{'=' * 60}\n")

                    # Guardar resumen en archivo
                    reports_dir = output_dir / "reports"
                    ai_report_file = reports_dir / f"{domain}_summary_ia.md"
                    save_ai_summary(ai_summary, str(ai_report_file))
                else:
                    logger.warning(f"Could not generate AI analysis for {domain}")

            except Exception as e:
                logger.error(f"Error during AI analysis for {domain}: {e}")
        else:
            logger.debug("GEMINI_API_KEY not found, skipping AI analysis")

        logger.success(f"Finished processing for {domain}")

    duration = time.time() - start_time

    # Enviar notificación a Discord si está configurado
    discord_webhook = os.getenv("DISCORD_WEBHOOK_URL")
    if discord_webhook:
        logger.info("Sending Discord notification...")
        try:
            # Contar resultados para el resumen
            total_subdomains = 0
            total_vulnerabilities = 0

            for domain in args.domain:
                # Contar subdominios
                subdomains_file = output_dir / domain / "subdomains" / "all_subdomains.txt"
                if subdomains_file.exists():
                    with open(subdomains_file) as f:
                        total_subdomains += len([line for line in f if line.strip()])

                # Contar vulnerabilidades
                vuln_file = output_dir / domain / "vulnerabilities" / "nuclei_results.json"
                if vuln_file.exists():
                    with open(vuln_file) as f:
                        content = f.read().strip()
                        if content:
                            # Contar líneas JSON (cada línea es una vulnerabilidad)
                            total_vulnerabilities += len([line for line in content.split("\n") if line.strip()])

            # Formatear mensaje de resumen
            summary_message = format_scan_summary(
                domains=args.domain,
                duration=duration,
                output_dir=str(output_dir),
                total_subdomains=total_subdomains if total_subdomains > 0 else None,
                total_vulnerabilities=total_vulnerabilities if total_vulnerabilities > 0 else None,
            )

            # Enviar notificación
            success = send_discord_notification(discord_webhook, summary_message)
            if success:
                logger.success("Discord notification sent successfully")
            else:
                logger.warning("Failed to send Discord notification")

        except Exception as e:
            logger.error(f"Error sending Discord notification: {e}")
    else:
        logger.debug("DISCORD_WEBHOOK_URL not found, skipping notification")

    logger.success(f"All scans completed in {duration:.2f} seconds.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.warning("Scan interrupted by user.")
    except Exception as e:
        logger.exception(f"An unhandled exception occurred: {e}")
