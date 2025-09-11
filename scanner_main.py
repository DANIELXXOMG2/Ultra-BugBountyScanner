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

from utils.ai_analyzer import get_gemini_summary
from utils.logger import get_logger
from utils.notifications import send_discord_notification
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
    crtsh_cmd = (
        f'curl -s "https://crt.sh/?q=%25.{domain}&output=json" | '
        f"jq -r '.[].name_value' | sed 's/\\*\\.//g' | sort -u > {tools['crtsh']}"
    )
    run_command(crtsh_cmd, shell=True)  # nosec B602 B604 - Necesario para pipeline de comandos

    # Consolidar resultados
    logger.info("Consolidating subdomain results...")
    all_subdomains = set()
    for tool_file in tools.values():
        if tool_file.exists():
            with tool_file.open() as f:
                subdomains = {line.strip() for line in f if line.strip()}
                all_subdomains.update(subdomains)

    with all_subs_file.open("w") as f:
        for sub in sorted(all_subdomains):
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
        ## CORRECCIÓN: Limpiar la salida de Naabu para Nmap
        logger.debug("Processing Naabu output for Nmap...")
        nmap_input_file = ports_out / "nmap_hosts.txt"
        unique_hosts = set()
        with naabu_file.open() as f:
            for line in f:
                host = line.strip().split(":")[0]
                if host:
                    unique_hosts.add(host)

        with nmap_input_file.open("w") as f:
            for host in sorted(unique_hosts):
                f.write(f"{host}\n")

        logger.debug(f"Running Nmap for service detection on {len(unique_hosts)} unique hosts...")
        nmap_txt = ports_out / "nmap.txt"
        nmap_xml = ports_out / "nmap.xml"
        nmap_cmd = [
            "nmap",
            "-iL",
            str(nmap_input_file),  ## CORRECCIÓN: Usar el archivo de hosts limpios
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
    """Discover web assets using httpx.

    Args:
        domain: The domain being scanned
        output_dir: The output directory for this domain
    """
    web_dir = output_dir / domain / "web"
    web_dir.mkdir(parents=True, exist_ok=True)

    # Check if subdomains file exists
    subdomains_file = output_dir / domain / "subdomains" / "all_subdomains.txt"
    if not subdomains_file.exists():
        logger.warning(f"Subdomains file not found: {subdomains_file}")
        return

    # Run httpx to discover live web assets
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
        "-no-color",  ## CORRECCIÓN: Añadir flag para evitar códigos de color en la salida
    ]

    logger.info(f"Running httpx web discovery for {domain}...")
    run_command(httpx_cmd)

    # Extract URLs from httpx_live.txt and create httpx_urls.txt for nuclei
    httpx_urls_file = web_dir / "httpx_urls.txt"
    if httpx_output.exists() and httpx_output.stat().st_size > 0:
        with httpx_output.open("r", encoding="utf-8") as f:
            lines = f.readlines()

        urls = []
        for line in lines:
            line = line.strip()
            if line and line.startswith(("http://", "https://")):
                # Extract just the URL part (before any status code or additional info)
                url = line.split()[0] if " " in line else line
                urls.append(url)

        # Write URLs to httpx_urls.txt
        with httpx_urls_file.open("w", encoding="utf-8") as f:
            for url in urls:
                f.write(f"{url}\n")

        logger.info(f"Extracted {len(urls)} URLs to {httpx_urls_file}")
    else:
        logger.warning(f"No httpx results found in {httpx_output}")

    logger.success(f"httpx web discovery completed for {domain}")


def scan_vulnerabilities(domain: str, output_dir: Path, quick_mode: bool) -> None:
    """Scan for vulnerabilities using nuclei.

    Args:
        domain: The domain being scanned
        output_dir: The output directory for this domain
        quick_mode: Whether to run in quick mode (skip vulnerability scanning)
    """
    if quick_mode:
        logger.info("Quick mode enabled, skipping vulnerability scanning")
        return

    vulnerabilities_dir = output_dir / domain / "vulnerabilities"
    vulnerabilities_dir.mkdir(parents=True, exist_ok=True)

    # Check if URLs file exists (generated by discover_web_assets)
    urls_file = output_dir / domain / "web" / "httpx_urls.txt"
    if not urls_file.exists():
        logger.warning(f"URLs file not found: {urls_file}")
        return

    # Run nuclei for vulnerability scanning
    nuclei_output = vulnerabilities_dir / "nuclei_results.json"
    nuclei_cmd = [
        "nuclei",
        "-l",
        str(urls_file),
        "-o",
        str(nuclei_output),
        "-json",
        "-severity",
        "high,critical",
        "-silent",
    ]

    logger.info(f"Running nuclei vulnerability scan for {domain}...")
    run_command(nuclei_cmd)
    logger.success(f"nuclei vulnerability scan completed for {domain}")


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

        # AI Analysis Phase
        gemini_api_key = os.getenv("GEMINI_API_KEY")
        if gemini_api_key and gemini_api_key.strip():
            logger.info(f"Starting AI analysis for {domain}...")

            # Collect scan data from relevant files
            scan_data_parts = []

            # Subdomains data
            subdomains_file = output_dir / domain / "subdomains" / "all_subdomains.txt"
            if subdomains_file.exists() and subdomains_file.stat().st_size > 0:
                with subdomains_file.open(encoding="utf-8") as f:
                    subdomains_content = f.read().strip()
                    if subdomains_content:
                        scan_data_parts.append(f"=== SUBDOMINIOS ENCONTRADOS ===\n{subdomains_content}")

            # Nmap data
            nmap_file = output_dir / domain / "ports" / "nmap.txt"
            if nmap_file.exists() and nmap_file.stat().st_size > 0:
                with nmap_file.open(encoding="utf-8") as f:
                    nmap_content = f.read().strip()
                    if nmap_content:
                        scan_data_parts.append(f"=== ESCANEO DE PUERTOS (NMAP) ===\n{nmap_content}")

            # Nuclei vulnerabilities data
            nuclei_file = output_dir / domain / "vulnerabilities" / "nuclei_results.json"
            if nuclei_file.exists() and nuclei_file.stat().st_size > 0:
                with nuclei_file.open(encoding="utf-8") as f:
                    nuclei_content = f.read().strip()
                    if nuclei_content:
                        scan_data_parts.append(f"=== VULNERABILIDADES (NUCLEI) ===\n{nuclei_content}")

            # Web assets data
            httpx_file = output_dir / domain / "web" / "httpx_live.txt"
            if httpx_file.exists() and httpx_file.stat().st_size > 0:
                with httpx_file.open(encoding="utf-8") as f:
                    httpx_content = f.read().strip()
                    if httpx_content:
                        scan_data_parts.append(f"=== ACTIVOS WEB ACTIVOS (HTTPX) ===\n{httpx_content}")

            if scan_data_parts:
                scan_data = "\n\n".join(scan_data_parts)

                # Generate AI summary
                ai_summary = get_gemini_summary(gemini_api_key, scan_data)

                if ai_summary:
                    # Print summary to console
                    logger.info("=" * 80)
                    logger.info(f"RESUMEN EJECUTIVO DE IA PARA {domain.upper()}")
                    logger.info("=" * 80)
                    print(ai_summary)
                    logger.info("=" * 80)

                    # Save summary to file within domain directory
                    reports_dir = output_dir / domain / "reports"
                    reports_dir.mkdir(parents=True, exist_ok=True)
                    summary_file = reports_dir / f"{domain}_summary_ia.md"

                    with summary_file.open("w", encoding="utf-8") as f:
                        f.write(f"# Resumen Ejecutivo de IA - {domain}\n\n")
                        f.write(ai_summary)

                    logger.success(f"AI summary saved to: {summary_file}")
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

    # Send Discord notification if webhook URL is configured
    webhook_url = os.getenv("DISCORD_WEBHOOK_URL")
    if webhook_url and webhook_url.strip():
        domains_str = ", ".join(args.domain)
        message = (
            f"🚀 Escaneo completado para los objetivos: {domains_str}. "
            f"Duración: {duration} segundos. "
            f"Resultados disponibles en la carpeta `{output_dir.name}`."
        )

        success = send_discord_notification(webhook_url, message)
        if success:
            logger.info("Discord notification sent successfully")
        else:
            logger.warning("Failed to send Discord notification")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.warning("Scan interrupted by user.")
    except Exception as e:
        logger.exception(f"An unhandled exception occurred: {e}")
