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
    ]

    logger.info(f"Running httpx web discovery for {domain}...")
    run_command(httpx_cmd)
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

    # Check if web assets file exists
    web_assets_file = output_dir / domain / "web" / "httpx_live.txt"
    if not web_assets_file.exists():
        logger.warning(f"Web assets file not found: {web_assets_file}")
        return

    # Run nuclei for vulnerability scanning
    nuclei_output = vulnerabilities_dir / "nuclei_results.json"
    nuclei_cmd = [
        "nuclei",
        "-l",
        str(web_assets_file),
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
