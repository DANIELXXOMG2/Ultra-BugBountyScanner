#!/usr/bin/env python3
"""Módulo de escaneo de puertos para Ultra-BugBountyScanner v2.3.

Este módulo contiene la funcionalidad para escanear puertos usando
múltiples herramientas: naabu para escaneo rápido y nmap para detección de servicios.

Author: Ultra-BugBountyScanner Team
"""

from pathlib import Path
from typing import Set

from utils.logger import get_logger
from utils.runner import run_command

# Inicializar logger
logger = get_logger()


def scan_ports(domain: str, output_dir: Path, quick_mode: bool) -> None:
    """Fase 2: Escaneo de Puertos.
    
    Utiliza múltiples herramientas para escanear puertos:
    - naabu: Escaneo rápido de puertos
    - nmap: Detección detallada de servicios (solo en modo completo)
    
    Args:
        domain: Dominio objetivo para escaneo
        output_dir: Directorio base de salida
        quick_mode: Si está habilitado, omite el escaneo detallado con nmap
    """
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
        unique_hosts: Set[str] = set()
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
