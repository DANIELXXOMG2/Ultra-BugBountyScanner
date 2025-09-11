#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Ultra-BugBountyScanner - Main Orchestrator
Author: danielxxomg2
Version: 1.1.0 (Python Refactor)
Description: Python-based reconnaissance tool orchestrator.
"""

import argparse
import os
import time
from pathlib import Path
from typing import List

from dotenv import load_dotenv

from utils.logger import get_logger
from utils.runner import run_command

# Cargar variables de entorno desde .env
load_dotenv()

# Inicializar logger
logger = get_logger()

def setup_directories(output_dir: Path, domains: List[str]) -> bool:
    """Crea los directorios de salida para cada dominio."""
    logger.info("Setting up output directories...")
    try:
        for domain in domains:
            domain_dir = output_dir / domain
            # Crear subdirectorios para cada fase del escaneo
            for subdir in ["subdomains", "ports", "web", "content", "vulnerabilities", "screenshots", "logs"]:
                (domain_dir / subdir).mkdir(parents=True, exist_ok=True)
        
        # Crear directorios globales
        (output_dir / "reports").mkdir(exist_ok=True)
        (output_dir / "temp").mkdir(exist_ok=True)
        
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
        "crtsh": domain_out / "crtsh.txt"
    }

    # Subfinder
    logger.debug("Running Subfinder...")
    subfinder_cmd = ['subfinder', '-d', domain, '-o', str(tools["subfinder"]), '-silent']
    run_command(subfinder_cmd)
    
    # Amass
    logger.debug("Running Amass...")
    amass_cmd = ['amass', 'enum', '-d', domain, '-o', str(tools["amass"]), '-silent']
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
            with open(tool_file, 'r') as f:
                subdomains = {line.strip() for line in f if line.strip()}
                all_subdomains.update(subdomains)

    with open(all_subs_file, 'w') as f:
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
    naabu_cmd = ['naabu', '-list', str(subdomains_file), '-o', str(naabu_file), '-silent', '-rate', '1000']
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
            'nmap', '-iL', str(naabu_file), '-sV', '-sC', 
            '-oN', str(nmap_txt), '-oX', str(nmap_xml), 
            '--max-retries', '2', '--max-rtt-timeout', '1000ms'
        ]
        run_command(nmap_cmd)
    else:
        logger.warning("No open ports found by Naabu, skipping Nmap.")

    logger.success(f"Port scanning completed for {domain}")


def main() -> None:
    """Punto de entrada principal del scanner."""
    parser = argparse.ArgumentParser(description=f"Ultra-BugBountyScanner v1.1.0 - Python Refactor")
    parser.add_argument('-d', '--domain', action='append', required=True, help='Target domain(s) to scan.')
    parser.add_argument('-o', '--output', default=os.getenv('OUTPUT_DIR', 'output'), help='Output directory.')
    parser.add_argument('-q', '--quick', action='store_true', help='Enable quick scan mode.')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose/debug output.')
    
    args = parser.parse_args()

    # Configurar nivel del logger
    if args.verbose or os.getenv('VERBOSE', 'false').lower() == 'true':
        logger.setLevel("DEBUG")
        logger.debug("Verbose mode enabled.")
        
    start_time = time.time()
    
    output_dir = Path(args.output).resolve()
    
    logger.info(f"Starting Ultra-BugBountyScanner for targets: {', '.join(args.domain)}")
    logger.info(f"Output will be saved to: {output_dir}")
    if args.quick:
        logger.warning("Quick mode is enabled. Intensive tasks will be skipped.")

    if not setup_directories(output_dir, args.domain):
        return # Salir si no se pueden crear los directorios

    for domain in args.domain:
        logger.info(f"Processing target: {domain}")
        enumerate_subdomains(domain, output_dir)
        scan_ports(domain, output_dir, args.quick)
        # Aquí se añadirán las llamadas a las demás fases (web, content, etc.) en la Fase 2
        logger.success(f"Finished processing for {domain}")

    duration = time.time() - start_time
    logger.success(f"All scans completed in {duration:.2f} seconds.")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        logger.warning("Scan interrupted by user.")
    except Exception as e:
        logger.exception(f"An unhandled exception occurred: {e}")
