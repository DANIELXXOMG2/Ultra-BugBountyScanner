#!/usr/bin/env python3
"""Módulo de enumeración de subdominios para Ultra-BugBountyScanner v2.3.

Este módulo contiene la funcionalidad para enumerar subdominios usando
múltiples herramientas: subfinder, amass y crt.sh.

Author: Ultra-BugBountyScanner Team
"""

from pathlib import Path
from typing import Dict, Set

from utils.logger import get_logger
from utils.runner import run_command

# Inicializar logger
logger = get_logger()


def enumerate_subdomains(domain: str, output_dir: Path) -> None:
    """Fase 1: Enumeración de Subdominios.
    
    Utiliza múltiples herramientas para enumerar subdominios:
    - subfinder: Herramienta rápida de enumeración pasiva
    - amass: Herramienta completa de reconocimiento
    - crt.sh: Certificate Transparency logs
    
    Args:
        domain: Dominio objetivo para enumeración
        output_dir: Directorio base de salida
    """
    logger.info(f"Starting subdomain enumeration for {domain}")
    domain_out = output_dir / domain / "subdomains"
    all_subs_file = domain_out / "all_subdomains.txt"

    # Herramientas y sus archivos de salida
    tools: Dict[str, Path] = {
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
    all_subdomains: Set[str] = set()
    for tool_file in tools.values():
        if tool_file.exists():
            with tool_file.open() as f:
                subdomains = {line.strip() for line in f if line.strip()}
                all_subdomains.update(subdomains)

    with all_subs_file.open("w") as f:
        for sub in sorted(all_subdomains):
            f.write(f"{sub}\n")

    logger.success(f"Found {len(all_subdomains)} unique subdomains for {domain}")