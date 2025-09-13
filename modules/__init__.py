"""Módulos de escaneo para Ultra-BugBountyScanner v2.3.

Este paquete contiene todos los módulos especializados de escaneo:
- subdomain_scanner: Enumeración de subdominios
- port_scanner: Escaneo de puertos y servicios
- web_assets_scanner: Descubrimiento de activos web
- vulnerability_scanner: Detección de vulnerabilidades
- javascript_analyzer: Análisis de endpoints JavaScript
"""

__version__ = "2.3.0"
__author__ = "Ultra-BugBountyScanner Team"

# Importaciones principales para facilitar el uso
from .subdomain_scanner import enumerate_subdomains
from .port_scanner import scan_ports
from .web_assets_scanner import discover_web_assets
from .vulnerability_scanner import scan_vulnerabilities
from .javascript_analyzer import analyze_javascript

__all__ = [
    "enumerate_subdomains",
    "scan_ports",
    "discover_web_assets",
    "scan_vulnerabilities",
    "analyze_javascript",
]