#!/usr/bin/env python3
"""Bucket Scanner Module for Ultra-BugBountyScanner v2.3

Este módulo implementa la funcionalidad de escaneo de buckets S3 utilizando:
- Generación inteligente de nombres de bucket basados en subdominios
- s3scanner: Para detectar buckets S3 públicos y mal configurados

Autor: danielxxomg2
Versión: 2.3
"""

import json
from pathlib import Path
import subprocess
import tempfile
from typing import List, Set

from utils.runner import run_command
from utils.logger import get_logger

# Configurar logger específico para este módulo
logger = get_logger(__name__)


def scan_buckets(domain: str, output_dir: Path) -> None:
    """Escanea buckets S3 utilizando s3scanner con nombres generados inteligentemente.
    
    Lee la lista de subdominios, genera posibles nombres de bucket y ejecuta
    s3scanner para detectar buckets S3 públicos o mal configurados.
    
    Args:
        domain: El dominio objetivo para el escaneo
        output_dir: Directorio base donde guardar los resultados
        
    Raises:
        FileNotFoundError: Si s3scanner no está instalado o archivos requeridos no existen
        subprocess.SubprocessError: Si hay errores en la ejecución de comandos
    """
    logger.info(f"🪣 Iniciando escaneo de buckets S3 para dominio: {domain}")

    buckets_dir = output_dir / "buckets"
    buckets_dir.mkdir(exist_ok=True)

    # Paso 1: Leer subdominios existentes
    subdomains = _read_subdomains(output_dir)

    if not subdomains:
        logger.warning("⚠️  No se encontraron subdominios para generar nombres de bucket")
        # Crear archivo vacío para mantener consistencia
        results_file = buckets_dir / "s3scanner_results.txt"
        with open(results_file, "w", encoding="utf-8") as f:
            f.write(f"# S3 Bucket Scan Results for {domain}\n")
            f.write("# No subdomains found - no bucket names generated\n")
        return

    # Paso 2: Generar nombres de bucket
    bucket_names = _generate_bucket_names(domain, subdomains)

    if not bucket_names:
        logger.warning("⚠️  No se pudieron generar nombres de bucket")
        return

    # Paso 3: Escanear buckets con s3scanner
    _scan_buckets_with_s3scanner(bucket_names, buckets_dir, domain)

    logger.info(f"✅ Escaneo de buckets completado. Resultados guardados en: {buckets_dir}")


def _read_subdomains(output_dir: Path) -> List[str]:
    """Lee la lista de subdominios del archivo all_subdomains.txt.
    
    Args:
        output_dir: Directorio base donde buscar el archivo de subdominios
        
    Returns:
        Lista de subdominios únicos
    """
    subdomains_file = output_dir / "subdomains" / "all_subdomains.txt"

    if not subdomains_file.exists():
        logger.error(f"❌ Archivo de subdominios no encontrado: {subdomains_file}")
        return []

    try:
        with open(subdomains_file, encoding="utf-8") as f:
            subdomains = [line.strip() for line in f if line.strip() and not line.startswith("#")]

        # Remover duplicados manteniendo orden
        unique_subdomains = list(dict.fromkeys(subdomains))
        logger.info(f"📊 Leídos {len(unique_subdomains)} subdominios únicos")

        return unique_subdomains

    except Exception as e:
        logger.error(f"❌ Error leyendo archivo de subdominios: {e}")
        return []


def _generate_bucket_names(domain: str, subdomains: List[str]) -> List[str]:
    """Genera una lista de posibles nombres de bucket basados en el dominio y subdominios.
    
    Args:
        domain: Dominio principal
        subdomains: Lista de subdominios encontrados
        
    Returns:
        Lista de nombres de bucket únicos para probar
    """
    logger.info(f"🎯 Generando nombres de bucket para {len(subdomains)} subdominios")

    bucket_names: Set[str] = set()

    # Extraer dominio base sin TLD para variaciones
    domain_base = domain.split('.')[0]

    # Patrones comunes de nombres de bucket
    patterns = [
        # Patrones basados en dominio principal
        domain,
        domain_base,
        f"{domain_base}-assets",
        f"{domain_base}-backup",
        f"{domain_base}-backups",
        f"{domain_base}-data",
        f"{domain_base}-files",
        f"{domain_base}-images",
        f"{domain_base}-logs",
        f"{domain_base}-media",
        f"{domain_base}-static",
        f"{domain_base}-storage",
        f"{domain_base}-uploads",
        f"{domain_base}-www",
        f"assets-{domain_base}",
        f"backup-{domain_base}",
        f"data-{domain_base}",
        f"files-{domain_base}",
        f"media-{domain_base}",
        f"static-{domain_base}",
        f"www-{domain_base}",
        # Variaciones con guiones
        domain.replace('.', '-'),
        f"{domain.replace('.', '-')}-assets",
        f"{domain.replace('.', '-')}-backup",
        f"{domain.replace('.', '-')}-data",
    ]

    # Añadir patrones base
    bucket_names.update(patterns)

    # Generar nombres basados en subdominios
    for subdomain in subdomains[:50]:  # Limitar para evitar listas muy largas
        # Extraer parte del subdominio
        subdomain_part = subdomain.split('.')[0]

        if subdomain_part and len(subdomain_part) > 2:  # Evitar subdominios muy cortos
            subdomain_patterns = [
                subdomain,
                subdomain_part,
                f"{subdomain_part}-{domain_base}",
                f"{domain_base}-{subdomain_part}",
                f"{subdomain_part}-assets",
                f"{subdomain_part}-backup",
                f"{subdomain_part}-data",
                f"{subdomain_part}-files",
                f"{subdomain_part}-static",
                # Variaciones con guiones
                subdomain.replace('.', '-'),
                f"{subdomain.replace('.', '-')}-assets",
                f"{subdomain.replace('.', '-')}-backup",
            ]

            bucket_names.update(subdomain_patterns)

    # Filtrar nombres válidos (solo caracteres permitidos en nombres de bucket S3)
    valid_bucket_names = []
    for name in bucket_names:
        # Nombres de bucket S3: 3-63 caracteres, solo minúsculas, números, guiones y puntos
        cleaned_name = name.lower().replace('_', '-')
        if 3 <= len(cleaned_name) <= 63 and all(c.isalnum() or c in '.-' for c in cleaned_name):
            # No debe empezar o terminar con guión o punto
            if not cleaned_name.startswith(('-', '.')) and not cleaned_name.endswith(('-', '.')):
                valid_bucket_names.append(cleaned_name)

    # Remover duplicados y ordenar
    unique_names = sorted(list(set(valid_bucket_names)))

    logger.info(f"📝 Generados {len(unique_names)} nombres de bucket únicos")

    return unique_names


def _scan_buckets_with_s3scanner(bucket_names: List[str], output_dir: Path, domain: str) -> None:
    """Ejecuta s3scanner sobre la lista de nombres de bucket generados.
    
    Args:
        bucket_names: Lista de nombres de bucket a probar
        output_dir: Directorio donde guardar los resultados
        domain: Dominio objetivo (para metadatos)
    """
    logger.info(f"🔍 Escaneando {len(bucket_names)} posibles buckets con s3scanner")

    # Crear archivo temporal con nombres de bucket
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as temp_file:
        for bucket_name in bucket_names:
            temp_file.write(f"{bucket_name}\n")
        temp_path = Path(temp_file.name)

    results_file = output_dir / "s3scanner_results.txt"

    try:
        # Comando s3scanner optimizado
        cmd = [
            "s3scanner",
            "--input", str(temp_path),
            "--output", str(results_file),
            "--threads", "10",  # Paralelización moderada
            "--timeout", "30",  # Timeout por bucket
            "--verbose"  # Información detallada
        ]

        logger.info("🚀 Ejecutando s3scanner...")
        stdout, stderr = run_command(cmd, timeout=600)  # 10 minutos timeout total

        if stdout is not None:
            # Procesar y enriquecer resultados
            _process_s3scanner_results(results_file, domain, len(bucket_names))
            logger.info("✅ Escaneo de buckets completado exitosamente")
        else:
            logger.error(f"❌ Error ejecutando s3scanner: {stderr}")
            # Crear archivo de resultados con información del error
            with open(results_file, "w", encoding="utf-8") as f:
                f.write(f"# S3 Bucket Scan Results for {domain}\n")
                f.write("# Error occurred during scanning\n")
                f.write(f"# Command: {' '.join(cmd)}\n")
                f.write(f"# Error: {stderr}\n")

    except subprocess.TimeoutExpired:
        logger.error("⏰ Timeout ejecutando s3scanner")
        with open(results_file, "w", encoding="utf-8") as f:
            f.write(f"# S3 Bucket Scan Results for {domain}\n")
            f.write("# Scan timed out after 10 minutes\n")
            f.write(f"# Buckets tested: {len(bucket_names)}\n")
    except Exception as e:
        logger.error(f"❌ Error inesperado ejecutando s3scanner: {e}")
        with open(results_file, "w", encoding="utf-8") as f:
            f.write(f"# S3 Bucket Scan Results for {domain}\n")
            f.write(f"# Unexpected error: {e}\n")
    finally:
        # Limpiar archivo temporal
        if temp_path.exists():
            temp_path.unlink()


def _process_s3scanner_results(results_file: Path, domain: str, total_tested: int) -> None:
    """Procesa y enriquece los resultados de s3scanner con metadatos adicionales.
    
    Args:
        results_file: Archivo con resultados de s3scanner
        domain: Dominio objetivo
        total_tested: Número total de buckets probados
    """
    if not results_file.exists():
        logger.warning("⚠️  Archivo de resultados de s3scanner no encontrado")
        return

    try:
        # Leer resultados existentes
        with open(results_file, encoding="utf-8") as f:
            original_content = f.read()

        # Contar buckets encontrados
        found_buckets = 0
        accessible_buckets = 0

        lines = original_content.split('\n')
        for line in lines:
            if 'bucket found' in line.lower() or 'exists' in line.lower():
                found_buckets += 1
            if 'readable' in line.lower() or 'writable' in line.lower():
                accessible_buckets += 1

        # Crear contenido enriquecido
        enriched_content = f"""# S3 Bucket Scan Results for {domain}
# Scan completed at: {_get_current_timestamp()}
# Total buckets tested: {total_tested}
# Buckets found: {found_buckets}
# Accessible buckets: {accessible_buckets}
# ================================================

{original_content}

# ================================================
# Scan Summary:
# - Domain: {domain}
# - Total tested: {total_tested}
# - Found: {found_buckets}
# - Accessible: {accessible_buckets}
# - Risk Level: {'HIGH' if accessible_buckets > 0 else 'MEDIUM' if found_buckets > 0 else 'LOW'}
"""

        # Escribir contenido enriquecido
        with open(results_file, "w", encoding="utf-8") as f:
            f.write(enriched_content)

        # También crear un resumen JSON para integración
        summary_file = results_file.parent / "bucket_scan_summary.json"
        summary_data = {
            "domain": domain,
            "scan_timestamp": _get_current_timestamp(),
            "total_buckets_tested": total_tested,
            "buckets_found": found_buckets,
            "accessible_buckets": accessible_buckets,
            "risk_level": "HIGH" if accessible_buckets > 0 else "MEDIUM" if found_buckets > 0 else "LOW",
            "results_file": str(results_file.name)
        }

        with open(summary_file, "w", encoding="utf-8") as f:
            json.dump(summary_data, f, indent=2, ensure_ascii=False)

        logger.info(f"📊 Resumen: {found_buckets} buckets encontrados, {accessible_buckets} accesibles")

    except Exception as e:
        logger.error(f"❌ Error procesando resultados de s3scanner: {e}")


def _get_current_timestamp() -> str:
    """Obtiene el timestamp actual en formato ISO.
    
    Returns:
        Timestamp en formato ISO string
    """
    from datetime import datetime
    return datetime.now().isoformat()


def _validate_s3scanner() -> bool:
    """Valida que s3scanner esté disponible.
    
    Returns:
        True si s3scanner está disponible, False en caso contrario
    """
    try:
        result = subprocess.run(["s3scanner", "--help"],
                              capture_output=True,
                              text=True,
                              timeout=10)
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        logger.error("❌ s3scanner no encontrado o no disponible")
        return False


if __name__ == "__main__":
    # Código de prueba para desarrollo
    import sys

    if len(sys.argv) != 3:
        print("Uso: python bucket_scanner.py <domain> <output_dir>")
        sys.exit(1)

    test_domain = sys.argv[1]
    test_output = Path(sys.argv[2])

    if not _validate_s3scanner():
        print("❌ s3scanner no disponible")
        sys.exit(1)

    scan_buckets(test_domain, test_output)