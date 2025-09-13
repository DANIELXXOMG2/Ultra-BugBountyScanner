#!/usr/bin/env python3
"""Secrets Scanner Module for Ultra-BugBountyScanner v2.3

Este módulo implementa la funcionalidad de escaneo de secretos utilizando:
- gitdorker: Para encontrar repositorios públicos asociados al dominio
- trufflehog: Para escanear secretos en los repositorios encontrados

Autor: danielxxomg2
Versión: 2.3
"""

import json
from pathlib import Path
import subprocess
import tempfile
from typing import List

from utils.runner import run_command
from utils.logger import get_logger

# Configurar logger específico para este módulo
logger = get_logger(__name__)


def scan_secrets(domain: str, output_dir: Path) -> None:
    """Escanea secretos utilizando gitdorker y trufflehog.
    
    Primero busca repositorios públicos asociados al dominio usando gitdorker,
    luego ejecuta trufflehog sobre los repositorios encontrados para detectar secretos.
    
    Args:
        domain: El dominio objetivo para el escaneo
        output_dir: Directorio base donde guardar los resultados
        
    Raises:
        FileNotFoundError: Si las herramientas requeridas no están instaladas
        subprocess.SubprocessError: Si hay errores en la ejecución de comandos
    """
    logger.info(f"🔍 Iniciando escaneo de secretos para dominio: {domain}")

    secrets_dir = output_dir / "secrets"
    secrets_dir.mkdir(exist_ok=True)

    # Paso 1: Buscar repositorios con gitdorker
    repositories = _find_repositories_with_gitdorker(domain, secrets_dir)

    if not repositories:
        logger.warning("⚠️  No se encontraron repositorios públicos para el dominio")
        # Crear archivo vacío para mantener consistencia
        results_file = secrets_dir / "trufflehog_results.json"
        with open(results_file, "w", encoding="utf-8") as f:
            json.dump({"domain": domain, "repositories_scanned": 0, "secrets_found": []}, f, indent=2)
        return

    # Paso 2: Escanear secretos con trufflehog
    _scan_repositories_with_trufflehog(repositories, secrets_dir, domain)

    logger.info(f"✅ Escaneo de secretos completado. Resultados guardados en: {secrets_dir}")


def _find_repositories_with_gitdorker(domain: str, output_dir: Path) -> List[str]:
    """Utiliza gitdorker para encontrar repositorios públicos asociados al dominio.
    
    Args:
        domain: El dominio objetivo
        output_dir: Directorio donde guardar resultados intermedios
        
    Returns:
        Lista de URLs de repositorios encontrados
    """
    logger.info(f"🔎 Buscando repositorios públicos para: {domain}")

    repos_file = output_dir / "github_repositories.txt"

    # Comando GitDorker con parámetros optimizados
    cmd = [
        "python3", "/opt/GitDorker/GitDorker.py",
        "-q", domain,
        "-o", str(repos_file.stem),  # GitDorker usa el nombre base sin extensión
        "-d", "/opt/GitDorker/Dorks/medium_dorks.txt"  # Usar los dorks incluidos
    ]

    try:
        stdout, stderr = run_command(cmd, timeout=300)  # 5 minutos timeout

        if stdout is None:
            logger.error(f"❌ Error ejecutando GitDorker: {stderr}")
            return []

        # GitDorker genera archivos de salida, leer desde el archivo generado
        output_file = output_dir / f"{repos_file.stem}_repos.txt"
        if output_file.exists():
            repos = []
            with open(output_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and "github.com" in line:
                        repos.append(line)
            return repos
        else:
            logger.warning("GitDorker no generó archivo de salida")
            return []

    except subprocess.TimeoutExpired:
        logger.error("⏰ Timeout ejecutando GitDorker")
        return []
    except Exception as e:
        logger.error(f"❌ Error inesperado en GitDorker: {e}")
        return []


def _scan_repositories_with_trufflehog(repositories: List[str], output_dir: Path, domain: str) -> None:
    """Ejecuta trufflehog sobre la lista de repositorios para encontrar secretos.
    
    Args:
        repositories: Lista de URLs de repositorios a escanear
        output_dir: Directorio donde guardar los resultados
        domain: Dominio objetivo (para metadatos)
    """
    logger.info(f"🕵️  Escaneando {len(repositories)} repositorios con trufflehog")

    results_file = output_dir / "trufflehog_results.json"
    all_secrets = []

    for i, repo_url in enumerate(repositories, 1):
        logger.info(f"📂 Escaneando repositorio {i}/{len(repositories)}: {repo_url}")

        # Crear archivo temporal para resultados de este repositorio
        with tempfile.NamedTemporaryFile(mode="w+", suffix=".json", delete=False) as temp_file:
            temp_path = Path(temp_file.name)

        try:
            # Comando trufflehog optimizado
            cmd = [
                "trufflehog",
                "git",
                repo_url,
                "--json",
                "--output", str(temp_path),
                "--max-depth", "10",  # Limitar profundidad para performance
                "--no-verification"  # Acelerar escaneo (opcional)
            ]

            stdout, stderr = run_command(cmd, timeout=180)  # 3 minutos por repo

            if stdout is not None and temp_path.exists():
                # Leer y procesar resultados
                repo_secrets = _process_trufflehog_output(temp_path, repo_url)
                all_secrets.extend(repo_secrets)
                logger.info(f"🔑 Encontrados {len(repo_secrets)} secretos en {repo_url}")
            else:
                logger.warning(f"⚠️  No se pudieron escanear secretos en: {repo_url}. Error: {stderr}")

        except subprocess.TimeoutExpired:
            logger.warning(f"⏰ Timeout escaneando repositorio: {repo_url}")
        except Exception as e:
            logger.error(f"❌ Error escaneando {repo_url}: {e}")
        finally:
            # Limpiar archivo temporal
            if temp_path.exists():
                temp_path.unlink()

    # Guardar resultados consolidados
    final_results = {
        "domain": domain,
        "repositories_scanned": len(repositories),
        "total_secrets_found": len(all_secrets),
        "scan_timestamp": _get_current_timestamp(),
        "secrets": all_secrets
    }

    with open(results_file, "w", encoding="utf-8") as f:
        json.dump(final_results, f, indent=2, ensure_ascii=False)

    logger.info(f"💾 Resultados guardados: {len(all_secrets)} secretos encontrados")


def _process_trufflehog_output(temp_file: Path, repo_url: str) -> List[dict]:
    """Procesa la salida JSON de trufflehog y extrae información relevante.
    
    Args:
        temp_file: Archivo temporal con resultados de trufflehog
        repo_url: URL del repositorio escaneado
        
    Returns:
        Lista de secretos encontrados con metadatos
    """
    secrets = []

    try:
        with open(temp_file, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                try:
                    secret_data = json.loads(line)

                    # Extraer información relevante
                    processed_secret = {
                        "repository": repo_url,
                        "detector_type": secret_data.get("DetectorType", "unknown"),
                        "detector_name": secret_data.get("DetectorName", "unknown"),
                        "verified": secret_data.get("Verified", False),
                        "file_path": secret_data.get("SourceMetadata", {}).get("Data", {}).get("Git", {}).get("file", "unknown"),
                        "line_number": secret_data.get("SourceMetadata", {}).get("Data", {}).get("Git", {}).get("line", 0),
                        "commit": secret_data.get("SourceMetadata", {}).get("Data", {}).get("Git", {}).get("commit", "unknown"),
                        "raw_secret": secret_data.get("Raw", "")[:100] + "..." if len(secret_data.get("Raw", "")) > 100 else secret_data.get("Raw", "")
                    }

                    secrets.append(processed_secret)

                except json.JSONDecodeError:
                    logger.warning(f"⚠️  Línea JSON inválida en resultados de trufflehog: {line[:50]}...")
                    continue

    except Exception as e:
        logger.error(f"❌ Error procesando resultados de trufflehog: {e}")

    return secrets


def _get_current_timestamp() -> str:
    """Obtiene el timestamp actual en formato ISO.
    
    Returns:
        Timestamp en formato ISO string
    """
    from datetime import datetime
    return datetime.now().isoformat()


def _validate_tools() -> bool:
    """Valida que las herramientas necesarias estén instaladas.
    
    Returns:
        True si todas las herramientas están disponibles, False en caso contrario
    """
    import shutil
    
    # Verificar trufflehog
    if not shutil.which("trufflehog"):
        logger.error("❌ Herramienta requerida no encontrada: trufflehog")
        return False
    
    # Verificar GitDorker
    gitdorker_path = Path("/opt/GitDorker/GitDorker.py")
    if not gitdorker_path.exists():
        logger.error("❌ GitDorker no encontrado en /opt/GitDorker/GitDorker.py")
        return False
    
    # Verificar dorks de GitDorker
    dorks_path = Path("/opt/GitDorker/Dorks/medium_dorks.txt")
    if not dorks_path.exists():
        logger.error("❌ Archivo de dorks no encontrado en /opt/GitDorker/Dorks/medium_dorks.txt")
        return False
    
    logger.info("✅ Todas las herramientas necesarias están disponibles")
    return True


if __name__ == "__main__":
    # Código de prueba para desarrollo
    import sys

    if len(sys.argv) != 3:
        print("Uso: python secrets_scanner.py <domain> <output_dir>")
        sys.exit(1)

    test_domain = sys.argv[1]
    test_output = Path(sys.argv[2])

    if not _validate_tools():
        print("❌ Herramientas requeridas no disponibles")
        sys.exit(1)

    scan_secrets(test_domain, test_output)