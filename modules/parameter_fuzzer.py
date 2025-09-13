#!/usr/bin/env python3
"""Parameter Fuzzer Module for Ultra-BugBountyScanner v2.3

Este módulo implementa la funcionalidad de fuzzing de parámetros utilizando:
- arjun: Para descubrir parámetros HTTP ocultos en aplicaciones web
- Procesamiento inteligente de URLs desde httpx_urls.txt

Autor: danielxxomg2
Versión: 2.3
"""

import json
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Set, Any, cast
from urllib.parse import urlparse

from utils.runner import run_command
from utils.logger import get_logger

# Configurar logger específico para este módulo
logger = get_logger(__name__)


def fuzz_parameters(domain: str, output_dir: Path) -> None:
    """Ejecuta fuzzing de parámetros utilizando arjun sobre URLs encontradas.
    
    Lee las URLs del archivo httpx_urls.txt y ejecuta arjun para descubrir
    parámetros HTTP ocultos que podrían ser vulnerables.
    
    Args:
        domain: El dominio objetivo para el escaneo
        output_dir: Directorio base donde guardar los resultados
        
    Raises:
        FileNotFoundError: Si arjun no está instalado o archivos requeridos no existen
        subprocess.SubprocessError: Si hay errores en la ejecución de comandos
    """
    logger.info(f"🎯 Iniciando fuzzing de parámetros para dominio: {domain}")

    parameters_dir = output_dir / "parameters"
    parameters_dir.mkdir(exist_ok=True)

    # Paso 1: Leer URLs de httpx
    urls = _read_httpx_urls(output_dir)

    if not urls:
        logger.warning("⚠️  No se encontraron URLs para fuzzing de parámetros")
        # Crear archivo vacío para mantener consistencia
        results_file = parameters_dir / "arjun_results.json"
        with open(results_file, "w", encoding="utf-8") as f:
            json.dump({
                "domain": domain,
                "urls_tested": 0,
                "parameters_found": [],
                "scan_timestamp": _get_current_timestamp()
            }, f, indent=2)
        return

    # Paso 2: Filtrar y preparar URLs para fuzzing
    target_urls = _prepare_urls_for_fuzzing(urls, domain)

    if not target_urls:
        logger.warning("⚠️  No se encontraron URLs válidas para fuzzing")
        return

    # Paso 3: Ejecutar arjun sobre las URLs
    _fuzz_parameters_with_arjun(target_urls, parameters_dir, domain)

    logger.info(f"✅ Fuzzing de parámetros completado. Resultados guardados en: {parameters_dir}")


def _read_httpx_urls(output_dir: Path) -> List[str]:
    """Lee las URLs del archivo httpx_urls.txt.
    
    Args:
        output_dir: Directorio base donde buscar el archivo de URLs
        
    Returns:
        Lista de URLs encontradas
    """
    urls_file = output_dir / "web" / "httpx_urls.txt"

    if not urls_file.exists():
        logger.error(f"❌ Archivo de URLs no encontrado: {urls_file}")
        return []

    try:
        with open(urls_file, encoding="utf-8") as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith("#")]

        logger.info(f"📊 Leídas {len(urls)} URLs desde httpx")
        return urls

    except Exception as e:
        logger.error(f"❌ Error leyendo archivo de URLs: {e}")
        return []


def _prepare_urls_for_fuzzing(urls: List[str], domain: str) -> List[str]:
    """Filtra y prepara URLs para fuzzing de parámetros.
    
    Args:
        urls: Lista de URLs encontradas
        domain: Dominio objetivo
        
    Returns:
        Lista de URLs preparadas para fuzzing
    """
    logger.info("🔧 Preparando URLs para fuzzing de parámetros")

    target_urls: Set[str] = set()

    for url in urls:
        try:
            parsed = urlparse(url)

            # Filtrar solo URLs del dominio objetivo
            if domain not in parsed.netloc:
                continue

            # Filtrar URLs que probablemente acepten parámetros
            if _is_suitable_for_parameter_fuzzing(url, parsed):
                # Limpiar URL (remover parámetros existentes para fuzzing limpio)
                clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                target_urls.add(clean_url)

        except Exception as e:
            logger.warning(f"⚠️  Error procesando URL {url}: {e}")
            continue

    # Limitar número de URLs para evitar escaneos muy largos
    final_urls = list(target_urls)[:50]  # Máximo 50 URLs

    logger.info(f"🎯 Seleccionadas {len(final_urls)} URLs para fuzzing")
    return final_urls


def _is_suitable_for_parameter_fuzzing(url: str, parsed: Any) -> bool:
    """Determina si una URL es adecuada para fuzzing de parámetros.
    
    Args:
        url: URL completa
        parsed: URL parseada
        
    Returns:
        True si la URL es adecuada para fuzzing
    """
    # Excluir archivos estáticos
    static_extensions = {
        '.css', '.js', '.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico',
        '.pdf', '.zip', '.tar', '.gz', '.mp4', '.mp3', '.avi', '.mov',
        '.woff', '.woff2', '.ttf', '.eot', '.xml', '.txt'
    }

    path_lower = parsed.path.lower()

    # Excluir si termina con extensión estática
    if any(path_lower.endswith(ext) for ext in static_extensions):
        return False

    # Excluir rutas de assets comunes
    excluded_paths = {
        '/assets/', '/static/', '/css/', '/js/', '/images/', '/img/',
        '/fonts/', '/media/', '/uploads/', '/downloads/', '/files/'
    }

    if any(excluded_path in path_lower for excluded_path in excluded_paths):
        return False

    # Preferir URLs que probablemente acepten parámetros
    preferred_indicators = {
        '/api/', '/search', '/login', '/register', '/profile', '/user',
        '/admin', '/dashboard', '/form', '/submit', '/query', '/filter'
    }

    # Si contiene indicadores preferidos, definitivamente incluir
    if any(indicator in path_lower for indicator in preferred_indicators):
        return True

    # Incluir URLs con rutas dinámicas (contienen números o IDs)
    if any(char.isdigit() for char in parsed.path):
        return True

    # Incluir URLs raíz y rutas simples
    if parsed.path in ['/', ''] or len(parsed.path.split('/')) <= 3:
        return True

    return False


def _fuzz_parameters_with_arjun(urls: List[str], output_dir: Path, domain: str) -> None:
    """Ejecuta arjun sobre las URLs seleccionadas para encontrar parámetros ocultos.
    
    Args:
        urls: Lista de URLs a probar
        output_dir: Directorio donde guardar los resultados
        domain: Dominio objetivo (para metadatos)
    """
    logger.info(f"🚀 Ejecutando arjun sobre {len(urls)} URLs")

    results_file = output_dir / "arjun_results.json"
    all_parameters: List[Dict] = []

    # Crear archivo temporal con URLs
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as temp_file:
        for url in urls:
            temp_file.write(f"{url}\n")
        temp_path = Path(temp_file.name)

    try:
        # Comando arjun optimizado
        cmd = [
            "arjun",
            "-i", str(temp_path),
            "-o", str(results_file),
            "--json",  # Salida en formato JSON
            "-t", "10",  # 10 threads para paralelización
            "-d", "1",   # Delay de 1 segundo entre requests
            "--stable",  # Usar modo estable para mejor precisión
            "-w", "small",  # Usar wordlist pequeña para velocidad
            "--headers", "User-Agent: Ultra-BugBountyScanner-v2.3"
        ]

        logger.info("🔍 Ejecutando arjun para fuzzing de parámetros...")
        stdout, stderr = run_command(cmd, timeout=1800)  # 30 minutos timeout

        if stdout is not None:
            # Procesar resultados
            _process_arjun_results(results_file, domain, len(urls))
            logger.info("✅ Fuzzing de parámetros completado exitosamente")
        else:
            logger.error(f"❌ Error ejecutando arjun: {stderr}")
            # Crear archivo de resultados con información del error
            error_results = {
                "domain": domain,
                "urls_tested": len(urls),
                "parameters_found": [],
                "error": stderr,
                "scan_timestamp": _get_current_timestamp()
            }

            with open(results_file, "w", encoding="utf-8") as f:
                json.dump(error_results, f, indent=2, ensure_ascii=False)

    except subprocess.TimeoutExpired:
        logger.error("⏰ Timeout ejecutando arjun")
        timeout_results = {
            "domain": domain,
            "urls_tested": len(urls),
            "parameters_found": [],
            "error": "Scan timed out after 30 minutes",
            "scan_timestamp": _get_current_timestamp()
        }

        with open(results_file, "w", encoding="utf-8") as f:
            json.dump(timeout_results, f, indent=2, ensure_ascii=False)

    except Exception as e:
        logger.error(f"❌ Error inesperado ejecutando arjun: {e}")
        error_results = {
            "domain": domain,
            "urls_tested": len(urls),
            "parameters_found": [],
            "error": str(e),
            "scan_timestamp": _get_current_timestamp()
        }

        with open(results_file, "w", encoding="utf-8") as f:
            json.dump(error_results, f, indent=2, ensure_ascii=False)

    finally:
        # Limpiar archivo temporal
        if temp_path.exists():
            temp_path.unlink()


def _process_arjun_results(results_file: Path, domain: str, urls_tested: int) -> None:
    """Procesa y enriquece los resultados de arjun con metadatos adicionales.
    
    Args:
        results_file: Archivo con resultados de arjun
        domain: Dominio objetivo
        urls_tested: Número de URLs probadas
    """
    if not results_file.exists():
        logger.warning("⚠️  Archivo de resultados de arjun no encontrado")
        return

    try:
        # Leer resultados de arjun
        with open(results_file, encoding="utf-8") as f:
            arjun_data = json.load(f)

        # Procesar y estructurar datos
        processed_results: Dict[str, object] = {
            "domain": domain,
            "urls_tested": urls_tested,
            "scan_timestamp": _get_current_timestamp(),
            "parameters_found": [],
            "summary": {
                "total_parameters": 0,
                "unique_parameters": set(),
                "urls_with_parameters": 0
            }
        }

        # Procesar resultados por URL
        if isinstance(arjun_data, dict):
            for url, params in arjun_data.items():
                if isinstance(params, list) and params:
                    url_result = {
                        "url": url,
                        "parameters": params,
                        "parameter_count": len(params),
                        "risk_level": _assess_parameter_risk(params)
                    }

                    cast(List[Dict[str, Any]], processed_results["parameters_found"]).append(url_result)
                    cast(Dict[str, Any], processed_results["summary"])["total_parameters"] += len(params)
                    cast(Set[str], cast(Dict[str, Any], processed_results["summary"])["unique_parameters"]).update(params)
                    cast(Dict[str, Any], processed_results["summary"])["urls_with_parameters"] += 1

        # Convertir set a lista para JSON
        summary = cast(Dict[str, Any], processed_results["summary"])
        unique_params_set = cast(Set[str], summary["unique_parameters"])
        summary["unique_parameters"] = list(unique_params_set)
        summary["unique_parameter_count"] = len(summary["unique_parameters"])

        # Guardar resultados procesados
        with open(results_file, "w", encoding="utf-8") as f:
            json.dump(processed_results, f, indent=2, ensure_ascii=False)

        # Crear resumen adicional
        summary_file = results_file.parent / "parameter_scan_summary.txt"
        with open(summary_file, "w", encoding="utf-8") as f:
            f.write(f"Parameter Fuzzing Summary for {domain}\n")
            f.write(f"{'='*50}\n")
            f.write(f"Scan Date: {processed_results['scan_timestamp']}\n")
            f.write(f"URLs Tested: {urls_tested}\n")
            f.write(f"URLs with Parameters: {cast(Dict[str, Any], processed_results['summary'])['urls_with_parameters']}\n")
            f.write(f"Total Parameters Found: {cast(Dict[str, Any], processed_results['summary'])['total_parameters']}\n")
            f.write(f"Unique Parameters: {cast(Dict[str, Any], processed_results['summary'])['unique_parameter_count']}\n\n")

            parameters_found = cast(List[Dict[str, Any]], processed_results["parameters_found"])
            if parameters_found:
                f.write("Parameters by URL:\n")
                f.write("-" * 30 + "\n")
                for url_result in parameters_found:
                    f.write(f"\nURL: {url_result['url']}\n")
                    f.write(f"Parameters ({url_result['parameter_count']}): {', '.join(url_result['parameters'])}\n")
                    f.write(f"Risk Level: {url_result['risk_level']}\n")

        summary_data = cast(Dict[str, Any], processed_results['summary'])
        logger.info(f"📊 Parámetros encontrados: {summary_data['total_parameters']} total, {summary_data['unique_parameter_count']} únicos")

    except Exception as e:
        logger.error(f"❌ Error procesando resultados de arjun: {e}")


def _assess_parameter_risk(parameters: List[str]) -> str:
    """Evalúa el nivel de riesgo basado en los parámetros encontrados.
    
    Args:
        parameters: Lista de parámetros encontrados
        
    Returns:
        Nivel de riesgo: HIGH, MEDIUM, LOW
    """
    high_risk_params = {
        'id', 'user_id', 'admin', 'password', 'pass', 'token', 'key',
        'secret', 'api_key', 'auth', 'login', 'username', 'email',
        'file', 'path', 'url', 'redirect', 'callback', 'return_url'
    }

    medium_risk_params = {
        'search', 'query', 'q', 'filter', 'sort', 'order', 'limit',
        'offset', 'page', 'size', 'format', 'type', 'category'
    }

    param_lower = [p.lower() for p in parameters]

    # Verificar parámetros de alto riesgo
    if any(param in high_risk_params for param in param_lower):
        return "HIGH"

    # Verificar parámetros de riesgo medio
    if any(param in medium_risk_params for param in param_lower):
        return "MEDIUM"

    return "LOW"


def _get_current_timestamp() -> str:
    """Obtiene el timestamp actual en formato ISO.
    
    Returns:
        Timestamp en formato ISO string
    """
    from datetime import datetime
    return datetime.now().isoformat()


def _validate_arjun() -> bool:
    """Valida que arjun esté disponible.
    
    Returns:
        True si arjun está disponible, False en caso contrario
    """
    try:
        result = subprocess.run(["arjun", "--help"],
                              capture_output=True,
                              text=True,
                              timeout=10)
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        logger.error("❌ arjun no encontrado o no disponible")
        return False


if __name__ == "__main__":
    # Código de prueba para desarrollo
    import sys

    if len(sys.argv) != 3:
        print("Uso: python parameter_fuzzer.py <domain> <output_dir>")
        sys.exit(1)

    test_domain = sys.argv[1]
    test_output = Path(sys.argv[2])

    if not _validate_arjun():
        print("❌ arjun no disponible")
        sys.exit(1)

    fuzz_parameters(test_domain, test_output)