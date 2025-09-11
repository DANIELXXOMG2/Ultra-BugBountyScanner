"""Módulo para análisis de resultados usando Google Gemini."""

from pathlib import Path
from typing import TYPE_CHECKING, Optional

from utils.logger import UltraLogger

if TYPE_CHECKING:
    import google.generativeai as genai
else:
    try:
        import google.generativeai as genai
    except ImportError:
        genai = None

# Configurar logger
logger = UltraLogger("ai_analyzer")


def get_gemini_summary(api_key: str, scan_results: str) -> Optional[str]:
    """Genera un resumen ejecutivo de los resultados de escaneo usando Gemini.

    Args:
        api_key: Clave de API de Google Gemini
        scan_results: Resultados del escaneo concatenados

    Returns:
        Resumen generado por IA o None si falla

    Raises:
        ValueError: Si api_key o scan_results están vacíos
        ImportError: Si google-generativeai no está instalado
    """
    # Verificar que la librería esté disponible
    if not TYPE_CHECKING and genai is None:
        logger.error("google-generativeai no está instalado. Instala con: pip install google-generativeai")
        return None

    # Validación de entrada
    if not api_key or not api_key.strip():
        logger.error("api_key no puede estar vacío")
        raise ValueError("api_key no puede estar vacío")

    if not scan_results or not scan_results.strip():
        logger.error("scan_results no puede estar vacío")
        raise ValueError("scan_results no puede estar vacío")

    try:
        # Configurar el cliente de Gemini
        genai.configure(api_key=api_key.strip())

        # Inicializar el modelo
        model = genai.GenerativeModel("gemini-pro")

        # Construir el prompt para el análisis
        prompt = _build_analysis_prompt(scan_results.strip())

        logger.info("Enviando resultados a Gemini para análisis...")

        # Generar el resumen
        response = model.generate_content(
            prompt,
            generation_config=genai.types.GenerationConfig(
                temperature=0.3,  # Respuestas más consistentes
                max_output_tokens=2048,  # Límite de tokens de salida
                top_p=0.8,
                top_k=40,
            ),
        )

        # Verificar que la respuesta sea válida
        if response and response.text:
            logger.info("Resumen de IA generado exitosamente")
            return str(response.text).strip()
        logger.warning("Gemini no generó contenido válido")
        return None

    except Exception as e:
        logger.error(f"Error al generar resumen con Gemini: {str(e)}")
        return None


def _build_analysis_prompt(scan_results: str) -> str:
    """Construye el prompt para el análisis de Gemini.

    Args:
        scan_results: Resultados del escaneo

    Returns:
        Prompt formateado para Gemini
    """
    return f"""Actúa como un analista senior de ciberseguridad especializado en bug bounty y pentesting.

Analiza los siguientes resultados de escaneo de reconocimiento y proporciona:

1. **RESUMEN EJECUTIVO**: Un resumen conciso de los hallazgos más importantes
2. **TOP 3 HALLAZGOS CRÍTICOS**: Los 3 descubrimientos más importantes ordenados por criticidad
3. **RECOMENDACIONES**: Próximos pasos específicos para la investigación
4. **SUPERFICIE DE ATAQUE**: Evaluación del perímetro de ataque identificado

Datos del escaneo:
{scan_results}

Enfócate en hallazgos que sean relevantes para bug bounty y pentesting."""


def save_ai_summary(summary: str, output_file: str) -> bool:
    """Guarda el resumen de IA en un archivo.

    Args:
        summary: Resumen generado por IA
        output_file: Ruta del archivo de salida

    Returns:
        True si se guardó exitosamente, False en caso contrario
    """
    try:
        output_path = Path(output_file)
        with output_path.open("w", encoding="utf-8") as f:
            f.write("# Resumen de Análisis de IA\n\n")
            f.write("Generado por Ultra-BugBountyScanner usando Google Gemini\n\n")
            f.write("---\n\n")
            f.write(summary)

        logger.info(f"Resumen de IA guardado en: {output_file}")
        return True

    except Exception as e:
        logger.error(f"Error al guardar resumen de IA: {str(e)}")
        return False


def format_scan_data_for_ai(
    subdomains_file: Optional[str] = None,
    ports_file: Optional[str] = None,
    vulnerabilities_file: Optional[str] = None,
    web_assets_file: Optional[str] = None,
) -> str:
    """Formatea los datos de escaneo para el análisis de IA.

    Args:
        subdomains_file: Ruta al archivo de subdominios
        ports_file: Ruta al archivo de puertos
        vulnerabilities_file: Ruta al archivo de vulnerabilidades
        web_assets_file: Ruta al archivo de assets web

    Returns:
        Datos formateados para el análisis
    """
    scan_data_parts = []

    # Leer subdominios
    if subdomains_file:
        try:
            subdomains_path = Path(subdomains_file)
            with subdomains_path.open(encoding="utf-8") as f:
                subdomains = f.read().strip()
                if subdomains:
                    scan_data_parts.append(f"## SUBDOMINIOS ENCONTRADOS\n{subdomains}\n")
        except FileNotFoundError:
            logger.warning(f"Archivo de subdominios no encontrado: {subdomains_file}")
        except Exception as e:
            logger.error(f"Error leyendo archivo de subdominios: {e}")

    # Leer archivo de puertos
    if ports_file:
        try:
            ports_path = Path(ports_file)
            with ports_path.open(encoding="utf-8") as f:
                ports = f.read().strip()
                if ports:
                    scan_data_parts.append(f"## ESCANEO DE PUERTOS\n{ports}\n")
        except FileNotFoundError:
            logger.warning(f"Archivo de puertos no encontrado: {ports_file}")
        except Exception as e:
            logger.error(f"Error leyendo archivo de puertos: {e}")

    # Leer archivo de vulnerabilidades
    if vulnerabilities_file:
        try:
            vulnerabilities_path = Path(vulnerabilities_file)
            with vulnerabilities_path.open(encoding="utf-8") as f:
                vulnerabilities = f.read().strip()
                if vulnerabilities:
                    scan_data_parts.append(f"## VULNERABILIDADES DETECTADAS\n{vulnerabilities}\n")
        except FileNotFoundError:
            logger.warning(f"Archivo de vulnerabilidades no encontrado: {vulnerabilities_file}")
        except Exception as e:
            logger.error(f"Error leyendo archivo de vulnerabilidades: {e}")

    # Leer archivo de assets web
    if web_assets_file:
        try:
            web_assets_path = Path(web_assets_file)
            with web_assets_path.open(encoding="utf-8") as f:
                web_assets = f.read().strip()
                if web_assets:
                    scan_data_parts.append(f"## ASSETS WEB ACTIVOS\n{web_assets}\n")
        except FileNotFoundError:
            logger.warning(f"Archivo de assets web no encontrado: {web_assets_file}")
        except Exception as e:
            logger.error(f"Error leyendo archivo de assets web: {e}")

    if not scan_data_parts:
        return "No se encontraron datos de escaneo para analizar."

    return "\n".join(scan_data_parts)
