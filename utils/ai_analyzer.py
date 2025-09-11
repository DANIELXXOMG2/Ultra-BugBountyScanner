"""Módulo de análisis de resultados impulsado por IA usando Google Gemini.

Este módulo proporciona funcionalidades para analizar los resultados de escaneo
de vulnerabilidades y generar resúmenes ejecutivos usando la API de Google Gemini.
"""

import logging
from typing import Optional

try:
    import google.generativeai as genai

    GENAI_AVAILABLE = True
except ImportError:
    genai = None  # type: ignore[assignment]
    GENAI_AVAILABLE = False

# Configurar logger
logger = logging.getLogger(__name__)


def get_gemini_summary(api_key: str, scan_results: str) -> Optional[str]:
    """Genera un resumen ejecutivo de los resultados de escaneo usando Google Gemini.

    Args:
        api_key: Clave de API de Google Gemini
        scan_results: Datos concatenados de los resultados del escaneo

    Returns:
        Resumen ejecutivo generado por IA o None si falla
    """
    if not GENAI_AVAILABLE or genai is None:
        logger.error("La librería google-generativeai no está instalada")
        return None

    if not api_key or not scan_results:
        logger.error("API key o scan_results están vacíos")
        return None

    try:
        # Configurar el cliente de Gemini
        genai.configure(api_key=api_key)

        # Seleccionar el modelo optimizado para velocidad y costo
        model = genai.GenerativeModel("gemini-2.5-flash-lite")

        # Prompt de sistema detallado para análisis de ciberseguridad
        system_prompt = """
Actúa como un Analista Experto en Ciberseguridad con más de 10 años de experiencia en Bug Bounty y Pentesting.

Tu tarea es analizar los resultados de un escaneo de reconocimiento y generar un resumen ejecutivo profesional.

FORMATO DE SALIDA REQUERIDO:

## 🎯 Resumen Ejecutivo
[Un párrafo conciso describiendo el alcance del escaneo, número de subdominios encontrados,
puertos abiertos y vulnerabilidades detectadas]

## 🚨 Hallazgos Más Críticos (Top 3)
1. **[Título del hallazgo]**: [Descripción detallada del riesgo y su impacto potencial]
2. **[Título del hallazgo]**: [Descripción detallada del riesgo y su impacto potencial]
3. **[Título del hallazgo]**: [Descripción detallada del riesgo y su impacto potencial]

## 🌐 Superficie de Ataque Potencial
[Descripción de los tipos de servicios expuestos, tecnologías identificadas y posibles vectores de ataque]

## 📋 Recomendaciones / Siguientes Pasos
- **Inmediato**: [Acciones urgentes a tomar]
- **Corto plazo**: [Investigaciones adicionales recomendadas]
- **Herramientas sugeridas**: [Herramientas específicas como Metasploit, Burp Suite, etc.]

CRITERIOS DE ANÁLISIS:
- Prioriza vulnerabilidades de severidad CRITICAL y HIGH
- Identifica servicios sensibles (SSH, RDP, bases de datos, paneles admin)
- Busca patrones que indiquen configuraciones inseguras
- Sugiere técnicas de explotación específicas cuando sea apropiado
- Mantén un enfoque profesional y técnico

Si no encuentras vulnerabilidades críticas, enfócate en la superficie de ataque y
oportunidades de investigación adicional.
"""

        # Construir el prompt completo
        full_prompt = f"{system_prompt}\n\nDATOS DEL ESCANEO A ANALIZAR:\n{scan_results}"

        logger.info("Enviando datos a Gemini para análisis...")

        # Generar el resumen usando Gemini
        response = model.generate_content(
            full_prompt,
            generation_config=genai.types.GenerationConfig(
                temperature=0.3,  # Respuestas más consistentes
                max_output_tokens=2048,  # Límite razonable para el resumen
                top_p=0.8,
                top_k=40,
            ),
        )

        if response and hasattr(response, "text") and response.text:
            logger.info("Resumen de IA generado exitosamente")
            return str(response.text).strip()
        logger.error("Gemini no devolvió contenido válido")
        return None

    except Exception as e:
        logger.error(f"Error al generar resumen con Gemini: {e}")
        return None
