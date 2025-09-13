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
        model = genai.GenerativeModel("gemini-1.5-flash-latest")

        # Prompt avanzado v2.1 con puntuación de riesgo y vectores de ataque
        system_prompt = """
Actúa como un Analista Experto en Ciberseguridad con más de 10 años de experiencia en Bug Bounty y Pentesting.

Tu tarea es analizar los resultados de un escaneo de reconocimiento y generar un reporte
    técnico avanzado con puntuación de riesgo, vectores de ataque y recomendaciones tácticas específicas.

FORMATO DE SALIDA REQUERIDO:

## 🛡️ Reporte de Análisis de Seguridad
### 📊 Puntuación de Riesgo Global: [X]/10

### 🎯 Resumen Ejecutivo
[Párrafo conciso describiendo el alcance del escaneo, número de subdominios encontrados,
puertos abiertos y vulnerabilidades detectadas con contexto de riesgo]

### 🚨 Hallazgos Críticos Priorizados
| Severidad | Vulnerabilidad | Host Afectado | Impacto | Explotabilidad |
|-----------|----------------|---------------|---------|----------------|
| [CRITICAL/HIGH/MEDIUM] | [Nombre] | [Host] | [Descripción] | [Facilidad 1-5] |

### ⚔️ Tabla de Vectores de Ataque
| Vector | Activos Afectados | Técnicas Sugeridas | Herramientas Recomendadas |
|--------|-------------------|-------------------|---------------------------|
| [Tipo] | [Lista hosts] | [Técnicas específicas] | [nmap, ffuf, burp, etc.] |

### 🌐 Superficie de Ataque Identificada
- **Servicios Web Expuestos**: [Lista con tecnologías detectadas]
- **Puertos Sensibles Abiertos**: [SSH, RDP, bases de datos, etc.]
- **Subdominios de Alto Valor**: [admin, api, dev, staging, etc.]
- **Tecnologías Vulnerables**: [Versiones desactualizadas identificadas]

### 📋 Recomendaciones Tácticas
#### 🔴 Acciones Inmediatas (0-24h)
```bash
# Comandos específicos para investigación inmediata
[comandos nmap, ffuf, curl específicos]
```

#### 🟡 Investigación Adicional (1-7 días)
- **Fuzzing Avanzado**: [Directorios y parámetros específicos a probar]
- **Análisis Manual**: [Endpoints específicos para revisión manual]
- **Técnicas de Bypass**: [WAF, autenticación, etc.]

#### 🟢 Monitoreo Continuo
- **Subdominios a Vigilar**: [Lista para monitoreo]
- **Cambios de Configuración**: [Servicios a supervisar]

CRITERIOS DE ANÁLISIS AVANZADOS:
- Calcula puntuación de riesgo basada en: severidad × exposición × facilidad de explotación
- Prioriza vectores con mayor potencial de impacto en el negocio
- Proporciona comandos bash específicos y listos para ejecutar
- Identifica patrones de configuración insegura y malas prácticas
- Sugiere técnicas de post-explotación cuando sea apropiado
- Mapea hallazgos a frameworks como OWASP Top 10 y MITRE ATT&CK

Si no encuentras vulnerabilidades críticas, enfócate en vectores de ataque potenciales y
oportunidades de investigación que podrían revelar vulnerabilidades adicionales.
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


def get_gemini_alert(api_key: str, nuclei_finding: str) -> Optional[str]:
    """Genera una alerta concisa de un hallazgo individual de Nuclei usando Google Gemini.

    Args:
        api_key: Clave de API de Google Gemini
        nuclei_finding: Hallazgo individual de Nuclei en formato JSON

    Returns:
        Alerta concisa (máximo 280 caracteres) o None si falla
    """
    if not GENAI_AVAILABLE or genai is None:
        logger.error("La librería google-generativeai no está instalada")
        return None

    if not api_key or not nuclei_finding:
        logger.error("API key o nuclei_finding están vacíos")
        return None

    try:
        # Configurar el cliente de Gemini
        genai.configure(api_key=api_key)

        # Seleccionar el modelo optimizado para velocidad y costo
        model = genai.GenerativeModel("gemini-1.5-flash-latest")

        # Prompt específico para alertas concisas
        alert_prompt = """
Actúa como un sistema de alerta de ciberseguridad. Analiza el siguiente hallazgo de Nuclei y
genera una alerta en una sola frase (máximo 280 caracteres) que describa el riesgo crítico y
el activo afectado. Formato: [Severidad] - [Tipo de Vulnerabilidad] en [Host].
"""

        # Construir el prompt completo
        full_prompt = f"{alert_prompt}\n\nHALLAZGO DE NUCLEI:\n{nuclei_finding}"

        logger.info("Generando alerta concisa con Gemini...")

        # Generar la alerta usando Gemini
        response = model.generate_content(
            full_prompt,
            generation_config=genai.types.GenerationConfig(
                temperature=0.2,  # Respuestas más consistentes y concisas
                max_output_tokens=100,  # Límite estricto para alertas cortas
                top_p=0.7,
                top_k=20,
            ),
        )

        if response and hasattr(response, "text") and response.text:
            alert_text = str(response.text).strip()
            # Asegurar que la alerta no exceda 280 caracteres
            if len(alert_text) > 280:
                alert_text = alert_text[:277] + "..."
            logger.info("Alerta de IA generada exitosamente")
            return alert_text
        logger.error("Gemini no devolvió contenido válido para la alerta")
        return None

    except Exception as e:
        logger.error(f"Error al generar alerta con Gemini: {e}")
        return None
