# === Ultra-BugBountyScanner Project Rules v2.1 ===

## 1. Python & Dependencies
- El proyecto usa Python 3.11+.
- Las dependencias de producción se gestionan en `requirements.txt`.
- Las dependencias de desarrollo y herramientas de calidad se gestionan y configuran a través de `pyproject.toml`.

## 2. Sistema de Calidad de Código (Dos Niveles)
- **Nivel 1 (Desarrollo Diario): `Ruff`**
  - `Ruff` es la única fuente de verdad para el linting y el formateo en tiempo real.
  - El formato de código sigue el estándar de `Black`, impuesto por `ruff format`.
  - Longitud de línea máxima: 120 caracteres.
  - Todas las importaciones deben ser ordenadas automáticamente por `ruff`.
- **Nivel 2 (Auditoría Profunda): `Pylint`**
  - `Pylint` se utiliza exclusivamente para auditorías de calidad de código más profundas, **no para estilo**.
  - Su configuración debe estar enfocada en detectar "code smells" que Ruff no cubre, principalmente la **lógica duplicada (`duplicate-code`)**.

## 3. Testing Framework
- Las pruebas unitarias se escriben con el módulo `unittest` de la librería estándar.
- Para la lógica compleja y la validación de datos, se debe usar `Hypothesis` para crear pruebas basadas en propiedades.
- El objetivo es alcanzar una cobertura de pruebas superior al 85% en las funciones lógicas clave.

## 4. Type Hinting & Static Analysis
- Todo el código nuevo **DEBE** incluir `type hints` completos.
- El código debe pasar el chequeo de `mypy` con la configuración estricta definida en `pyproject.toml` sin errores.

## 5. Security Standards
- Todo el código debe pasar un escaneo de `Bandit` sin vulnerabilidades de severidad media o alta.
- Está estrictamente prohibido hardcodear credenciales, API keys o cualquier tipo de secreto en el código. Deben gestionarse a través de variables de entorno (`.env`).
- Todas las entradas del usuario (argumentos de línea de comandos, etc.) deben ser tratadas como no confiables y sanitizadas si se usan para construir comandos de sistema.