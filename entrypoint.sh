#!/bin/bash
# ============================================================================
# Ultra-BugBountyScanner v2.1 - Entrypoint Dual Inteligente
# ============================================================================
# Autor: danielxxomg2
# Descripción: Punto de entrada que detecta automáticamente el modo de operación
#              - Con argumentos: Modo automático (CI/CD)
#              - Sin argumentos: Modo interactivo (análisis manual)
# ============================================================================

set -euo pipefail  # Modo estricto para seguridad

# Función para sanitizar argumentos de entrada
sanitize_args() {
    local args=("$@")
    local sanitized_args=()
    
    for arg in "${args[@]}"; do
        # Verificar longitud máxima
        if [ ${#arg} -gt 256 ]; then
            echo "❌ SECURITY: Argument too long (${#arg} chars), max 256 allowed" >&2
            return 1
        fi
        
        # Verificar patrones peligrosos
        if [[ "$arg" =~ [\;\&\|\`\$\(\)\{\}\[\]\<\>] ]]; then
            echo "❌ SECURITY: Dangerous characters detected in argument: $arg" >&2
            return 1
        fi
        
        # Verificar path traversal
        if [[ "$arg" =~ \.\./|\\\\ ]]; then
            echo "❌ SECURITY: Path traversal attempt detected: $arg" >&2
            return 1
        fi
        
        # Verificar protocolos peligrosos
        if [[ "$arg" =~ ^(file|javascript|data|vbscript): ]]; then
            echo "❌ SECURITY: Dangerous protocol detected: $arg" >&2
            return 1
        fi
        
        # Remover caracteres de control y null bytes
        sanitized_arg=$(echo "$arg" | tr -d '\000-\010\013\014\016-\037\177')
        
        # Trim whitespace
        sanitized_arg=$(echo "$sanitized_arg" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        
        # Solo agregar si no está vacío después de sanitización
        if [ -n "$sanitized_arg" ]; then
            sanitized_args+=("$sanitized_arg")
        fi
    done
    
    echo "${sanitized_args[@]}"
}

# Función para mostrar banner de bienvenida
show_banner() {
    echo "🚀 Ultra-BugBountyScanner v2.1 - Modo Interactivo"
    echo "📋 Herramientas disponibles:"
    echo "   • fastfetch - Información del sistema"
    echo "   • bat - Visualizador de archivos mejorado"
    echo "   • micro - Editor de texto ligero"
    echo "   • python3 scanner_main.py - Scanner principal"
    echo "───────────────────────────────────────────────────"
    echo "💡 Ejemplo de uso: python3 scanner_main.py -d example.com"
    echo "📚 Ayuda: python3 scanner_main.py --help"
    echo "───────────────────────────────────────────────────"
}

# Función principal
main() {
    # Verificar si se proporcionaron argumentos
    if [ "$#" -gt 0 ]; then
        echo "🔄 Ultra-BugBountyScanner v2.1 - Modo Automático"
        echo "📊 Iniciando escaneo con argumentos: $*"
        echo "───────────────────────────────────────────────────"
        
        # Sanitizar argumentos de entrada por seguridad
        echo "🔐 Validando argumentos de entrada..."
        if ! sanitized_args=($(sanitize_args "$@")); then
            echo "❌ SECURITY: Argument validation failed, aborting execution" >&2
            echo "💡 Tip: Check your arguments for dangerous characters or excessive length" >&2
            exit 1
        fi
        
        echo "✅ Argumentos validados exitosamente"
        
        # Ejecutar scanner con argumentos sanitizados
        exec python3 scanner_main.py "${sanitized_args[@]}"
    else
        echo "🎯 Detectado modo interactivo - Sin argumentos proporcionados"
        show_banner
        
        # Iniciar sesión bash interactiva con herramientas QoL
        exec /bin/bash
    fi
}

# Manejo de errores
trap 'echo "❌ Error en entrypoint.sh - Línea $LINENO"' ERR

# Ejecutar función principal con todos los argumentos
main "$@"