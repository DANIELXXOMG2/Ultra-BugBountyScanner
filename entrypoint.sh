#!/bin/bash

# ============================================================================
# Ultra-BugBountyScanner v2.1 - Entrypoint Inteligente
# Author: danielxxomg2
# ============================================================================

set -euo pipefail

# Función para mostrar el mensaje de bienvenida
show_welcome() {
    echo ""
    echo "🚀 ===================================================== 🚀"
    echo "    Ultra-BugBountyScanner v2.1 - Modo Interactivo"
    echo "    Author: danielxxomg2"
    echo "🚀 ===================================================== 🚀"
    echo ""
    echo "📋 Comandos disponibles:"
    echo "   • python3 scanner_main.py --help    - Ver ayuda del scanner"
    echo "   • python3 scanner_main.py -d <domain> - Escanear un dominio"
    echo "   • sudo apt update && sudo apt install <paquete> - Instalar paquetes adicionales"
    echo "   • exit                               - Salir del contenedor"
    echo ""
    echo "🔧 Herramientas instaladas:"
    echo "   • subfinder, httpx, nuclei, naabu, katana, ffuf, waybackurls"
    echo "   • nmap, masscan, neofetch, bat, micro"
    echo "   • trufflehog, s3scanner, arjun, GitDorker"
    echo ""
    echo "📁 Directorio de trabajo: /app"
    echo "📁 Resultados se guardan en: /app/output"
    echo ""
    echo "🔐 Permisos administrativos:"
    echo "   • Usuario 'scanner' tiene acceso sudo sin contraseña"
    echo "   • Puedes instalar paquetes adicionales con 'sudo apt install <paquete>'"
    echo "   • Ejemplo: sudo apt install vim curl wget"
    echo ""
    echo "💡 Tip: Usa 'neofetch' para ver información del sistema"
    echo "💡 Tip: Usa 'bat' en lugar de 'cat' para resaltado de sintaxis"
    echo "💡 Tip: Usa 'sudo -l' para ver tus permisos sudo"
    echo ""
}

# Lógica principal del entrypoint
if [ "$#" -gt 0 ]; then
    # Si se pasan argumentos, ejecutar el scanner en modo automático
    echo "🚀 Iniciando Ultra-BugBountyScanner en modo automático..."
    exec python3 scanner_main.py "$@"
else
    # Si no se pasan argumentos, mostrar bienvenida y ejecutar bash interactivo
    show_welcome
    echo "🐚 Iniciando shell interactivo..."
    echo ""
    exec bash
fi