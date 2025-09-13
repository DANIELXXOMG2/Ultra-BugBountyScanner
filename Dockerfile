# ============================================================================
# Stage 1: Build Environment - Instala herramientas y dependencias
# ============================================================================
FROM debian:bookworm-slim AS builder

LABEL maintainer="danielxxomg2" \
      description="Ultra-BugBountyScanner - Build Environment"

# Variables de entorno para optimización y configuración
ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    GO_VERSION=1.24.0 \
    # Definimos la ruta del venv para usarla en múltiples lugares
    VENV_PATH=/opt/venv \
    PATH=/usr/local/go/bin:/root/go/bin:$PATH

# Actualizamos la variable PATH para incluir el venv
ENV PATH="$VENV_PATH/bin:$PATH"
ENV PYTHONDONTWRITEBYTECODE=1

# Instala paquetes esenciales del sistema, Go y herramientas en una sola capa optimizada
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl wget git unzip build-essential \
    dnsutils nmap masscan jq parallel python3 python3-pip python3-venv \
    libpcap-dev \
    && curl -fsSL https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz | tar -xzC /usr/local \
    && go version \
    && go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
    && go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest \
    && go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
    && go install -v github.com/projectdiscovery/katana/cmd/katana@latest \
    && go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest \
    && go install -v github.com/ffuf/ffuf@latest \
    && go install -v github.com/tomnomnom/waybackurls@latest \
    && python3 -m venv $VENV_PATH \
    && rm -rf /var/lib/apt/lists/*

# Instala dependencias de Python en el entorno virtual
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ============================================================================
# Stage 2: Runtime Environment - Imagen de producción mínima
# ============================================================================
FROM debian:bookworm-slim AS runtime

LABEL maintainer="danielxxomg2" \
      description="Ultra-BugBountyScanner - Runtime"

# Variables de entorno para ejecución
ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    VENV_PATH=/opt/venv \
    # Importante: El PATH en runtime también debe apuntar al venv
    PATH="/opt/venv/bin:/root/go/bin:/usr/local/bin:$PATH"

# Instala dependencias de ejecución y herramientas de calidad de vida
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl dnsutils nmap masscan jq parallel python3 libpcap0.8 \
    fastfetch bat micro \
    && rm -rf /var/lib/apt/lists/*

# Copia los binarios de Go y el entorno virtual completo del builder
COPY --from=builder /root/go/bin/* /usr/local/bin/
COPY --from=builder $VENV_PATH $VENV_PATH

# Establece el directorio de trabajo
WORKDIR /app

# Copia los scripts y la configuración de la aplicación
COPY . .

# Crea el usuario no-root, configura .bashrc y asigna permisos
RUN useradd -m -s /bin/bash scanner && \
    mkdir -p /app/output && \
    echo "alias cat='bat'" >> /home/scanner/.bashrc && \
    echo "alias ll='ls -alF'" >> /home/scanner/.bashrc && \
    echo "# Ejecutar fastfetch al iniciar sesión interactiva" >> /home/scanner/.bashrc && \
    echo "if [[ \$- == *i* ]]; then fastfetch; fi" >> /home/scanner/.bashrc && \
    chown -R scanner:scanner /app && \
    chown scanner:scanner /home/scanner/.bashrc

# Cambia al usuario no-root
USER scanner

# Punto de entrada inteligente que maneja modo automático e interactivo
ENTRYPOINT ["./entrypoint.sh"]