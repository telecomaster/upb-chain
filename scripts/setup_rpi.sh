#!/bin/bash
# ──────────────────────────────────────────────────────────────────
# UPB-Chain — Setup para Raspberry Pi 5
# Ejecutar con: sudo bash scripts/setup_rpi.sh [node_id] [api_port] [p2p_port]
# Una réplica = una unidad systemd (upbchain-<node_id>) con su propio EnvironmentFile
# (<proyecto>/nodes/<node_id>.env) y su propio DATA_DIR. Para 2 réplicas por Pi se ejecuta
# una vez por réplica (guía completa en docs/despliegue_rpi.md):
#   sudo bash scripts/setup_rpi.sh node_1 8000 8001
#   sudo SKIP_APT=1 bash scripts/setup_rpi.sh node_2 8010 8011
# Variables opcionales:
#   UPB_USER    usuario que ejecuta el servicio (por defecto SUDO_USER; si no, "pi")
#   UPB_DIR     directorio del proyecto (por defecto /home/<usuario>/upb-chain)
#   SKIP_APT=1  no ejecutar apt update/upgrade/install (2.ª réplica en la misma Pi)
# ──────────────────────────────────────────────────────────────────
set -e

NODE_ID=${1:-node_1}
API_PORT=${2:-8000}
P2P_PORT=${3:-8001}
# El usuario no siempre es "pi": Raspberry Pi Imager deja elegir el nombre.
USUARIO="${UPB_USER:-${SUDO_USER:-pi}}"
PROJECT_DIR="${UPB_DIR:-/home/$USUARIO/upb-chain}"
SERVICIO="upbchain-$NODE_ID"
ENV_FILE="$PROJECT_DIR/nodes/$NODE_ID.env"

echo "════════════════════════════════════════════"
echo "  UPB-Chain — Configuración de Nodo RPi 5"
echo "  Nodo: $NODE_ID | API: $API_PORT | P2P: $P2P_PORT | usuario: $USUARIO"
echo "════════════════════════════════════════════"

# ── 1. Sistema base ───────────────────────────────────────────────
if [ "${SKIP_APT:-0}" = 1 ]; then
    echo "[1/7] SKIP_APT=1: se omiten las dependencias del sistema"
else
    echo "[1/7] Actualizando sistema..."
    apt-get update -qq && apt-get upgrade -y -qq

    echo "[1/7] Instalando dependencias del sistema..."
    apt-get install -y -qq \
        python3 python3-pip python3-venv \
        git curl wget build-essential \
        libssl-dev libffi-dev libopenblas-dev \
        htop iotop net-tools \
        ufw fail2ban
fi

# ── 2. Clonar / copiar proyecto ───────────────────────────────────
echo "[2/7] Configurando directorio del proyecto..."
# Si el script ya corre dentro de $PROJECT_DIR (clon directo) no hay nada que copiar. Si no, se
# copia el código sin venv, .git, data, .env, nodes, cachés ni .claude (tar viene en toda
# Raspberry Pi OS). En una reinstalación el código se actualiza y .env/nodes/data/venv no se tocan.
mkdir -p "$PROJECT_DIR"
if [ "$(pwd -P)" = "$(cd "$PROJECT_DIR" && pwd -P)" ]; then
    echo "  el proyecto ya está en $PROJECT_DIR: no se copia"
else
    tar --exclude=./venv --exclude=./.git --exclude=./data --exclude=./.env \
        --exclude=./nodes --exclude=./.claude --exclude=__pycache__ \
        --exclude=.pytest_cache --exclude='*.pyc' \
        -cf - . | tar -xf - -C "$PROJECT_DIR"
fi
cd "$PROJECT_DIR"

# ── 3. Entorno virtual Python ─────────────────────────────────────
echo "[3/7] Creando entorno virtual Python..."
[ -x venv/bin/python ] || python3 -m venv venv
source venv/bin/activate

pip install --upgrade pip -q
pip install -r requirements.txt -q

# ── 4. Configurar variables de entorno ───────────────────────────
echo "[4/7] Configurando entorno..."
mkdir -p "$PROJECT_DIR/nodes"
if [ -f "$ENV_FILE" ]; then
    echo "  $ENV_FILE ya existe: no se modifica (conserva ADMIN_API_KEY, PBFT_*, TLS...)"
else
cat > "$ENV_FILE" << EOF
NODE_ID=$NODE_ID
NODE_HOST=0.0.0.0
NODE_PORT=$P2P_PORT
API_PORT=$API_PORT
DATA_DIR=$PROJECT_DIR/data/$NODE_ID
LOG_LEVEL=INFO
EOF
    echo "  creado $ENV_FILE mínimo (sin PBFT/TLS/ADMIN_API_KEY: ver docs/despliegue_rpi.md)"
fi
chmod 600 "$ENV_FILE"   # puede contener ADMIN_API_KEY

# El script corre como root pero el servicio corre como $USUARIO: sin esto chain.db y las llaves
# (data/) no se pueden escribir y el nodo muere al arrancar.
mkdir -p "$PROJECT_DIR/data"
chown -R $USUARIO:$USUARIO "$PROJECT_DIR"

# ── 5. Servicio systemd ──────────────────────────────────────────
echo "[5/7] Creando servicio systemd $SERVICIO..."
cat > /etc/systemd/system/$SERVICIO.service << EOF
[Unit]
Description=UPB-Chain Blockchain Node ($NODE_ID)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$USUARIO
WorkingDirectory=$PROJECT_DIR
EnvironmentFile=$ENV_FILE
ExecStart=$PROJECT_DIR/venv/bin/uvicorn api.app:app --host 0.0.0.0 --port $API_PORT --workers 1
Restart=on-failure
RestartSec=5s
StandardOutput=journal
StandardError=journal
SyslogIdentifier=$SERVICIO

[Install]
WantedBy=multi-user.target
EOF

# Un solo worker por nodo: varios procesos = varias cadenas y choque en el puerto P2P.
systemctl daemon-reload
systemctl enable $SERVICIO
systemctl restart $SERVICIO

# ── 6. Firewall ───────────────────────────────────────────────────
echo "[6/7] Configurando firewall..."
ufw allow ssh
ufw allow "$API_PORT/tcp" comment "UPB-Chain API $NODE_ID"
ufw allow "$P2P_PORT/tcp" comment "UPB-Chain P2P $NODE_ID"
ufw --force enable

# ── 7. Verificación ──────────────────────────────────────────────
echo "[7/7] Verificando instalación..."
# El primer arranque en una Pi puede tardar (revalidación de la cadena): reintentar hasta 60 s.
SALUD=0
for _ in $(seq 1 30); do
    if curl -s "http://localhost:$API_PORT/health" | grep -q "ok"; then SALUD=1; break; fi
    sleep 2
done
if [ "$SALUD" = 1 ]; then
    echo "✓ UPB-Chain iniciado correctamente"
    echo "  API: http://$(hostname -I | awk '{print $1}'):$API_PORT"
    echo "  Dashboard: http://$(hostname -I | awk '{print $1}'):$API_PORT/"
    echo "  Docs: http://$(hostname -I | awk '{print $1}'):$API_PORT/docs"
else
    echo "✗ El nodo no respondió en /health tras 60 s. Ver logs: journalctl -u $SERVICIO -f"
    exit 1
fi

echo ""
echo "════════════════════════════════════════════"
echo "  Instalación completada para $NODE_ID"
echo "════════════════════════════════════════════"
