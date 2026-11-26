#!/bin/bash
# ──────────────────────────────────────────────────────────────────
# UPB-Chain — Setup para Raspberry Pi 5
# Ejecutar con: sudo bash setup_rpi.sh [node_id] [api_port] [p2p_port]
# Ejemplo nodo 1: sudo bash setup_rpi.sh node_1 8000 8001
# Ejemplo nodo 2: sudo bash setup_rpi.sh node_2 8002 8003
# ──────────────────────────────────────────────────────────────────
set -e

NODE_ID=${1:-node_1}
API_PORT=${2:-8000}
P2P_PORT=${3:-8001}
PROJECT_DIR="/home/pi/upb-chain"

echo "════════════════════════════════════════════"
echo "  UPB-Chain — Configuración de Nodo RPi 5"
echo "  Nodo: $NODE_ID | API: $API_PORT | P2P: $P2P_PORT"
echo "════════════════════════════════════════════"

# ── 1. Sistema base ───────────────────────────────────────────────
echo "[1/7] Actualizando sistema..."
apt-get update -qq && apt-get upgrade -y -qq

echo "[1/7] Instalando dependencias del sistema..."
apt-get install -y -qq \
    python3 python3-pip python3-venv \
    git curl wget build-essential \
    libssl-dev libffi-dev libopenblas-dev \
    htop iotop net-tools \
    ufw fail2ban

# ── 2. Clonar / copiar proyecto ───────────────────────────────────
echo "[2/7] Configurando directorio del proyecto..."
# Se copia el código sin venv, .git, data, .env, cachés ni .claude (tar viene en toda Raspberry Pi OS).
# Si ya existía una instalación, el código se actualiza y .env/data/venv no se tocan.
mkdir -p "$PROJECT_DIR"
tar --exclude=./venv --exclude=./.git --exclude=./data --exclude=./.env \
    --exclude=./.claude --exclude=__pycache__ --exclude=.pytest_cache --exclude='*.pyc' \
    -cf - . | tar -xf - -C "$PROJECT_DIR"
cd "$PROJECT_DIR"

# ── 3. Entorno virtual Python ─────────────────────────────────────
echo "[3/7] Creando entorno virtual Python..."
python3 -m venv venv
source venv/bin/activate

pip install --upgrade pip -q
pip install -r requirements.txt -q

# ── 4. Configurar variables de entorno ───────────────────────────
echo "[4/7] Configurando entorno..."
if [ -f .env ]; then
    echo "  .env ya existe: no se modifica (conserva ADMIN_API_KEY, PEERS, etc.)"
else
cat > .env << EOF
NODE_ID=$NODE_ID
NODE_HOST=0.0.0.0
NODE_PORT=$P2P_PORT
API_PORT=$API_PORT
DATA_DIR=/home/pi/upb-chain/data
LOG_LEVEL=INFO
EOF
fi

# El script corre como root pero el servicio corre como "pi": sin esto chain.db y las llaves
# (data/) no se pueden escribir y el nodo muere al arrancar.
mkdir -p "$PROJECT_DIR/data"
chown -R pi:pi "$PROJECT_DIR"

# ── 5. Servicio systemd ──────────────────────────────────────────
echo "[5/7] Creando servicio systemd..."
cat > /etc/systemd/system/upbchain.service << EOF
[Unit]
Description=UPB-Chain Blockchain Node ($NODE_ID)
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=pi
WorkingDirectory=$PROJECT_DIR
EnvironmentFile=$PROJECT_DIR/.env
ExecStart=$PROJECT_DIR/venv/bin/uvicorn api.app:app --host 0.0.0.0 --port $API_PORT --workers 1
Restart=on-failure
RestartSec=5s
StandardOutput=journal
StandardError=journal
SyslogIdentifier=upbchain-$NODE_ID

[Install]
WantedBy=multi-user.target
EOF

# Un solo worker por nodo: varios procesos = varias cadenas y choque en el puerto P2P.
systemctl daemon-reload
systemctl enable upbchain
systemctl start upbchain

# ── 6. Firewall ───────────────────────────────────────────────────
echo "[6/7] Configurando firewall..."
ufw allow ssh
ufw allow "$API_PORT/tcp" comment "UPB-Chain API"
ufw allow "$P2P_PORT/tcp" comment "UPB-Chain P2P"
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
    echo "✗ El nodo no respondió en /health tras 60 s. Ver logs: journalctl -u upbchain -f"
    exit 1
fi

echo ""
echo "════════════════════════════════════════════"
echo "  Instalación completada para $NODE_ID"
echo "════════════════════════════════════════════"
