"""
Configuración del nodo UPB-Chain (P0-7).

Único lugar donde se leen las variables de entorno. ``load_settings()`` carga
``.env`` (sin sobrescribir variables ya definidas en el entorno) y devuelve un
objeto inmutable con los valores ya convertidos.
"""
import logging
import os
from dataclasses import dataclass, field
from typing import List

from dotenv import load_dotenv


@dataclass(frozen=True)
class Settings:
    node_id: str = "node_1"
    node_host: str = "0.0.0.0"        # dirección de escucha P2P
    node_port: int = 8001             # puerto P2P
    api_port: int = 8000
    # Dirección que se anuncia a los pares (si vacía, se usa node_host).
    node_advertise_host: str = ""
    peers: List[str] = field(default_factory=list)
    data_dir: str = "data/chain"      # aquí se guarda chain.json
    mining_difficulty: int = 4
    log_level: str = "INFO"
    # Llave privada de la autoridad UPB (P0-6). Archivo local, ignorado por git.
    authority_key_file: str = "data/keys/authority.json"
    # URL pública base para los QR de verificación (P1-3). Vacía = la del request.
    public_base_url: str = ""


def load_settings(load_env_file: bool = True) -> Settings:
    """Lee la configuración del entorno (y de ``.env`` si existe)."""
    if load_env_file:
        load_dotenv(override=False, encoding="utf-8")
    env = os.environ.get
    peers = [p.strip() for p in env("PEERS", "").split(",") if p.strip()]
    return Settings(
        node_id=env("NODE_ID", "node_1"),
        node_host=env("NODE_HOST", "0.0.0.0"),
        node_port=int(env("NODE_PORT", "8001")),
        api_port=int(env("API_PORT", "8000")),
        node_advertise_host=env("NODE_ADVERTISE_HOST", ""),
        peers=peers,
        data_dir=env("DATA_DIR", "data/chain"),
        mining_difficulty=int(env("MINING_DIFFICULTY", "4")),
        log_level=env("LOG_LEVEL", "INFO").upper(),
        authority_key_file=env("AUTHORITY_KEY_FILE", "data/keys/authority.json"),
        public_base_url=env("PUBLIC_BASE_URL", "").strip(),
    )


def configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level, logging.INFO),
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
