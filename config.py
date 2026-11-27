"""
Configuración del nodo UPB-Chain (P0-7, P2-9).

Único lugar donde se leen las variables de entorno. ``Settings`` es un modelo de
``pydantic-settings`` inmutable y validado; ``load_settings()`` lo construye leyendo
el entorno y ``.env`` (las variables de entorno ganan al ``.env``). Un valor
inválido (puerto fuera de rango, dificultad negativa...) lanza ``ConfigError``
con un mensaje en español.
"""
import logging
from typing import Annotated, List

from pydantic import ValidationError, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

_NIVELES_LOG = ("CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG")


class ConfigError(ValueError):
    """Configuración inválida (mensaje en español, una línea por campo)."""


def _lista(valor):
    """``"a, b"`` -> ``["a", "b"]`` (las listas ya hechas pasan sin cambio)."""
    if isinstance(valor, str):
        return [p.strip() for p in valor.split(",") if p.strip()]
    return valor


class Settings(BaseSettings):
    # Los valores pasados por argumento ganan al entorno, y el entorno gana al .env.
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore", frozen=True)

    node_id: str = "node_1"
    node_host: str = "0.0.0.0"        # dirección de escucha P2P
    node_port: int = 8001             # puerto P2P (0 = efímero, útil en tests)
    api_port: int = 8000
    # Dirección que se anuncia a los pares (si vacía, se usa node_host).
    node_advertise_host: str = ""
    peers: Annotated[List[str], NoDecode] = []
    data_dir: str = "data/chain"      # aquí se guarda chain.db (P2-4)
    mining_difficulty: int = 16       # dificultad inicial en BITS (P2-5)
    # Arranque (P2-4): "fast" = verificación barata + foto de estado; "full" =
    # revalidar firmas y contratos desde el génesis. Ver docs/arquitectura.md.
    revalidate_on_start: str = "fast"
    # Cada cuántos bloques se guarda una foto del estado de los contratos (0 = nunca).
    snapshot_interval: int = 100
    # Anclaje público (idea 3): cada tantos bloques se sella el hash del bloque en los
    # calendarios de OpenTimestamps (0 = apagado). No es consenso: mejor esfuerzo.
    anchor_interval: int = 0
    # Quién ancla: auto = en pbft una sola réplica por bloque (rotando por índice), en pow todos
    # los nodos con ANCHOR_INTERVAL > 0; always = siempre; never = nunca (solo sirve lo que haya).
    anchor_role: str = "auto"
    anchor_calendars: Annotated[List[str], NoDecode] = [
        "https://a.pool.opentimestamps.org", "https://b.pool.opentimestamps.org"]
    log_level: str = "INFO"
    # Llave privada de la autoridad UPB (P0-6). Archivo local, ignorado por git.
    authority_key_file: str = "data/keys/authority.json"
    # URL pública base para los QR de verificación (P1-3). Vacía = la del request.
    public_base_url: str = ""
    # Dominio del did:web de la UPB (P2-3), p. ej. "upb.edu.bo". Vacío = el host de
    # PUBLIC_BASE_URL (o el del request). did:web exige servir /.well-known/did.json por HTTPS
    # en ese dominio; eso lo debe disponer el despliegue (proxy inverso) en la Pi.
    did_web_domain: str = ""
    # Llave de los endpoints de administración (P1-9). Vacía = solo peticiones locales.
    admin_api_key: str = ""
    # /metrics (P2-10): False = mismo control que los endpoints de administración;
    # True = abierto (solo para una red interna, p. ej. Prometheus dentro de docker compose).
    metrics_public: bool = False
    # Orígenes CORS permitidos. Vacía = solo el origen propio del nodo en localhost.
    cors_origins: Annotated[List[str], NoDecode] = []
    # Máximo de TX por minuto y emisor admitidas al mempool (P1-5). No es regla de consenso.
    tx_rate_limit: int = 100
    # Freno térmico LOCAL del minero (idea 5): "on"/"off". No es consenso: no cambia la
    # dificultad ni la validación, solo el ciclo de trabajo del hilo de minado.
    thermal_throttle: str = "off"
    # IA federada (idea 6): "on"/"off". Solo intercambia resúmenes estadísticos y banderas; no es
    # consenso. FEDERATED_K = nodos distintos que deben marcar la misma TX/emisor para alertar.
    federated_ai: str = "off"
    federated_k: int = 2
    thermal_soft_c: float = 70.0   # por debajo: velocidad completa
    thermal_hard_c: float = 80.0   # desde aquí: ciclo mínimo
    thermal_min_duty: float = 0.2

    # Tope del mempool y de TX pendientes por remitente (P1-5). Política local: al llenarse
    # se rechaza la TX nueva. Cubre también las TXs recibidas por P2P.
    mempool_max: int = 5000
    mempool_max_per_sender: int = 64
    # Consenso (P1-1): "pow" o "pbft". Es de TODA la red: un par con otro modo se rechaza.
    consensus: str = "pow"
    # PBFT: lista ordenada de réplicas {"replicas": [{"id", "address", "public_key"}]}
    # (el orden define el primario de cada vista) y la llave de firma de ESTA réplica.
    pbft_replicas_file: str = "pbft_replicas.json"
    pbft_key_file: str = "data/keys/pbft_replica.json"
    # Segundos sin progreso con trabajo pendiente antes de pedir cambio de vista.
    pbft_view_timeout: float = 5.0
    # Cada cuánto, como mínimo, el primario propone un bloque si hay TXs pendientes.
    pbft_batch_interval: float = 0.2

    # P2P con TLS mutuo (P2-6): "off" (por defecto) u "on" (recomendado en las Pi). Con "on" se
    # leen P2P_TLS_DIR/ca.crt, <NODE_ID>.crt y <NODE_ID>.key (ver scripts/crear_ca.py).
    p2p_tls: str = "off"
    p2p_tls_dir: str = "data/tls"
    # node_ids permitidos (CN del certificado). Vacía = en pbft los ids de las réplicas; en pow,
    # cualquier certificado de la CA. Sin TLS solo avisa (el node_id anunciado no está autenticado).
    p2p_allowlist: Annotated[List[str], NoDecode] = []

    @field_validator("peers", "cors_origins", "p2p_allowlist", "anchor_calendars", mode="before")
    @classmethod
    def _separar_comas(cls, v):
        return _lista(v)

    @field_validator("node_port", "api_port")
    @classmethod
    def _puerto(cls, v: int) -> int:
        if not 0 <= v <= 65535:
            raise ValueError("debe ser un puerto entre 0 y 65535")
        return v

    @field_validator("mining_difficulty")
    @classmethod
    def _dificultad(cls, v: int) -> int:
        if not 1 <= v <= 256:
            raise ValueError("debe estar entre 1 y 256 (bits de dificultad)")
        return v

    @field_validator("revalidate_on_start", mode="before")
    @classmethod
    def _arranque(cls, v):
        v = str(v).strip().lower()
        if v not in ("fast", "full"):
            raise ValueError("debe ser 'fast' o 'full'")
        return v

    @field_validator("anchor_role", mode="before")
    @classmethod
    def _rol_anclaje(cls, v):
        v = str(v).strip().lower()
        if v not in ("auto", "always", "never"):
            raise ValueError("debe ser 'auto', 'always' o 'never'")
        return v

    @field_validator("snapshot_interval", "anchor_interval")
    @classmethod
    def _intervalo(cls, v: int) -> int:
        if v < 0:
            raise ValueError("debe ser 0 o mayor")
        return v

    @field_validator("tx_rate_limit", "mempool_max", "mempool_max_per_sender")
    @classmethod
    def _limite(cls, v: int) -> int:
        if v < 1:
            raise ValueError("debe ser al menos 1")
        return v

    @field_validator("federated_ai", mode="before")
    @classmethod
    def _federated(cls, v):
        v = str(v).strip().lower()
        if v not in ("off", "on"):
            raise ValueError("debe ser 'off' o 'on'")
        return v

    @field_validator("federated_k")
    @classmethod
    def _federated_k(cls, v: int) -> int:
        if v < 1:
            raise ValueError("debe ser al menos 1")
        return v

    @field_validator("thermal_throttle", mode="before")
    @classmethod
    def _thermal(cls, v):
        v = str(v).strip().lower()
        if v not in ("off", "on"):
            raise ValueError("debe ser 'off' o 'on'")
        return v

    @field_validator("thermal_min_duty")
    @classmethod
    def _min_duty(cls, v: float) -> float:
        if not 0.0 < v <= 1.0:
            raise ValueError("debe estar en (0, 1]")
        return v

    @model_validator(mode="after")
    def _umbrales_termicos(self):
        if self.thermal_hard_c <= self.thermal_soft_c:
            raise ValueError("THERMAL_HARD_C debe ser mayor que THERMAL_SOFT_C")
        return self

    @field_validator("p2p_tls", mode="before")
    @classmethod
    def _p2p_tls(cls, v):
        v = str(v).strip().lower()
        if v not in ("off", "on"):
            raise ValueError("debe ser 'off' o 'on'")
        return v

    @field_validator("consensus", mode="before")
    @classmethod
    def _consenso(cls, v):
        v = str(v).strip().lower()
        if v not in ("pow", "pbft"):
            raise ValueError("debe ser 'pow' o 'pbft'")
        return v

    @field_validator("pbft_view_timeout", "pbft_batch_interval")
    @classmethod
    def _segundos(cls, v: float) -> float:
        if not v > 0:
            raise ValueError("debe ser un número de segundos mayor que 0")
        return v

    @field_validator("log_level", mode="before")
    @classmethod
    def _nivel(cls, v):
        v = str(v).strip().upper()
        if v not in _NIVELES_LOG:
            raise ValueError(f"debe ser uno de {', '.join(_NIVELES_LOG)}")
        return v

    @field_validator("node_id")
    @classmethod
    def _nodo(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("no puede estar vacío")
        return v

    @field_validator("public_base_url", "admin_api_key", "did_web_domain")
    @classmethod
    def _recortar(cls, v: str) -> str:
        return v.strip()


def _mensaje(err: dict) -> str:
    if err["type"].startswith("int_"):
        return "debe ser un número entero"
    if err["type"].startswith("float_"):
        return "debe ser un número"
    return err["msg"].removeprefix("Value error, ")


def build_settings(load_env_file: bool = True, **valores) -> Settings:
    """Construye ``Settings`` (entorno + ``.env`` opcional) con ``valores`` por encima.

    Convierte los errores de validación de pydantic en ``ConfigError`` en español.
    """
    try:
        return Settings(_env_file=".env" if load_env_file else None, **valores)
    except ValidationError as e:
        lineas = [f"  {'.'.join(str(p) for p in err['loc']).upper()}: {_mensaje(err)}"
                  for err in e.errors()]
        raise ConfigError("Configuración inválida:\n" + "\n".join(lineas)) from None


def load_settings(load_env_file: bool = True) -> Settings:
    """Lee la configuración del entorno (y de ``.env`` si existe)."""
    return build_settings(load_env_file)


def configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level, logging.INFO),
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
