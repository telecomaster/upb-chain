"""
Laboratorio de ataques EN VIVO (Idea 1 del ROADMAP).

A diferencia de ``simulator.py`` y ``eclipse.py`` (modelos matemáticos), aquí un nodo
malicioso REAL ataca a nodos honestos REALES, todos en el mismo proceso y por sockets
reales en loopback (127.0.0.1):

- Los nodos honestos son nodos completos construidos con ``api.app.build_node`` (la misma
  función que usa la API): cadena con contratos, P2P, monitor de seguridad y, en pbft,
  réplica PBFT con su transporte. Se arrancan igual que en el ``lifespan`` de la app.
- El atacante es un ``NodoMalicioso``: subclase de ``P2PNode`` con una cadena ``Blockchain``
  real. Sus conductas maliciosas están marcadas y solo cambian lo que hace SU nodo
  (retener bloques, anunciar una cadena privada, mandar mensajes distintos a pares
  distintos, firmar votos o certificados falsos). Nunca se toca ni se "parcha" el código
  de consenso de los nodos honestos: si el ataque falla es porque sus reglas lo rechazan.

Escenarios (cada uno devuelve un dict con ``narrativa`` en español y datos medidos):

1. ``doble_gasto``: el atacante paga al comercio (TOKEN_TRANSFER confirmada en el bloque k)
   y en secreto mina una bifurcación desde k-1 que gasta los mismos fondos en un cómplice.
   - pow: si la bifurcación privada llega a tener más trabajo, la libera; los honestos
     hacen ``replace_chain`` (reorg) y el pago del comercio desaparece.
   - pbft: el atacante controla UNA réplica real (r3, f = 1). Su bifurcación necesita
     certificados de commit (2f+1 = 3 firmas); solo tiene 1 firma verdadera, falsifica las
     otras y los honestos la rechazan: los bloques certificados nunca se reemplazan.
2. ``reorg`` (solo pow): barrido de la cuota de hash del atacante con varias corridas
   pequeñas; tasa de éxito y profundidad del reorg medidas EN PROCESO (portátil).
3. ``sybil``: el atacante fabrica muchas identidades. Con TLS mutuo + lista blanca (P2-6)
   se cortan en el apretón de manos (alerta UNKNOWN_PEER). Sin TLS la lista blanca solo
   avisa: los Sybil quedan conectados. En pbft, sus votos se descartan (firmante desconocido).
4. ``equivocacion``: en pbft, el primario (r0, malicioso) firma dos PRE-PREPARE distintos
   para la misma altura → alerta PBFT_EQUIVOCATION, cambio de vista y como máximo un
   bloque confirmado. En pow no existe la noción: dos bloques válidos a la misma altura son
   una bifurcación que se resuelve con el siguiente bloque (reorg de 1).

Cómo se emula el "51 %" en pow
------------------------------
No hay hardware distinto: todos los nodos comparten el intérprete. La carrera avanza en
rondas y en cada ronda se reparten ``INTENTOS_POR_RONDA`` = 100 intentos de hash REALES
(SHA-256 del bloque con la dificultad que exige la regla de consenso, la misma para todos):
``cuota`` intentos son del atacante y ``100 - cuota`` del minero honesto. Es decir, la cuota
es la fracción del tiempo de CPU dedicado a minar, no una dificultad más fácil (un bloque
con menos bits sería inválido para los honestos). Si una cadena cruza una época de
``difficulty_window`` bloques, su dificultad se reajusta con la regla normal; por eso la
carrera compara trabajo acumulado y no altura. El atacante abandona si queda
``max_atraso`` bloques atrás (o tras ``max_rondas``). La semilla fija los nonces iniciales; las firmas ECDSA y las marcas de
tiempo no son deterministas, así que dos corridas con la misma semilla pueden diferir.

Seguridad: SOLO para el laboratorio. Todo escucha en 127.0.0.1 y vive en un directorio
temporal que se borra al terminar; nunca apuntar esto a nodos ajenos.
"""
import contextlib
import json
import logging
import random
import tempfile
import threading
import time
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from blockchain.consensus.pbft import COMMIT, PRE_PREPARE, ReplicaSet, sign_message
from blockchain.core.block import Block, BlockHeader, hash_meets_bits
from blockchain.core.chain import Blockchain
from blockchain.core.transaction import (
    Transaction, TransactionType, create_mint_transaction, create_transfer_transaction,
)
from blockchain.core.wallet import Wallet
from blockchain.network.node import MSG_BLOCK, MSG_CHAIN, MSG_GET_CHAIN, P2PNode

logger = logging.getLogger("upb_chain.laboratorio")

HOST = "127.0.0.1"            # el laboratorio nunca sale del loopback
INTENTOS_POR_RONDA = 100      # intentos de hash repartidos en cada ronda de la carrera PoW
ESCENARIOS = ("doble_gasto", "reorg", "sybil", "equivocacion")


# ── Nodo malicioso ────────────────────────────────────────────────────────────

class NodoMalicioso(P2PNode):
    """Nodo P2P REAL (misma clase base que los honestos) con conductas maliciosas explícitas.

    Lo único que cambia respecto de ``P2PNode`` está marcado con ``MALICIOSO`` y afecta solo
    a este nodo:
      - Retiene su cadena privada (otra ``Blockchain``, fuera de la red) y, al ``liberar``,
        la anuncia como propia: ``_status`` y ``GET_CHAIN`` responden con ella.
      - Envía mensajes elegidos a pares elegidos (``enviar_bloque_a``, ``enviar_pbft_a``):
        así puede decir cosas distintas a nodos distintos (equivocación).
    Los mensajes PBFT que recibe se ignoran (no corre una réplica honesta).
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._privada: Optional[Tuple[List[dict], Dict[int, dict]]] = None

    # MALICIOSO: anuncia una cadena que mantuvo en secreto.
    def liberar(self, bloques: List[dict], certificados: Optional[Dict[int, dict]] = None) -> int:
        """Publica la cadena privada: desde ahora la sirve y difunde su punta. Devuelve envíos."""
        self._privada = (list(bloques), dict(certificados or {}))
        punta = bloques[-1]
        cert = (certificados or {}).get(punta["header"]["index"])
        return self.broadcast_block(punta, cert)

    def _status(self) -> dict:
        estado = super()._status()
        if self._privada is not None:            # MALICIOSO: estado de la cadena privada
            bloques = [Block.from_dict(b) for b in self._privada[0]]
            estado.update(height=len(bloques) - 1, work=Blockchain.cumulative_work(bloques),
                          tip=bloques[-1].hash)
        return estado

    def _dispatch(self, message: dict, conn) -> None:
        if message.get("type") == MSG_GET_CHAIN and self._privada is not None:
            if not self._mark_seen(message.get("id", "")):
                return
            bloques, certs = self._privada     # MALICIOSO: sirve la cadena privada
            respuesta = {"type": MSG_CHAIN, "data": bloques}
            if certs:
                respuesta["certificates"] = {str(h): c for h, c in certs.items()}
            self._send_framed(conn, respuesta)
            return
        super()._dispatch(message, conn)

    # MALICIOSO: entrega dirigida (no gossip) para contar historias distintas a cada par.
    def enviar_bloque_a(self, puerto: int, bloque: dict, certificado: Optional[dict] = None) -> None:
        mensaje = self._new_message(MSG_BLOCK, bloque)
        mensaje["origin"] = {"host": self.advertise_host, "port": self.port, "node_id": self.node_id}
        if certificado is not None:
            mensaje["certificate"] = certificado
        self._request(HOST, puerto, mensaje, expect_reply=False)

    def enviar_pbft_a(self, puerto: int, mensaje_pbft: dict) -> None:
        self.send_pbft(HOST, puerto, mensaje_pbft)


# ── Utilidades ────────────────────────────────────────────────────────────────

def _esperar(cond: Callable[[], bool], limite: float = 10.0, paso: float = 0.02) -> bool:
    fin = time.time() + limite
    while time.time() < fin:
        if cond():
            return True
        time.sleep(paso)
    return cond()


def _puertos_libres(n: int) -> List[int]:
    import socket
    socks = []
    for _ in range(n):
        s = socket.socket()
        s.bind((HOST, 0))
        socks.append(s)
    puertos = [s.getsockname()[1] for s in socks]
    for s in socks:
        s.close()
    return puertos


def _intentar(bloque: Block, intentos: int) -> bool:
    """``intentos`` hashes reales sobre ``bloque`` (avanza el nonce). True si cumple la dificultad."""
    bits = bloque.header.difficulty
    for _ in range(intentos):
        h = bloque.compute_hash()
        if hash_meets_bits(h, bits):
            bloque.hash = h
            return True
        bloque.header.nonce += 1
    return False


def _minar(bloque: Block) -> Block:
    while not _intentar(bloque, 10_000):
        pass
    return bloque


def _publicar(node, bloque: Block) -> None:
    """Un nodo honesto agrega su bloque minado y lo difunde (como ``POST /blocks/mine``)."""
    ok, motivo = node.blockchain.add_block(bloque)
    if not ok:
        raise RuntimeError(f"el bloque honesto fue rechazado: {motivo}")
    node.announce_block(bloque.to_dict())
    node.p2p.broadcast_block(bloque.to_dict())


def _confirmaciones(bc: Blockchain, tx_id: str) -> int:
    tx = bc.get_transaction(tx_id)
    return 0 if tx is None else bc.height - tx["block"] + 1


def _alertas(node, tipos: Optional[Tuple[str, ...]] = None) -> List[dict]:
    return [{"nodo": node.settings.node_id, "tipo": a["event_type"],
             "nivel": getattr(a["level"], "value", a["level"]), "mensaje": a["message"],
             "datos": a.get("metadata", {})}
            for a in node.security_monitor.get_alerts(limit=500)
            if tipos is None or a["event_type"] in tipos]


def _bloque_sin_trabajo(previo: Block, txs: List[dict], node_id: str) -> Block:
    """Bloque con la forma de PBFT (dificultad 0, nonce 0) encima de ``previo``."""
    header = BlockHeader(index=previo.header.index + 1,
                         timestamp=max(time.time(), previo.header.timestamp + 0.001),
                         previous_hash=previo.hash, merkle_root=Block.compute_merkle_root(txs),
                         nonce=0, difficulty=0, node_id=node_id)
    return Block(header=header, transactions=txs)


def _certificado_falso(bloque: Block, llave: str, firmantes: List[str]) -> dict:
    """MALICIOSO: COMMIT a nombre de ``firmantes``, TODOS firmados con la única llave del atacante."""
    h = bloque.header.index
    commits = [sign_message({"type": COMMIT, "replica": rid, "view": 0, "seq": h,
                             "digest": bloque.hash}, llave) for rid in firmantes]
    return {"view": 0, "seq": h, "digest": bloque.hash, "commits": commits}


# ── Montaje de la red del laboratorio ─────────────────────────────────────────

class _Laboratorio:
    """Directorio temporal + nodos honestos y maliciosos; al salir los detiene a todos."""

    def __init__(self, nombre: str):
        self._tmp = tempfile.TemporaryDirectory(prefix=f"lab-{nombre}-", ignore_cleanup_errors=True)
        self.dir = Path(self._tmp.name)
        self.autoridad = Wallet.generate()        # autoridad de prueba: firma TOKEN_MINT
        self.honestos: List = []
        self.maliciosos: List[NodoMalicioso] = []
        self.cadenas: List[Blockchain] = []

    def __enter__(self) -> "_Laboratorio":
        return self

    def __exit__(self, *exc) -> None:
        def parar_honesto(node):
            node.mining_stop.set()
            if node.pbft is not None:
                node.pbft.stop()
                node.pbft_transport.stop()
            node.p2p.stop()
        hilos = [threading.Thread(target=parar_honesto, args=(n,)) for n in self.honestos]
        hilos += [threading.Thread(target=m.stop) for m in self.maliciosos]
        for t in hilos:
            t.start()
        for t in hilos:
            t.join(timeout=5)
        for bc in [n.blockchain for n in self.honestos] + self.cadenas:
            with contextlib.suppress(Exception):
                bc.close()
        self._tmp.cleanup()

    # Configuración ───────────────────────────────────────────────────────────

    def _ajustes(self, nid: str, consenso: str, bits: int, puerto: int, **extra):
        from config import build_settings
        valores = dict(node_id=nid, node_host=HOST, node_advertise_host=HOST, node_port=puerto,
                       data_dir=str(self.dir / nid), mining_difficulty=bits, consensus=consenso,
                       authority_key_file=str(self.dir / "sin_llave_de_autoridad.json"),
                       log_level="WARNING", tx_rate_limit=10_000, peers=[], p2p_tls="off",
                       p2p_allowlist=[], pbft_view_timeout=1.0, pbft_batch_interval=0.05)
        valores.update(extra)
        return build_settings(False, **valores)

    def lista_pbft(self, ids: List[str]) -> Tuple[Path, ReplicaSet, Dict[str, Wallet], Dict[str, int]]:
        """Lista de réplicas (archivo), sus llaves y puertos P2P reservados."""
        puertos = dict(zip(ids, _puertos_libres(len(ids))))
        llaves = {rid: Wallet.generate() for rid in ids}
        items = [{"id": rid, "address": f"{HOST}:{puertos[rid]}",
                  "public_key": llaves[rid].public_key_hex} for rid in ids]
        ruta = self.dir / "pbft_replicas.json"
        with open(ruta, "w", encoding="utf-8") as f:
            json.dump({"replicas": items}, f)
        for rid, w in llaves.items():
            w.export(str(self.dir / f"{rid}_pbft.json"))
        return ruta, ReplicaSet.from_list(items), llaves, puertos

    def extra_pbft(self, ruta: Path, rid: str) -> dict:
        return {"pbft_replicas_file": str(ruta), "pbft_key_file": str(self.dir / f"{rid}_pbft.json")}

    # Nodos ───────────────────────────────────────────────────────────────────

    def honesto(self, nid: str, consenso: str = "pow", bits: int = 10, puerto: int = 0, **extra):
        """Nodo completo de ``build_node`` arrancado como en el ``lifespan`` de la app."""
        from api.app import build_node
        node = build_node(self._ajustes(nid, consenso, bits, puerto, **extra),
                          self.autoridad.address)
        self.honestos.append(node)
        node.p2p.start()
        if node.replica_set is not None:          # en pbft las réplicas también son pares
            for r in node.replica_set.replicas:
                if r.id != nid:
                    node.p2p.add_peer(r.host, r.port)
        if node.pbft is not None:
            node.pbft_transport.start()
            node.pbft.start()
        return node

    def cadena(self, nid: str, consenso: str = "pow", bits: int = 10,
               replica_set: Optional[ReplicaSet] = None) -> Blockchain:
        """Una ``Blockchain`` real con las mismas reglas que los honestos."""
        from api.app import build_node_state
        bc = build_node_state(str(self.dir / nid), nid, authority_address=self.autoridad.address,
                              initial_difficulty=bits, consensus=consenso, replica_set=replica_set)
        self.cadenas.append(bc)
        return bc

    def malicioso(self, nid: str, consenso: str = "pow", bits: int = 10, puerto: int = 0,
                  replica_set: Optional[ReplicaSet] = None, tls: Optional[dict] = None,
                  con_cadena: bool = True) -> NodoMalicioso:
        bc = self.cadena(f"{nid}_publica", consenso, bits, replica_set) if con_cadena else None
        nodo = NodoMalicioso(nid, HOST, puerto, blockchain=bc, consensus=consenso, tls=tls,
                             sync_interval=60.0)
        self.maliciosos.append(nodo)
        nodo.start()
        return nodo


def _conectar(p2p_a: P2PNode, p2p_b: P2PNode) -> bool:
    """``a`` hace HANDSHAKE con ``b`` y espera a que ambos se vean activos."""
    if not p2p_a.connect_to_peer(HOST, p2p_b.port):
        return False
    return _esperar(lambda: any(p.is_active and p.port == p2p_a.port
                                for p in p2p_b.peers_snapshot()), 5)


# ── 1. Doble gasto ────────────────────────────────────────────────────────────

def doble_gasto(consenso: str = "pow", semilla: int = 1, cuota: int = 90,
                confirmaciones: int = 1, bits: int = 10, monto: int = 100,
                max_atraso: int = 4) -> dict:
    """Doble gasto contra un comercio. ``cuota`` = % de los intentos de hash del atacante (pow)."""
    if consenso == "pbft":
        return _doble_gasto_pbft(semilla, monto)
    return _doble_gasto_pow(semilla, cuota, confirmaciones, bits, monto, max_atraso)


def _carrera_pow(minero, comercio, privada: Blockchain, pago_id: str, cuota: int, z: int,
                 max_atraso: int, rng: random.Random, max_rondas: int = 20_000) -> dict:
    """Rondas de minado: el honesto y el atacante gastan su parte de INTENTOS_POR_RONDA.

    Cada candidato usa la dificultad que dicta la regla de SU cadena (si una cadena cruza
    una época, se reajusta como en cualquier nodo); por eso se compara trabajo, no altura.
    """
    intentos_honesto = INTENTOS_POR_RONDA - cuota

    def candidato(bc):
        b = bc.create_candidate_block()
        b.header.nonce = rng.randrange(1 << 30)
        return b
    cand_h, cand_a = candidato(minero.blockchain), candidato(privada)
    rondas = 0
    while rondas < max_rondas:
        rondas += 1
        if intentos_honesto and _intentar(cand_h, intentos_honesto):
            _publicar(minero, cand_h)
            altura = minero.blockchain.height
            _esperar(lambda: comercio.blockchain.height >= altura, 5)
            cand_h = candidato(minero.blockchain)
        if cuota and _intentar(cand_a, cuota):
            ok, motivo = privada.add_block(cand_a)
            if not ok:
                raise RuntimeError(f"bloque privado inválido: {motivo}")
            cand_a = candidato(privada)
        h_hon, h_priv = minero.blockchain.height, privada.height
        if (_confirmaciones(comercio.blockchain, pago_id) >= z
                and privada.total_work > comercio.blockchain.total_work):
            return {"liberar": True, "rondas": rondas}
        if h_hon - h_priv >= max_atraso:
            break
    return {"liberar": False, "rondas": rondas}


def _doble_gasto_pow(semilla, cuota, z, bits, monto, max_atraso) -> dict:
    if not 0 <= cuota <= INTENTOS_POR_RONDA:
        raise ValueError("cuota debe estar entre 0 y 100 (% de los intentos de hash)")
    rng = random.Random(semilla)
    narr: List[str] = []
    with _Laboratorio("doble-gasto-pow") as lab:
        minero = lab.honesto("minero_honesto", "pow", bits)
        comercio = lab.honesto("comercio", "pow", bits)
        atacante = lab.malicioso("atacante", "pow", bits)
        for a, b in ((comercio.p2p, minero.p2p), (atacante, minero.p2p), (atacante, comercio.p2p)):
            if not _conectar(a, b):
                raise RuntimeError("los nodos del laboratorio no se conectaron")
        w_atk, w_com, w_cmp = Wallet.generate(), Wallet.generate(), Wallet.generate()
        narr.append(f"Red PoW en loopback: minero_honesto y comercio (honestos) + atacante; "
                    f"dificultad {bits} bits; el atacante tiene el {cuota} % de los intentos de hash.")

        # Fondos del atacante: la autoridad le emite `monto` (bloque k-1).
        mint = create_mint_transaction(lab.autoridad.address, w_atk.address, monto,
                                       lab.autoridad.private_key_hex, nonce=1)
        ok, motivo = minero.blockchain.add_transaction(mint)
        if not ok:
            raise RuntimeError(f"no se pudo emitir saldo al atacante: {motivo}")
        _publicar(minero, _minar(minero.blockchain.create_candidate_block()))
        if not _esperar(lambda: comercio.blockchain.height == 1 and atacante.blockchain.height == 1, 10):
            raise RuntimeError("el bloque de fondos no se propagó")
        k = 2
        narr.append(f"Bloque {k - 1}: la autoridad emite {monto} PUPB al atacante.")

        # MALICIOSO: copia la cadena pública hasta k-1 y mina en secreto el gasto alternativo.
        privada = lab.cadena("atacante_privada", "pow", bits)
        ok, motivo = privada.replace_chain([b.to_dict() for b in atacante.blockchain.chain[:k]])
        if not ok:
            raise RuntimeError(f"no se pudo copiar la cadena pública: {motivo}")
        pago = create_transfer_transaction(w_atk.address, w_com.address, monto,
                                           w_atk.private_key_hex, nonce=1)
        robo = create_transfer_transaction(w_atk.address, w_cmp.address, monto,
                                           w_atk.private_key_hex, nonce=1)
        ok, motivo = privada.add_transaction(robo)
        if not ok:
            raise RuntimeError(f"la TX alternativa no entra en la cadena privada: {motivo}")
        atacante.broadcast_transaction(pago.to_dict())
        if not _esperar(lambda: any(t.tx_id == pago.tx_id for t in minero.blockchain.mempool), 5):
            raise RuntimeError("el pago no llegó al minero honesto")
        narr.append(f"El atacante paga {monto} PUPB al comercio (TX {pago.tx_id[:12]}…) y, en "
                    f"secreto, mina desde el bloque {k - 1} una TX con el MISMO nonce que envía "
                    f"esos fondos a un cómplice (TX {robo.tx_id[:12]}…).")

        carrera = _carrera_pow(minero, comercio, privada, pago.tx_id, cuota, z, max_atraso, rng)
        alt_honesta, alt_privada = comercio.blockchain.height, privada.height
        conf = _confirmaciones(comercio.blockchain, pago.tx_id)
        punta_comercio = comercio.blockchain.last_block.hash
        if conf >= z:
            narr.append(f"El comercio ve el pago con {conf} confirmación(es) (bloque "
                        f"{comercio.blockchain.get_transaction(pago.tx_id)['block']}) y entrega "
                        f"el producto.")
        if carrera["liberar"]:
            narr.append(f"Tras {carrera['rondas']} rondas la cadena privada (altura {alt_privada}) "
                        f"supera a la pública (altura {alt_honesta}): el atacante la LIBERA.")
            atacante.liberar([b.to_dict() for b in privada.chain])
            _esperar(lambda: comercio.blockchain.last_block.hash == privada.last_block.hash
                     and minero.blockchain.last_block.hash == privada.last_block.hash, 10)
        else:
            motivo = (f"va {alt_honesta - alt_privada} bloque(s) atrás"
                      if alt_honesta - alt_privada >= max_atraso else "se agotaron las rondas")
            narr.append(f"Tras {carrera['rondas']} rondas el atacante abandona: {motivo} (cadena "
                        f"privada {alt_privada}, pública {alt_honesta}). No libera nada.")
        bc = comercio.blockchain
        pago_vigente = bc.get_transaction(pago.tx_id) is not None
        robo_vigente = bc.get_transaction(robo.tx_id) is not None
        reorgs = _alertas(comercio, ("CHAIN_REORG",))
        # Profundidad = bloques del comercio descartados (la mide el propio nodo en su alerta).
        profundidad = max((int(a["datos"].get("depth", 0)) for a in reorgs), default=0)
        exito = carrera["liberar"] and not pago_vigente and robo_vigente
        if exito:
            narr.append(f"El comercio REORGANIZA su cadena (profundidad {profundidad}): su pago ya "
                        f"no existe y el saldo del comercio es {bc.get_balance(w_com.address)}; el "
                        f"cómplice tiene {bc.get_balance(w_cmp.address)}. Doble gasto CONSUMADO. "
                        f"El monitor del comercio levantó {len(reorgs)} alerta(s) CHAIN_REORG, "
                        f"pero después del hecho.")
        else:
            narr.append(f"El pago sigue en la cadena del comercio (saldo "
                        f"{bc.get_balance(w_com.address)}): el doble gasto FALLÓ.")
        return {
            "escenario": "doble_gasto", "consenso": "pow", "semilla": semilla,
            "exito_ataque": exito, "cuota_atacante_pct": cuota, "confirmaciones_exigidas": z,
            "bits": bits, "rondas": carrera["rondas"], "liberada": carrera["liberar"],
            "altura_publica_al_liberar": alt_honesta, "altura_privada_al_liberar": alt_privada,
            "profundidad_reorg": profundidad, "punta_comercio_antes": punta_comercio[:16],
            "punta_comercio_despues": bc.last_block.hash[:16],
            "pago_en_cadena_del_comercio": pago_vigente, "robo_en_cadena_del_comercio": robo_vigente,
            "saldo_comercio": bc.get_balance(w_com.address),
            "saldo_complice": bc.get_balance(w_cmp.address),
            "alertas": reorgs, "narrativa": narr,
        }


def _doble_gasto_pbft(semilla: int, monto: int) -> dict:
    narr: List[str] = []
    ids = ["r0", "r1", "r2", "r3"]
    with _Laboratorio("doble-gasto-pbft") as lab:
        ruta, rs, llaves, puertos = lab.lista_pbft(ids)
        # MALICIOSO: r3 es una réplica comprometida (el atacante tiene su llave real).
        atacante = lab.malicioso("r3", "pbft", puerto=puertos["r3"], replica_set=rs)
        honestos = {rid: lab.honesto(rid, "pbft", puerto=puertos[rid], **lab.extra_pbft(ruta, rid))
                    for rid in ("r0", "r1", "r2")}
        comercio = honestos["r1"]
        for node in honestos.values():
            if not _conectar(atacante, node.p2p):
                raise RuntimeError("el atacante no se conectó a las réplicas")
        if not _esperar(lambda: all(n.p2p.get_network_stats()["active_peers"] >= 3
                                    for n in honestos.values()), 10):
            raise RuntimeError("las réplicas honestas no se conectaron entre sí")
        narr.append("Red PBFT en loopback: 4 réplicas (n = 4, f = 1, quórum 2f+1 = 3). r0, r1 y r2 "
                    "son honestas; r3 está comprometida: el atacante tiene su llave real. El "
                    "comercio mira la cadena de r1.")
        w_atk, w_com, w_cmp = Wallet.generate(), Wallet.generate(), Wallet.generate()

        def confirmar(tx: Transaction, altura: int) -> None:
            r0 = honestos["r0"]
            if tx.sender == lab.autoridad.address:
                ok, motivo = r0.blockchain.add_transaction(tx)
                if not ok:
                    raise RuntimeError(motivo)
                r0.p2p.broadcast_transaction(tx.to_dict())
            else:
                atacante.broadcast_transaction(tx.to_dict())
            if not _esperar(lambda: all(n.blockchain.height >= altura for n in honestos.values()), 15):
                raise RuntimeError(f"PBFT no confirmó la altura {altura}")
            if not _esperar(lambda: atacante.blockchain.height >= altura, 3):
                atacante.sync_with(f"{HOST}:{puertos['r0']}")

        confirmar(create_mint_transaction(lab.autoridad.address, w_atk.address, monto,
                                          lab.autoridad.private_key_hex, nonce=1), 1)
        narr.append(f"Bloque 1 (certificado): la autoridad emite {monto} PUPB al atacante.")
        pago = create_transfer_transaction(w_atk.address, w_com.address, monto,
                                           w_atk.private_key_hex, nonce=1)
        robo = create_transfer_transaction(w_atk.address, w_cmp.address, monto,
                                           w_atk.private_key_hex, nonce=1)
        confirmar(pago, 2)
        bc = comercio.blockchain
        bloque_pago = bc.get_transaction(pago.tx_id)["block"]
        cert_ok = bc.check_certificate(bc.chain[bloque_pago], bc.certificates.get(bloque_pago))
        punta_antes = bc.last_block.hash
        narr.append(f"El pago al comercio queda en el bloque {bloque_pago} con certificado de "
                    f"commit ({len(bc.certificates[bloque_pago]['commits'])} firmas): "
                    f"{cert_ok[1]}. El comercio entrega el producto.")

        # MALICIOSO: bifurcación desde el bloque 1, más larga, con certificados falsificados.
        base = atacante.blockchain.chain[:bloque_pago]
        horquilla, certs = list(base), {}
        llave_r3 = llaves["r3"].private_key_hex
        for txs in ([robo.to_dict()], [], []):
            b = _bloque_sin_trabajo(horquilla[-1], txs, "r3")
            horquilla.append(b)
            certs[b.header.index] = _certificado_falso(b, llave_r3, ["r3", "r0", "r1"])
        primero = horquilla[bloque_pago]
        motivo_falso = bc.check_certificate(primero, certs[bloque_pago])[1]
        motivo_propio = bc.check_certificate(primero, _certificado_falso(primero, llave_r3, ["r3"]))[1]
        rechazos_antes = {rid: n.pbft.rejected_messages for rid, n in honestos.items()}
        atacante.liberar([b.to_dict() for b in horquilla], certs)
        narr.append(f"El atacante libera una bifurcación desde el bloque {bloque_pago - 1} con "
                    f"{len(horquilla) - bloque_pago} bloques (más larga que la honesta) que gasta los "
                    f"mismos fondos en un cómplice. Sus certificados llevan la firma real de r3 y "
                    f"firmas FALSIFICADAS a nombre de r0 y r1.")
        # 2º intento: un bloque con el robo encima de la punta honesta y certificado falso.
        inyectado = _bloque_sin_trabajo(bc.last_block, [robo.to_dict()], "r3")
        for node in honestos.values():
            atacante.enviar_bloque_a(node.p2p.port, inyectado.to_dict(),
                                     _certificado_falso(inyectado, llave_r3, ["r3", "r0", "r1"]))
        # 3º intento: votos COMMIT falsificados por el canal PBFT.
        votos_falsos = 0
        for rid in ("r0", "r2"):
            voto = sign_message({"type": COMMIT, "replica": rid, "view": 0, "seq": bloque_pago,
                                 "digest": primero.hash}, llave_r3)
            for destino in ("r1",):
                atacante.enviar_pbft_a(puertos[destino], voto)
                votos_falsos += 1
        _esperar(lambda: honestos["r1"].pbft.rejected_messages - rechazos_antes["r1"] >= votos_falsos
                 and any(_alertas(n, ("INVALID_BLOCK",)) for n in honestos.values()), 5)
        # Los honestos consultan al atacante (anuncia más altura) y deben rechazar su cadena.
        for node in honestos.values():
            node.p2p.sync_with(f"{HOST}:{atacante.port}")
        pago_vigente = bc.get_transaction(pago.tx_id) is not None
        robo_vigente = bc.get_transaction(robo.tx_id) is not None
        puntas = {rid: n.blockchain.last_block.hash for rid, n in honestos.items()}
        cert_despues = bc.check_certificate(bc.chain[bloque_pago], bc.certificates.get(bloque_pago))
        alertas = [a for n in honestos.values() for a in _alertas(n)]
        rechazados = {rid: n.pbft.rejected_messages - rechazos_antes[rid] for rid, n in honestos.items()}
        exito = not pago_vigente
        narr.append(f"Las réplicas honestas rechazan la bifurcación: «{motivo_falso}». Aun usando "
                    f"solo su firma verdadera: «{motivo_propio}».")
        narr.append(f"El bloque inyectado sobre la punta se descarta (alertas INVALID_BLOCK: "
                    f"{sum(1 for a in alertas if a['tipo'] == 'INVALID_BLOCK')}); los votos COMMIT "
                    f"falsificados se descartan por firma inválida (mensajes rechazados en r1: "
                    f"{rechazados['r1']}).")
        narr.append(("El pago sigue certificado en el bloque "
                     f"{bloque_pago} ({cert_despues[1]}); las tres réplicas honestas conservan la "
                     f"misma punta. Doble gasto FALLIDO: un bloque certificado nunca se reemplaza.")
                    if not exito else "El pago desapareció: el ataque tuvo éxito (no debería ocurrir).")
        return {
            "escenario": "doble_gasto", "consenso": "pbft", "semilla": semilla,
            "exito_ataque": exito, "replica_comprometida": "r3",
            "bloque_del_pago": bloque_pago, "altura_bifurcacion": len(horquilla) - 1,
            "altura_honesta": bc.height, "punta_sin_cambios": bc.last_block.hash == punta_antes,
            "puntas_iguales": len(set(puntas.values())) == 1,
            "pago_en_cadena_del_comercio": pago_vigente, "robo_en_cadena_del_comercio": robo_vigente,
            "certificado_del_pago": cert_despues[1],
            "motivo_rechazo_certificado_falso": motivo_falso,
            "motivo_rechazo_solo_firma_propia": motivo_propio,
            "mensajes_pbft_rechazados": rechazados,
            "saldo_comercio": bc.get_balance(w_com.address),
            "saldo_complice": bc.get_balance(w_cmp.address),
            "alertas": alertas, "narrativa": narr,
        }


# ── 2. Barrido de reorg (solo PoW) ────────────────────────────────────────────

def barrido_reorg(consenso: str = "pow", semilla: int = 1, cuotas=(10, 30, 45, 60, 75, 90),
                  intentos: int = 4, confirmaciones: int = 1, bits: int = 10) -> dict:
    """Tasa de éxito del doble gasto y profundidad del reorg según la cuota del atacante."""
    if consenso == "pbft":
        return {"escenario": "reorg", "consenso": "pbft", "aplica": False, "exito_ataque": False,
                "narrativa": ["En PBFT no hay carrera de trabajo: un bloque certificado es final "
                              "y replace_chain se niega a reemplazarlo. Ver "
                              "`--escenario doble_gasto --consenso pbft`."]}
    filas = []
    t0 = time.perf_counter()
    for cuota in cuotas:
        corridas = [doble_gasto("pow", semilla * 1000 + cuota * 10 + i, cuota, confirmaciones, bits)
                    for i in range(intentos)]
        exitos = [c for c in corridas if c["exito_ataque"]]
        filas.append({
            "cuota_atacante_pct": cuota, "corridas": intentos, "exitos": len(exitos),
            "tasa_exito": round(len(exitos) / intentos, 3),
            "profundidad_media": (round(sum(c["profundidad_reorg"] for c in exitos) / len(exitos), 2)
                                  if exitos else None),
            "profundidad_max": max((c["profundidad_reorg"] for c in exitos), default=None),
            "rondas_medias": round(sum(c["rondas"] for c in corridas) / intentos, 1),
        })
    duracion = round(time.perf_counter() - t0, 1)
    narr = [f"Barrido PoW: {intentos} corrida(s) por cuota, {confirmaciones} confirmación(es) "
            f"exigida(s), {bits} bits iniciales, el atacante abandona si va 4 bloques atrás.",
            "MEDIDO EN PROCESO en esta máquina (nodos en un mismo intérprete, loopback); n pequeño: "
            "son tasas de laboratorio, no probabilidades exactas ni cifras de las Raspberry Pi."]
    for f in filas:
        narr.append(f"  cuota {f['cuota_atacante_pct']:>3} %: {f['exitos']}/{f['corridas']} dobles "
                    f"gastos consumados; profundidad media del reorg "
                    f"{f['profundidad_media'] if f['profundidad_media'] is not None else 'n/a'}.")
    return {"escenario": "reorg", "consenso": "pow", "aplica": True, "semilla": semilla,
            "exito_ataque": any(f["exitos"] for f in filas), "medicion": "en proceso (portátil)",
            "duracion_s": duracion, "filas": filas, "narrativa": narr}


# ── 3. Sybil ──────────────────────────────────────────────────────────────────

def sybil(consenso: str = "pow", semilla: int = 1, identidades: int = 5) -> dict:
    """Muchas identidades falsas contra un nodo con y sin TLS mutuo + lista blanca."""
    con_tls = _sybil_ronda(consenso, identidades, tls=True)
    sin_tls = _sybil_ronda(consenso, identidades, tls=False)
    narr = [f"El atacante fabrica {identidades} identidades (sybil_0…) y además usa su ÚNICO "
            f"certificado válido de la red (CN = atacante, fuera de la lista blanca)."]
    narr += con_tls.pop("narrativa") + sin_tls.pop("narrativa")
    return {"escenario": "sybil", "consenso": consenso, "semilla": semilla,
            "identidades": identidades,
            "exito_ataque": con_tls["aceptados"] > 0,
            "con_tls": con_tls, "sin_tls": sin_tls, "narrativa": narr}


def _sybil_ronda(consenso: str, n: int, tls: bool) -> dict:
    from security.pki import crear_ca, emitir_cert_nodo
    narr: List[str] = []
    etiqueta = "CON TLS mutuo + lista blanca" if tls else "SIN TLS (lista blanca solo informativa)"
    with _Laboratorio(f"sybil-{consenso}") as lab:
        if consenso == "pbft":
            ids = ["r0", "r1", "r2", "r3"]
            objetivo_id, vecino = "r1", "r0"
        else:
            ids = ["honesto"]
            objetivo_id, vecino = "honesto", "vecino"
        extra_tls: dict = {}
        ca_red, ca_pirata = lab.dir / "tls_red", lab.dir / "tls_pirata"
        if tls:
            crear_ca(ca_red)
            for nid in ids + ["atacante"]:
                emitir_cert_nodo(ca_red, nid, [HOST])
            crear_ca(ca_pirata, nombre="CA pirata")
            for i in range(n):
                emitir_cert_nodo(ca_pirata, f"sybil_{i}", [HOST])
            extra_tls = {"p2p_tls": "on", "p2p_tls_dir": str(ca_red)}
        if consenso == "pbft":
            ruta, rs, _, puertos = lab.lista_pbft(ids)
            nodos = {rid: lab.honesto(rid, "pbft", puerto=puertos[rid], **lab.extra_pbft(ruta, rid),
                                      **extra_tls) for rid in ids}
            _esperar(lambda: all(x.p2p.get_network_stats()["active_peers"] >= 3
                                 for x in nodos.values()), 10)
        else:
            nodos = {"honesto": lab.honesto("honesto", "pow", p2p_allowlist=["honesto", vecino],
                                            **extra_tls)}
        objetivo = nodos[objetivo_id]
        lista = sorted(objetivo.p2p.allowlist)

        def tls_de(directorio, nid):
            return {"ca": str(directorio / "ca.crt"), "cert": str(directorio / f"{nid}.crt"),
                    "key": str(directorio / f"{nid}.key")}

        intentos = []          # (identidad, credencial, aceptado)
        sybils = []
        for i in range(n):
            nid = f"sybil_{i}"
            cred = tls_de(ca_pirata, nid) if tls else None
            s = lab.malicioso(nid, consenso, tls=cred, con_cadena=False)
            sybils.append(s)
            intentos.append((nid, "cert. de CA pirata" if tls else "sin credencial",
                             s.connect_to_peer(HOST, objetivo.p2p.port)))
        if tls:
            for i in range(n):         # MALICIOSO: un solo certificado válido, muchas identidades
                s = lab.malicioso(f"sybil_{n + i}", consenso, tls=tls_de(ca_red, "atacante"),
                                  con_cadena=False)
                intentos.append((f"sybil_{n + i}", "cert. válido de 'atacante'",
                                 s.connect_to_peer(HOST, objetivo.p2p.port)))
            impostor = lab.malicioso(vecino, consenso, tls=tls_de(ca_red, "atacante"),
                                     con_cadena=False)
            intentos.append((vecino, "cert. de 'atacante' haciéndose pasar por un nodo permitido",
                             impostor.connect_to_peer(HOST, objetivo.p2p.port)))
        honestos_ids = set(ids)
        _esperar(lambda: sum(1 for p in objetivo.p2p.peers_snapshot()
                             if p.is_active and p.node_id not in honestos_ids) >= sum(
                                 1 for x in intentos if x[2]), 3)
        aceptados = sorted(p.node_id for p in objetivo.p2p.peers_snapshot()
                           if p.is_active and p.node_id not in honestos_ids)
        alertas = _alertas(objetivo, ("UNKNOWN_PEER",))
        narr.append(f"[{etiqueta}] nodo objetivo {objetivo_id} (lista blanca: {', '.join(lista)}): "
                    f"{sum(1 for x in intentos if x[2])} de {len(intentos)} conexiones aceptadas; "
                    f"{len(alertas)} alerta(s) UNKNOWN_PEER.")
        if tls:
            narr.append("  Los certificados de otra CA fallan en el apretón de manos TLS; el "
                        "certificado válido de 'atacante' se corta por la lista blanca (CN fuera de "
                        "ella). Las alertas se emiten una vez por identidad (no por intento).")
        else:
            narr.append("  Sin TLS el node_id anunciado no está autenticado: cada Sybil queda "
                        "conectado y solo se avisa. Con suficientes Sybil un atacante puede rodear "
                        "a un nodo (eclipse, ver security/attacks/eclipse.py).")
        votos = None
        if consenso == "pbft" and not tls:
            # MALICIOSO: cada Sybil vota COMMIT (con su propia llave) por un bloque inventado.
            replica = objetivo.pbft
            antes, altura = replica.rejected_messages, objetivo.blockchain.height
            digest = "f" * 64
            enviados = 0
            for i, s in enumerate(sybils):
                llave = Wallet.generate().private_key_hex
                for rid in (s.node_id, vecino):        # identidad propia y suplantando a r0
                    s.enviar_pbft_a(objetivo.p2p.port, sign_message(
                        {"type": COMMIT, "replica": rid, "view": 0, "seq": altura + 1,
                         "digest": digest}, llave))
                    enviados += 1
            _esperar(lambda: replica.rejected_messages - antes >= enviados, 5)
            votos = {"enviados": enviados, "rechazados": replica.rejected_messages - antes,
                     "altura_antes": altura, "altura_despues": objetivo.blockchain.height}
            narr.append(f"  PBFT: {enviados} votos COMMIT de Sybil (con su nombre o suplantando a "
                        f"{vecino}) → {votos['rechazados']} descartados por firma inválida o réplica "
                        f"desconocida; la altura sigue en {votos['altura_despues']}.")
        return {"tls": tls, "objetivo": objetivo_id, "lista_blanca": lista,
                "intentos": [{"identidad": i, "credencial": c, "aceptado": a} for i, c, a in intentos],
                "aceptados": len(aceptados), "pares_aceptados": aceptados,
                "alertas": alertas, "votos_pbft": votos, "narrativa": narr}


# ── 4. Equivocación ───────────────────────────────────────────────────────────

def equivocacion(consenso: str = "pbft", semilla: int = 1, bits: int = 10) -> dict:
    if consenso == "pow":
        return _equivocacion_pow(semilla, bits)
    return _equivocacion_pbft(semilla)


def _equivocacion_pbft(semilla: int) -> dict:
    narr: List[str] = []
    ids = ["r0", "r1", "r2", "r3"]
    with _Laboratorio("equivocacion-pbft") as lab:
        ruta, rs, llaves, puertos = lab.lista_pbft(ids)
        # MALICIOSO: r0, primario de la vista 0, controlado por el atacante.
        atacante = lab.malicioso("r0", "pbft", puerto=puertos["r0"], replica_set=rs)
        honestos = {rid: lab.honesto(rid, "pbft", puerto=puertos[rid], **lab.extra_pbft(ruta, rid))
                    for rid in ("r1", "r2", "r3")}
        for node in honestos.values():
            _conectar(atacante, node.p2p)
        if not _esperar(lambda: all(n.p2p.get_network_stats()["active_peers"] >= 3
                                    for n in honestos.values()), 10):
            raise RuntimeError("las réplicas no se conectaron")
        narr.append("Red PBFT: r0 (primario de la vista 0) es malicioso; r1, r2 y r3 son honestas.")
        w = Wallet.generate()
        tx = Transaction(type=TransactionType.DATA_RECORD, sender=w.address, recipient="UPB_LAB",
                         payload={"dato": f"registro {semilla}"}, nonce=1)
        tx.sign(w.private_key_hex)
        r1 = honestos["r1"]
        ok, motivo = r1.blockchain.add_transaction(tx)
        if not ok:
            raise RuntimeError(motivo)
        r1.p2p.broadcast_transaction(tx.to_dict())
        _esperar(lambda: all(len(n.blockchain.mempool) == 1 for n in honestos.values()), 5)
        a = atacante.blockchain.create_candidate_block([tx])
        b = Block(header=BlockHeader(**{**a.header.__dict__, "timestamp": a.header.timestamp + 1}),
                  transactions=a.transactions)

        def pp(bloque):
            m = sign_message({"type": PRE_PREPARE, "replica": "r0", "view": 0, "seq": 1,
                              "digest": bloque.hash}, llaves["r0"].private_key_hex)
            m["block"] = bloque.to_dict()
            return m
        orden = {"r1": (a, b), "r2": (b, a), "r3": (b, a)}
        for rid, (primero, segundo) in orden.items():   # MALICIOSO: dos propuestas firmadas
            atacante.enviar_pbft_a(puertos[rid], pp(primero))
            time.sleep(0.15)
            atacante.enviar_pbft_a(puertos[rid], pp(segundo))
        narr.append(f"r0 firma DOS PRE-PREPARE para la altura 1: A ({a.hash[:12]}…) primero a r1 y "
                    f"B ({b.hash[:12]}…) primero a r2 y r3; luego el otro a cada una.")
        detectada = _esperar(lambda: all(_alertas(n, ("PBFT_EQUIVOCATION",))
                                         for n in honestos.values()), 5)
        confirmado = _esperar(lambda: all(n.blockchain.height >= 1 for n in honestos.values()), 15)
        hashes = {rid: n.blockchain.chain[1].hash for rid, n in honestos.items()
                  if n.blockchain.height >= 1}
        distintos = set(hashes.values())
        estado = {rid: {"vista": n.pbft.view, "primario": n.pbft.primary,
                        "cambios_de_vista": n.pbft.view_changes_total}
                  for rid, n in honestos.items()}
        alertas = [x for n in honestos.values() for x in _alertas(n, ("PBFT_EQUIVOCATION",))]
        cual = ("B" if distintos == {b.hash} else "A" if distintos == {a.hash} else None)
        narr.append(f"Cada réplica honesta detecta la equivocación (alertas PBFT_EQUIVOCATION: "
                    f"{len(alertas)}) y, como el primario no logra quórum, pide cambio de vista "
                    f"(vista actual {estado['r1']['vista']}, primario {estado['r1']['primario']}).")
        if confirmado and len(distintos) == 1:
            narr.append(f"El nuevo primario re-propone el bloque {cual or 'propuesto'} (el que llegó "
                        f"a 'prepared', o uno nuevo si ninguno llegó); "
                        f"las tres réplicas confirman el MISMO bloque en la altura 1. Ataque FALLIDO.")
        return {"escenario": "equivocacion", "consenso": "pbft", "semilla": semilla,
                "exito_ataque": len(distintos) > 1, "equivocacion_detectada": detectada,
                "bloques_distintos_confirmados_en_altura_1": len(distintos),
                "bloque_confirmado": cual, "estado_replicas": estado,
                "alertas": alertas, "narrativa": narr}


def _equivocacion_pow(semilla: int, bits: int) -> dict:
    rng = random.Random(semilla)
    narr: List[str] = []
    with _Laboratorio("equivocacion-pow") as lab:
        ha = lab.honesto("honesto_a", "pow", bits)
        hb = lab.honesto("honesto_b", "pow", bits)
        atacante = lab.malicioso("atacante", "pow", bits)
        for x, y in ((ha.p2p, hb.p2p), (atacante, ha.p2p), (atacante, hb.p2p)):
            if not _conectar(x, y):
                raise RuntimeError("los nodos no se conectaron")
        a = atacante.blockchain.create_candidate_block()
        a.header.nonce = rng.randrange(1 << 30)
        _minar(a)
        b = atacante.blockchain.create_candidate_block()
        b.header.timestamp = a.header.timestamp + 0.5
        b.header.nonce = rng.randrange(1 << 30)
        _minar(b)
        # MALICIOSO: A solo a honesto_a y B solo a honesto_b, a la vez.
        envios = [threading.Thread(target=atacante.enviar_bloque_a, args=(nodo.p2p.port, blq.to_dict()))
                  for nodo, blq in ((ha, a), (hb, b))]
        for t in envios:
            t.start()
        for t in envios:
            t.join(timeout=5)
        _esperar(lambda: ha.blockchain.height == 1 and hb.blockchain.height == 1, 5)
        time.sleep(0.3)        # el gossip cruzado llega, pero un empate de trabajo no reorganiza
        divergen = ha.blockchain.last_block.hash != hb.blockchain.last_block.hash
        narr.append(f"El atacante mina dos bloques válidos para la altura 1 (A {a.hash[:12]}…, B "
                    f"{b.hash[:12]}…) y entrega A a honesto_a y B a honesto_b.")
        narr.append(f"PoW no tiene 'equivocación': ambos bloques son válidos. Las puntas "
                    f"{'DIVERGEN' if divergen else 'coinciden'} (mismo trabajo: cada nodo conserva "
                    f"el suyo) y el monitor no levanta alertas de equivocación.")
        _publicar(ha, _minar(ha.blockchain.create_candidate_block()))
        convergen = _esperar(lambda: hb.blockchain.last_block.hash == ha.blockchain.last_block.hash, 10)
        reorgs = _alertas(hb, ("CHAIN_REORG",))
        narr.append(f"honesto_a mina el bloque 2 sobre A; honesto_b lo recibe, ve más trabajo y "
                    f"reorganiza (alertas CHAIN_REORG en honesto_b: {len(reorgs)}). Las puntas "
                    f"{'convergen' if convergen else 'no convergen'}: el bloque B quedó huérfano. "
                    f"El 'éxito' del atacante es solo una división temporal de la red.")
        return {"escenario": "equivocacion", "consenso": "pow", "semilla": semilla,
                "exito_ataque": divergen, "divergencia_temporal": divergen,
                "convergen_tras_siguiente_bloque": convergen,
                "alertas_equivocacion": sum(len(_alertas(n, ("PBFT_EQUIVOCATION",)))
                                            for n in (ha, hb)),
                "alertas": reorgs, "narrativa": narr}


# ── Punto de entrada común ────────────────────────────────────────────────────

def ejecutar(escenario: str, consenso: str = "pow", semilla: int = 1, **opciones) -> dict:
    """Corre un escenario del laboratorio y devuelve su resultado estructurado."""
    if consenso not in ("pow", "pbft"):
        raise ValueError("consenso debe ser 'pow' o 'pbft'")
    funciones = {"doble_gasto": doble_gasto, "reorg": barrido_reorg, "sybil": sybil,
                 "equivocacion": equivocacion}
    if escenario not in funciones:
        raise ValueError(f"escenario desconocido: {escenario} (use {', '.join(ESCENARIOS)})")
    return funciones[escenario](consenso=consenso, semilla=semilla, **opciones)
