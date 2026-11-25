"""P1-1: PBFT con firmas, certificados de commit y cambio de vista (red en memoria).

Estas pruebas usan ``InMemoryNetwork`` (entrega síncrona, sin sockets) y un reloj
falso, así que son deterministas y rápidas. Las pruebas con apps reales y P2P
están en ``test_pbft_red.py``.
"""
import pytest

from blockchain.consensus.pbft import (CERT_REPLY, CERT_REQUEST, COMMIT, PRE_PREPARE, VIEW_CHANGE,
                                       InMemoryNetwork, PBFTReplica, ReplicaSet, sign_message)
from blockchain.core.block import Block, BlockHeader
from blockchain.core.chain import Blockchain
from blockchain.core.transaction import Transaction, TransactionType
from blockchain.core.wallet import Wallet
from security.monitor import SecurityMonitor


class Reloj:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def _tx(i=0):
    w = Wallet.generate()
    tx = Transaction(type=TransactionType.DATA_RECORD, sender=w.address, recipient="UPB_DEST",
                     payload={"dato": f"registro {i}"}, fee=0, nonce=1)
    tx.sign(w.private_key_hex)
    return tx


class Red:
    """4 réplicas PBFT en memoria con su cadena, monitor y reloj falso."""

    def __init__(self, tmp_path, n=4, timeout=5.0, iniciar=None):
        self.wallets = [Wallet.generate() for _ in range(n)]
        self.ids = [f"r{i}" for i in range(n)]
        self.rs = ReplicaSet.from_list([
            {"id": rid, "address": f"127.0.0.1:{9000 + i}", "public_key": w.public_key_hex}
            for i, (rid, w) in enumerate(zip(self.ids, self.wallets))])
        self.reloj = Reloj()
        self.net = InMemoryNetwork()
        self.monitores, self.cadenas, self.replicas = {}, {}, {}
        for i, rid in enumerate(self.ids):
            if iniciar is not None and rid not in iniciar:
                continue
            bc = Blockchain(node_id=rid, data_dir=str(tmp_path / rid), consensus="pbft",
                            replica_set=self.rs)
            mon = SecurityMonitor()
            r = PBFTReplica(rid, self.wallets[i].private_key_hex, self.rs, bc,
                            self.net.sender(rid), send_to=self.net.unicaster(rid),
                            view_timeout=timeout, batch_interval=0.0,
                            on_equivocation=mon.on_pbft_equivocation,
                            on_invalid_block=mon.on_invalid_block,
                            clock=self.reloj)
            bc.add_certified_conflict_listener(mon.on_certified_conflict)
            self.net.add(r)
            self.cadenas[rid], self.monitores[rid], self.replicas[rid] = bc, mon, r

    def enviar_tx(self, tx):
        """Simula el gossip de una TX: entra al mempool de todas las réplicas vivas."""
        for rid, bc in self.cadenas.items():
            if rid not in self.net.down:
                assert bc.add_transaction(tx)[0]

    def tick(self, avanzar=0.0):
        self.reloj.t += avanzar
        for rid, r in self.replicas.items():
            if rid not in self.net.down:
                r.tick()

    def alturas(self):
        return {rid: bc.height for rid, bc in self.cadenas.items() if rid not in self.net.down}

    def firmar(self, i, **campos):
        return sign_message({"replica": self.ids[i], **campos}, self.wallets[i].private_key_hex)


# ── Conjunto de réplicas y firmas ─────────────────────────────────────────────

def test_quorums_y_rotacion_del_primario(tmp_path):
    red = Red(tmp_path, iniciar=[])
    assert (red.rs.n, red.rs.f, red.rs.quorum, red.rs.prepare_quorum) == (4, 1, 3, 2)
    assert [red.rs.primary(v) for v in range(6)] == ["r0", "r1", "r2", "r3", "r0", "r1"]
    siete = ReplicaSet.from_list([{"id": f"x{i}", "address": f"h:{i + 1}",
                                   "public_key": Wallet.generate().public_key_hex}
                                  for i in range(7)])
    assert (siete.f, siete.quorum) == (2, 5)


def test_firma_valida_y_mensaje_alterado_o_de_desconocido(tmp_path):
    red = Red(tmp_path, iniciar=[])
    m = red.firmar(1, type=COMMIT, view=0, seq=1, digest="ab" * 32)
    assert red.rs.verify(m)
    assert not red.rs.verify({**m, "seq": 2})                      # alterado
    assert not red.rs.verify({**m, "replica": "r2"})               # otro firmante
    intruso = sign_message({"replica": "intruso", "type": COMMIT, "view": 0, "seq": 1,
                            "digest": "ab" * 32}, Wallet.generate().private_key_hex)
    assert not red.rs.verify(intruso)


def test_lista_de_replicas_invalida_da_error_en_espanol(tmp_path):
    from blockchain.consensus.pbft import PBFTConfigError
    with pytest.raises(PBFTConfigError, match="repetidos"):
        ReplicaSet.from_list([{"id": "a", "address": "h:1", "public_key": "00"},
                              {"id": "a", "address": "h:2", "public_key": "01"}])
    with pytest.raises(PBFTConfigError, match="no existe"):
        ReplicaSet.from_file(tmp_path / "no_hay.json")


# ── Caso normal ───────────────────────────────────────────────────────────────

def test_caso_normal_confirma_en_las_4_replicas_con_certificado(tmp_path):
    red = Red(tmp_path)
    red.enviar_tx(_tx())
    red.tick()
    assert red.alturas() == {"r0": 1, "r1": 1, "r2": 1, "r3": 1}
    hashes = {bc.last_block.hash for bc in red.cadenas.values()}
    assert len(hashes) == 1
    for bc in red.cadenas.values():
        b = bc.last_block
        assert b.header.difficulty == 0 and b.header.nonce == 0
        cert = bc.certificates[1]
        assert len(cert["commits"]) == 3 and cert["view"] == 0
        assert red.rs.check_commit_certificate(cert, b.hash, 1) == (True, "OK")
        assert not bc.mempool
    # El primario no envía PREPARE: su PRE-PREPARE cuenta como su voto (§4.2).
    slotless = red.replicas["r0"].status()
    assert slotless["last_committed_seq"] == 1 and slotless["primary"] == "r0"


def test_una_replica_caida_f1_igual_confirma(tmp_path):
    red = Red(tmp_path)
    red.net.down = {"r3"}
    red.enviar_tx(_tx())
    red.tick()
    assert red.alturas() == {"r0": 1, "r1": 1, "r2": 1}


def test_dos_replicas_caidas_no_hay_commit_pero_tampoco_bifurcacion(tmp_path):
    red = Red(tmp_path)
    red.net.down = {"r2", "r3"}
    red.enviar_tx(_tx())
    for _ in range(6):
        red.tick(avanzar=6.0)        # varios temporizadores y cambios de vista fallidos
    assert red.alturas() == {"r0": 0, "r1": 0}
    assert all(not bc.certificates for bc in red.cadenas.values())


def test_primario_caido_cambio_de_vista_y_el_nuevo_primario_confirma(tmp_path):
    red = Red(tmp_path, timeout=5.0)
    red.net.down = {"r0"}
    red.enviar_tx(_tx())
    red.tick()                       # arranca el temporizador
    assert red.alturas() == {"r1": 0, "r2": 0, "r3": 0}
    red.tick(avanzar=5.1)            # vence: VIEW-CHANGE → NEW-VIEW (r1)
    red.tick()                       # r1 propone en la vista 1
    assert red.alturas() == {"r1": 1, "r2": 1, "r3": 1}
    for rid in ("r1", "r2", "r3"):
        r = red.replicas[rid]
        assert r.view == 1 and r.primary == "r1" and r.view_changes_total == 1
        assert red.cadenas[rid].certificates[1]["view"] == 1


def test_bloque_preparado_se_repropone_tras_el_cambio_de_vista(tmp_path):
    """r0 logra 'prepared' en r1..r3 pero los COMMIT se pierden; el nuevo primario
    debe re-proponer EL MISMO bloque (certificados prepared del VIEW-CHANGE)."""
    red = Red(tmp_path)
    red.enviar_tx(_tx())
    original = red.net.sender

    # Interceptar: descartar todos los COMMIT de esta ronda.
    def sin_commits(src):
        envio = original(src)
        return lambda m: None if m["type"] == COMMIT else envio(m)
    for rid, r in red.replicas.items():
        r._send = sin_commits(rid)
    red.tick()
    assert red.alturas() == {"r0": 0, "r1": 0, "r2": 0, "r3": 0}
    propuesto = next(iter(red.replicas["r1"]._slots.values())).digest
    for rid, r in red.replicas.items():
        r._send = original(rid)
    red.net.down = {"r0"}
    red.tick(avanzar=5.1)
    red.tick()
    assert red.alturas() == {"r1": 1, "r2": 1, "r3": 1}
    assert all(bc.last_block.hash == propuesto for rid, bc in red.cadenas.items() if rid != "r0")


# ── Mensajes falsificados y equivocación ─────────────────────────────────────

def test_mensajes_falsificados_o_de_desconocidos_se_ignoran(tmp_path):
    red = Red(tmp_path)
    r1 = red.replicas["r1"]
    bloque = red.cadenas["r0"].create_candidate_block([_tx()])
    pp = sign_message({"type": PRE_PREPARE, "replica": "r0", "view": 0, "seq": 1,
                       "digest": bloque.hash}, Wallet.generate().private_key_hex)  # llave ajena
    pp["block"] = bloque.to_dict()
    assert r1.receive(pp) is False
    intruso = sign_message({"type": COMMIT, "replica": "intruso", "view": 0, "seq": 1,
                            "digest": bloque.hash}, Wallet.generate().private_key_hex)
    assert r1.receive(intruso) is False
    # Firma válida, pero r2 no es el primario de la vista 0.
    falso_primario = red.firmar(2, type=PRE_PREPARE, view=0, seq=1, digest=bloque.hash)
    falso_primario["block"] = bloque.to_dict()
    r1.receive(falso_primario)
    # Malformado (vista no entera): se descarta antes de mirar la firma.
    assert r1.receive({"type": COMMIT, "replica": "r2", "view": "0", "seq": 1,
                       "digest": bloque.hash}) is False
    assert r1.rejected_messages == 4
    assert not r1._slots and red.alturas()["r1"] == 0


def test_primario_que_equivoca_no_logra_dos_bloques_y_se_alerta(tmp_path):
    red = Red(tmp_path, iniciar=["r1", "r2", "r3"])     # r0 = primario bizantino
    tx = _tx()
    red.enviar_tx(tx)
    base = red.cadenas["r1"].create_candidate_block([tx])
    otro_h = BlockHeader(**{**base.header.__dict__, "timestamp": base.header.timestamp + 1})
    a, b = base, Block(header=otro_h, transactions=base.transactions)
    assert a.hash != b.hash

    def pp(bloque):
        m = red.firmar(0, type=PRE_PREPARE, view=0, seq=1, digest=bloque.hash)
        m["block"] = bloque.to_dict()
        return m
    red.replicas["r1"].receive(pp(a))
    red.replicas["r1"].receive(pp(b))
    for rid in ("r2", "r3"):
        red.replicas[rid].receive(pp(b))
        red.replicas[rid].receive(pp(a))
    for rid in ("r1", "r2", "r3"):
        tipos = [x["event_type"] for x in red.monitores[rid].get_alerts()]
        assert "PBFT_EQUIVOCATION" in tipos, rid
    assert red.alturas() == {"r1": 0, "r2": 0, "r3": 0}  # B: solo 2 COMMIT (r2, r3)
    red.tick()
    red.tick(avanzar=5.1)                               # cambio de vista: r1 re-propone B
    red.tick()
    assert red.alturas() == {"r1": 1, "r2": 1, "r3": 1}
    assert {bc.last_block.hash for bc in red.cadenas.values()} == {b.hash}


# ── Certificados en la cadena ─────────────────────────────────────────────────

def _cadena_confirmada(tmp_path):
    red = Red(tmp_path)
    red.enviar_tx(_tx())
    red.tick()
    return red


def test_validez_de_bloque_en_modo_pbft(tmp_path):
    red = _cadena_confirmada(tmp_path)
    bc = red.cadenas["r0"]
    cand = bc.create_candidate_block([_tx(1)])
    assert cand.header.difficulty == 0 and bc.check_block(cand) == (True, "OK")
    con_nonce = Block(header=BlockHeader(**{**cand.header.__dict__, "nonce": 7}),
                      transactions=cand.transactions)
    assert "nonce" in bc.check_block(con_nonce)[1]
    con_dif = Block(header=BlockHeader(**{**cand.header.__dict__, "difficulty": 4}),
                    transactions=cand.transactions)
    assert "Dificultad" in bc.check_block(con_dif)[1]
    ok, motivo = bc.add_block(cand)                       # sin certificado
    assert not ok and "certificado" in motivo.lower()

    def cert(firmantes, digest=cand.hash, seq=2):
        return {"view": 0, "seq": seq, "digest": digest,
                "commits": [red.firmar(i, type=COMMIT, view=0, seq=seq, digest=digest)
                            for i in firmantes]}
    assert "2 firmas" in bc.add_block(cand, cert([0, 1]))[1]
    assert "repetido" in bc.add_block(cand, cert([0, 1, 1]))[1]
    assert "otro bloque" in bc.add_block(cand, cert([0, 1, 2], digest="00" * 32))[1]
    falso = cert([0, 1])
    falso["commits"].append(sign_message({"type": COMMIT, "replica": "r2", "view": 0, "seq": 2,
                                          "digest": cand.hash}, Wallet.generate().private_key_hex))
    assert "firma inválida" in bc.add_block(cand, falso)[1]
    assert bc.add_block(cand, cert([1, 2, 3])) == (True, "OK")
    assert bc.height == 2


def test_genesis_identico_en_ambos_modos(tmp_path):
    red = Red(tmp_path, iniciar=["r0"])
    pow_bc = Blockchain(node_id="p", data_dir=str(tmp_path / "pow"))
    assert red.cadenas["r0"].chain[0].hash == pow_bc.chain[0].hash


def test_nodo_tardio_verifica_certificados_al_sincronizar(tmp_path):
    red = _cadena_confirmada(tmp_path)
    fuente = red.cadenas["r1"]
    datos = [b.to_dict() for b in fuente.chain]
    nuevo = Blockchain(node_id="obs", data_dir=str(tmp_path / "obs"), consensus="pbft",
                       replica_set=red.rs)
    ok, motivo = nuevo.replace_chain(datos)                  # sin certificados
    assert not ok and "certificados" in motivo
    malo = {1: {**fuente.certificates[1], "commits": fuente.certificates[1]["commits"][:2]}}
    assert not nuevo.replace_chain(datos, malo)[0]
    assert nuevo.replace_chain(datos, {"1": fuente.certificates[1]}) == (True, "OK")
    assert nuevo.height == 1 and nuevo.certificates[1] == fuente.certificates[1]
    # Reinicio: los certificados se leen de chain.db y se vuelven a verificar.
    nuevo.close()
    otra = Blockchain(node_id="obs", data_dir=str(tmp_path / "obs"), consensus="pbft",
                      replica_set=red.rs)
    assert otra.height == 1 and otra.certificates[1] == fuente.certificates[1]


def test_certificado_alterado_en_disco_impide_arrancar(tmp_path):
    import json
    import sqlite3
    red = _cadena_confirmada(tmp_path)
    bc = red.cadenas["r2"]
    bc.close()
    conn = sqlite3.connect(str(tmp_path / "r2" / "chain.db"))
    with conn:
        cert = json.loads(conn.execute("SELECT data FROM certificates").fetchone()[0])
        cert["commits"] = cert["commits"][:1]
        conn.execute("UPDATE certificates SET data = ?", (json.dumps(cert),))
    conn.close()
    with pytest.raises(ValueError, match="pbft"):
        Blockchain(node_id="r2", data_dir=str(tmp_path / "r2"), consensus="pbft",
                   replica_set=red.rs)


def test_cadena_pow_no_carga_en_modo_pbft(tmp_path):
    from tests.helpers import mine_and_add
    pow_bc = Blockchain(node_id="p", data_dir=str(tmp_path / "pow"), initial_difficulty=1)
    assert mine_and_add(pow_bc)[0]
    pow_bc.close()
    red = Red(tmp_path, iniciar=[])
    with pytest.raises(ValueError, match="pbft"):
        Blockchain(node_id="p", data_dir=str(tmp_path / "pow"), consensus="pbft",
                   replica_set=red.rs)


def test_dos_bloques_certificados_en_la_misma_altura_alerta_critica(tmp_path):
    red = _cadena_confirmada(tmp_path)
    bc = red.cadenas["r1"]
    # Más de f réplicas bizantinas (aquí: la prueba tiene todas las llaves) certifican otro bloque.
    otra = Blockchain(node_id="x", data_dir=str(tmp_path / "x"), consensus="pbft",
                      replica_set=red.rs)
    y = otra.create_candidate_block([_tx(9)])
    cert_y = {"view": 0, "seq": 1, "digest": y.hash,
              "commits": [red.firmar(i, type=COMMIT, view=0, seq=1, digest=y.hash)
                          for i in range(3)]}
    assert otra.add_block(y, cert_y)[0]
    ok, motivo = bc.replace_chain([b.to_dict() for b in otra.chain], {1: cert_y})
    assert not ok and "Conflicto PBFT" in motivo
    alertas = [a for a in red.monitores["r1"].get_alerts() if a["event_type"] == "PBFT_CONFLICT"]
    assert alertas and str(alertas[0]["level"].value if hasattr(alertas[0]["level"], "value")
                           else alertas[0]["level"]) == "CRITICAL"
    assert bc.height == 1 and bc.last_block.hash != y.hash


# ── Réplica rezagada: ponerse al día con el certificado de commit ─────────────

def _sin_commits_para_r0(enviados):
    """Pierde todo COMMIT de la altura 1 dirigido a r0 y anota los tipos enviados."""
    def drop(src, dst, m):
        enviados.append((src, m["type"]))
        return dst == "r0" and m["type"] == COMMIT and m.get("seq") == 1
    return drop


def test_primario_que_pierde_los_commit_se_pone_al_dia_sin_cambio_de_vista(tmp_path):
    """Regresión: antes r0 se quedaba en la altura 0 (solo la sincronización periódica,
    ~15 s, lo sacaba) y a los 5 s lanzaba un VIEW-CHANGE solitario que nadie seguía."""
    red = Red(tmp_path, timeout=5.0)
    enviados = []
    red.net.drop = _sin_commits_para_r0(enviados)
    red.enviar_tx(_tx())
    red.tick()
    assert red.alturas() == {"r0": 0, "r1": 1, "r2": 1, "r3": 1}
    inicio = red.reloj.t
    while red.cadenas["r0"].height < 1 and red.reloj.t - inicio < 15.0:
        red.tick(avanzar=0.1)
    assert red.cadenas["r0"].height == 1
    assert red.reloj.t - inicio < 2.0
    bc0 = red.cadenas["r0"]
    assert bc0.last_block.hash == red.cadenas["r1"].last_block.hash
    assert red.rs.check_commit_certificate(bc0.certificates[1], bc0.last_block.hash, 1)[0]
    assert ("r0", CERT_REQUEST) in enviados
    assert not [m for m in enviados if m[1] == VIEW_CHANGE]
    for r in red.replicas.values():
        assert r.view == 0 and not r.in_view_change and r.view_changes_total == 0
    assert red.replicas["r0"].caught_up_blocks == 1
    # Sigue siendo el primario y el siguiente bloque se confirma en las 4.
    red.net.drop = None
    red.enviar_tx(_tx(1))
    red.tick()
    assert red.alturas() == {"r0": 2, "r1": 2, "r2": 2, "r3": 2}


def test_view_change_de_una_replica_atrasada_recibe_el_certificado(tmp_path):
    """Si los CERT-REQUEST también se pierden, el VIEW-CHANGE de la rezagada (altura
    menor) lo contestan las demás con el bloque y su certificado. El VIEW-CHANGE ya
    enviado no se retira (seguridad, §4.4): r0 se une a la vista 1 con la siguiente TX."""
    red = Red(tmp_path, timeout=5.0)
    commits = _sin_commits_para_r0([])
    red.net.drop = lambda s, d, m: commits(s, d, m) or m["type"] == CERT_REQUEST
    red.enviar_tx(_tx())
    red.tick()
    for _ in range(52):
        red.tick(avanzar=0.1)                    # vence el temporizador de r0 (5 s)
    r0 = red.replicas["r0"]
    assert red.cadenas["r0"].height == 1 and r0.in_view_change
    assert all(red.replicas[r].view == 0 and not red.replicas[r].in_view_change
               for r in ("r1", "r2", "r3"))
    red.net.drop = None
    red.enviar_tx(_tx(1))
    for _ in range(200):
        red.tick(avanzar=0.1)
        if set(red.alturas().values()) == {2}:
            break
    assert red.alturas() == {"r0": 2, "r1": 2, "r2": 2, "r3": 2}
    assert len({bc.last_block.hash for bc in red.cadenas.values()}) == 1


def test_certificado_falso_o_insuficiente_en_la_puesta_al_dia_se_rechaza(tmp_path):
    red = Red(tmp_path)
    red.net.drop = _sin_commits_para_r0([])
    red.enviar_tx(_tx())
    red.tick()                                   # sin avanzar el reloj: r0 sigue atrasado
    r0, bc1 = red.replicas["r0"], red.cadenas["r1"]
    assert red.cadenas["r0"].height == 0
    bloque, bueno = bc1.chain[1], bc1.certificates[1]

    def commit(i, digest=bloque.hash, llave=None):
        return sign_message({"type": COMMIT, "replica": red.ids[i], "view": 0, "seq": 1,
                             "digest": digest}, llave or red.wallets[i].private_key_hex)

    def respuesta(cert, de=1, blk=bloque):
        m = red.firmar(de, type=CERT_REPLY, view=0, seq=1, digest=blk.hash, tip=1,
                       certificate=cert)
        m["block"] = blk.to_dict()
        return m

    def cert(commits, digest=bloque.hash):
        return {"view": 0, "seq": 1, "digest": digest, "commits": commits}
    falsos = {
        "solo f firmas": cert([commit(1)]),
        "2f firmas": cert([commit(1), commit(2)]),
        "firmante repetido": cert([commit(1), commit(2), commit(2)]),
        "llave desconocida": cert([commit(1), commit(2),
                                   commit(3, llave=Wallet.generate().private_key_hex)]),
        "otro hash": cert([commit(i, digest="00" * 32) for i in (1, 2, 3)], digest="00" * 32),
        "otra vista": {**bueno, "view": 1},
        "sin certificado": None,
    }
    for nombre, c in falsos.items():
        antes = r0.rejected_messages
        r0.receive(respuesta(c))
        assert red.cadenas["r0"].height == 0, nombre
        assert r0.rejected_messages == antes + 1, nombre
    # Bloque que no corresponde a su digest (con un certificado válido de otro bloque).
    m = respuesta(bueno)
    m["block"] = {**bloque.to_dict(), "transactions": []}
    r0.receive(m)
    # Firmado por quien no es réplica: se descarta antes de mirar el certificado.
    intruso = sign_message({"type": CERT_REPLY, "replica": "intruso", "view": 0, "seq": 1,
                            "digest": bloque.hash, "certificate": bueno},
                           Wallet.generate().private_key_hex)
    intruso["block"] = bloque.to_dict()
    assert r0.receive(intruso) is False
    assert red.cadenas["r0"].height == 0
    # El certificado verdadero (2f + 1 firmas válidas) sí se acepta, venga de quien venga.
    r0.receive(respuesta(bueno, de=3))
    assert red.cadenas["r0"].height == 1 and red.cadenas["r0"].last_block.hash == bloque.hash
