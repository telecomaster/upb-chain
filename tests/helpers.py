"""Utilidades de prueba: minar bloques válidos con dificultad baja (P0-3)."""
from blockchain.consensus.proof_of_work import ProofOfWork


def mine_candidate(bc, transactions=None):
    """Crea un candidato, lo mina con la dificultad esperada y lo devuelve (sin añadirlo)."""
    candidate = bc.create_candidate_block(transactions)
    result = ProofOfWork(difficulty=candidate.header.difficulty).mine(
        candidate, timeout=60.0, difficulty=candidate.header.difficulty
    )
    assert result is not None, "el minado de prueba falló"
    return result.block


def mine_and_add(bc, transactions=None):
    """Mina y añade el siguiente bloque; devuelve (ok, motivo)."""
    return bc.add_block(mine_candidate(bc, transactions))


# ── Apps de prueba (P2-9) ────────────────────────────────────────────────────

def make_settings(tmp_path, nombre="nodo", **valores):
    """``Settings`` de prueba: datos en ``tmp_path``, sin ``.env``, P2P en puerto efímero
    y sin llave de autoridad real (la ruta no existe)."""
    from config import build_settings
    base = dict(
        data_dir=str(tmp_path / nombre),
        authority_key_file=str(tmp_path / f"{nombre}_authority_no_existe.json"),
        node_id=nombre, node_port=0, mining_difficulty=1,
    )
    base.update(valores)
    return build_settings(False, **base)


def make_app(tmp_path, nombre="nodo", autoridad=None, **valores):
    """App con su propio ``NodeState`` (``app.state.node``) construida con ``create_app``.

    ``autoridad``: ``Wallet`` de prueba que sustituye a la autoridad del génesis (su llave
    se escribe en ``authority_key_file`` y la app la carga como en producción).
    """
    from api.app import create_app
    settings = make_settings(tmp_path, nombre, **valores)
    if autoridad is not None:
        autoridad.export(settings.authority_key_file)
    return create_app(settings, authority_address=autoridad.address if autoridad else None)


def reiniciar_nodo(app, autoridad=None):
    """Simula reiniciar el proceso: cadena y contratos nuevos desde el mismo directorio,
    en la misma app (el cliente HTTP de la prueba sigue apuntando a ella)."""
    from api.app import build_node
    app.state.node = build_node(app.state.node.settings,
                                autoridad.address if autoridad else None)
    return app.state.node


def usar_cadena(app, bc):
    """Sustituye la cadena de la app (y la del P2P) por ``bc`` ya construida."""
    node = app.state.node
    node.blockchain = bc
    node.p2p.blockchain = bc
    bc.add_reorg_listener(node.on_chain_reorg)
