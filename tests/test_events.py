"""P2-7: bus de eventos y flujo SSE (todo con timeouts para no colgar)."""
import asyncio
import threading

import httpx

from api.events import EventBus, sse_stream
from blockchain.consensus.proof_of_work import ProofOfWork
from tests.helpers import make_app

T = 10.0


def run(coro):
    return asyncio.run(asyncio.wait_for(coro, 90))


def test_fanout_a_dos_suscriptores():
    async def main():
        bus = EventBus()
        a, b = bus.subscribe(), bus.subscribe()
        bus.publish("tx", {"n": 1})
        ea, eb = await a.get(T), await b.get(T)
        assert ea["event"] == eb["event"] == "tx" and ea["data"] == {"n": 1}
    run(main())


def test_cola_acotada_descarta_el_mas_viejo_sin_bloquear():
    async def main():
        bus = EventBus(maxlen=3)
        s = bus.subscribe()
        for i in range(10):
            bus.publish("tx", {"i": i})
        assert s.pending() == 3 and s.dropped == 7
        assert [(await s.get(T))["data"]["i"] for _ in range(3)] == [7, 8, 9]
        assert await s.get(0.05) is None
    run(main())


def test_publicar_desde_otro_hilo_despierta_al_suscriptor():
    async def main():
        bus = EventBus()
        s = bus.subscribe()
        threading.Thread(target=lambda: bus.publish("alert", {"x": 1})).start()
        assert (await s.get(T))["event"] == "alert"
    run(main())


def test_heartbeat_y_baja_al_desconectar():
    async def main():
        bus = EventBus()
        gen = sse_stream(bus, heartbeat=0.05)
        assert (await gen.__anext__()).startswith(": conectado")
        assert bus.subscriber_count() == 1
        assert (await gen.__anext__()) == ": hb\n\n"
        await gen.aclose()
        assert bus.subscriber_count() == 0
    run(main())


def test_dos_apps_tienen_buses_independientes(tmp_path):
    a, b = make_app(tmp_path, "a"), make_app(tmp_path, "b")
    assert a.state.node.events is not b.state.node.events


def test_progreso_no_cambia_el_resultado_minado(tmp_path):
    bc = make_app(tmp_path, "pow").state.node.blockchain
    c1, c2 = bc.create_candidate_block(), bc.create_candidate_block()
    c2.header.timestamp = c1.header.timestamp
    llamadas = []
    r1 = ProofOfWork().mine(c1, difficulty=14, timeout=60)
    r2 = ProofOfWork().mine(c2, difficulty=14, timeout=60,
                            on_progress=lambda n, t: llamadas.append(n))
    assert r1.nonce == r2.nonce and r1.hash == r2.hash
    assert len(llamadas) == r1.nonce // 4096   # un reporte cada 4096 intentos (nonce 0 no cuenta)


def test_minar_por_la_api_emite_progreso_y_bloque(tmp_path):
    app = make_app(tmp_path, "sse", mining_difficulty=16)
    node = app.state.node

    async def main():
        sub = node.events.subscribe()
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
            r = await asyncio.wait_for(c.post("/blocks/mine", json={}), 80)
            assert r.status_code == 200, r.text
        eventos, intentos = [], 0
        while (e := await sub.get(0.2)) is not None:
            eventos.append(e["event"])
            if e["event"] == "mining_done":
                intentos = e["data"]["attempts"]
        assert "mining_done" in eventos and "block" in eventos
        if intentos > 4097:   # el progreso se reporta cada 4096 intentos
            assert eventos.count("mining_progress") >= 1
            assert eventos.index("mining_progress") < eventos.index("mining_done")
    run(main())


def test_endpoint_events_entrega_sse(tmp_path):
    """httpx ASGITransport no hace streaming: se llama al endpoint y se lee su cuerpo."""
    from api.app import events_stream
    app = make_app(tmp_path, "sse2")
    node = app.state.node

    class Peticion:
        async def is_disconnected(self):
            return False

    async def main():
        resp = await events_stream(Peticion(), node)
        assert resp.media_type == "text/event-stream"
        it = resp.body_iterator
        assert (await asyncio.wait_for(it.__anext__(), T)).startswith(": conectado")
        node.events.publish("reorg", {"dropped": 1})
        assert (await asyncio.wait_for(it.__anext__(), T)) == 'event: reorg\ndata: {"dropped": 1}\n\n'
        await it.aclose()
        assert node.events.subscriber_count() == 0
    run(main())


