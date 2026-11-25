"""Tests de P2-11 (parte 2): contratos de estudiantes en la cadena y por la API.

- despliegue y llamada: storage, recibos, gas cobrado y quemado, oferta total;
- REVERT / sin gas / error: TX válida, estado revertido, gas cobrado;
- TXs inválidas (bytecode mal formado, saldo para el gas, contrato inexistente…):
  400 en la API y bloque rechazado si se mina a mano;
- determinismo: replace_chain, recarga desde chain.db con fotos (P2-4);
- los tres ejemplos de ``contratos_estudiantes/`` de punta a punta por la API;
- ``POST /vm/simulate`` no cambia nada.
"""
import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from blockchain.contracts import programs
from blockchain.contracts.programs import CALL_BASE_GAS, contract_address, deploy_gas
from blockchain.core.chain import Blockchain
from blockchain.core.transaction import (
    Transaction, TransactionType, create_mint_transaction, create_transfer_transaction,
)
from blockchain.core.wallet import Wallet
from blockchain.vm import assemble
from blockchain.vm.asm import address_to_int
from tests.helpers import make_app, mine_and_add, mine_candidate

RAIZ = Path(__file__).resolve().parent.parent
EJEMPLOS = RAIZ / "contratos_estudiantes"


def fuente(nombre: str) -> str:
    return (EJEMPLOS / f"{nombre}.upbasm").read_text(encoding="utf-8")


def h(valor: int) -> int:
    return int.from_bytes(hashlib.sha256(valor.to_bytes(32, "big")).digest(), "big")


# ── A nivel de cadena ────────────────────────────────────────────────────────

def _cadena(directorio, autoridad, **kw) -> Blockchain:
    return Blockchain(f"nodo_{directorio.name}", str(directorio), initial_difficulty=1,
                      authority_address=autoridad.address, **kw)


def _firmar(tx: Transaction, wallet: Wallet) -> Transaction:
    tx.sign(wallet.private_key_hex)
    return tx


def deploy_tx(wallet, nonce, code: bytes, storage=None, gas_price=1, gas_limit=None, **cambios):
    code_hex = code.hex()
    payload = {"code": code_hex, "gas_price": gas_price,
               "gas_limit": gas_limit or deploy_gas(code_hex, storage)}
    if storage:
        payload["storage"] = storage
    payload.update(cambios.pop("payload", {}))
    tx = Transaction(type=TransactionType.CONTRACT_DEPLOY, sender=wallet.address,
                     recipient=cambios.pop("recipient", contract_address(wallet.address, nonce)),
                     payload=payload, nonce=nonce)
    return _firmar(tx, wallet)


def call_tx(wallet, nonce, contrato, args=(), value=0, gas_limit=10_000, gas_price=1):
    tx = Transaction(type=TransactionType.CONTRACT_CALL, sender=wallet.address,
                     recipient=contrato, nonce=nonce,
                     payload={"args": list(args), "value": value, "gas_limit": gas_limit,
                              "gas_price": gas_price})
    return _firmar(tx, wallet)


def _minar(bc, txs):
    for tx in txs:
        ok, why = bc.add_transaction(tx)
        assert ok, why
    ok, why = mine_and_add(bc)
    assert ok, why


def _oferta_cuadra(bc):
    cuentas, vm = bc.accounts, bc.contract_state("vm")
    contratos = sum(c["balance"] for c in vm.contracts.values())
    assert sum(cuentas.balances.values()) + contratos == cuentas.total_supply


@pytest.fixture
def red(tmp_path):
    autoridad, ana, beto = Wallet.generate(), Wallet.generate(), Wallet.generate()
    bc = _cadena(tmp_path / "a", autoridad)
    _minar(bc, [create_mint_transaction(autoridad.address, ana.address, 100_000,
                                        autoridad.private_key_hex, nonce=1),
                create_mint_transaction(autoridad.address, beto.address, 100_000,
                                        autoridad.private_key_hex, nonce=2)])
    return SimpleNamespace(bc=bc, autoridad=autoridad, ana=ana, beto=beto, tmp=tmp_path)


CONTADOR = assemble(fuente("contador"))


@pytest.mark.integration
def test_desplegar_y_llamar_cobra_gas_y_cambia_storage(red):
    bc, ana = red.bc, red.ana
    _minar(bc, [deploy_tx(ana, 1, CONTADOR, gas_price=2)])
    addr = contract_address(ana.address, 1)
    costo_deploy = deploy_gas(CONTADOR.hex(), None) * 2
    assert bc.get_balance(ana.address) == 100_000 - costo_deploy
    llamada = call_tx(ana, 2, addr, args=[5], gas_price=3)
    _minar(bc, [llamada])
    vm = bc.contract_state("vm")
    assert vm.contracts[addr]["storage"] == {0: 5}
    recibo = vm.receipts[llamada.tx_id]
    assert recibo["status"] == "ok" and recibo["return_value"] == 5
    assert recibo["cost"] == recibo["gas_used"] * 3 and recibo["gas_used"] > CALL_BASE_GAS
    assert bc.get_balance(ana.address) == 100_000 - costo_deploy - recibo["cost"]
    assert bc.accounts.burned_fees == costo_deploy + recibo["cost"] == vm.gas_burned
    assert vm.logs[addr][0]["value"] == 5 and vm.logs[addr][0]["block_index"] == bc.height
    _oferta_cuadra(bc)


REVIERTE = assemble("PUSH 7\nSSTORE 1\nLOG 1\nARG 0\nJUMPI falla\nSTOP\nfalla: REVERT 9")


@pytest.mark.integration
def test_revert_es_valida_revierte_y_cobra_lo_usado(red):
    bc, ana = red.bc, red.ana
    _minar(bc, [deploy_tx(ana, 1, REVIERTE)])
    addr = contract_address(ana.address, 1)
    antes = bc.get_balance(ana.address)
    tx = call_tx(ana, 2, addr, args=[1], value=500, gas_limit=5_000)
    _minar(bc, [tx])                                  # el bloque es válido
    vm = bc.contract_state("vm")
    recibo = vm.receipts[tx.tx_id]
    assert recibo["status"] == "revert" and recibo["error"] == "REVERT 9"
    assert recibo["gas_used"] < 5_000
    assert vm.contracts[addr]["storage"] == {} and addr not in vm.logs
    assert vm.contracts[addr]["balance"] == 0          # value no se movió
    assert bc.get_balance(ana.address) == antes - recibo["gas_used"]
    assert bc.accounts.nonce_of(ana.address) == 2      # consumió nonce
    _oferta_cuadra(bc)


@pytest.mark.integration
def test_sin_gas_y_error_cobran_todo_el_gas_limit(red):
    bc, ana = red.bc, red.ana
    bucle = assemble("PUSH 1\nSSTORE 1\nbucle:\nJUMP bucle")
    divide = assemble("PUSH 1\nPUSH 0\nDIV\nSTOP")
    _minar(bc, [deploy_tx(ana, 1, bucle), deploy_tx(ana, 2, divide)])
    antes = bc.get_balance(ana.address)
    t1 = call_tx(ana, 3, contract_address(ana.address, 1), gas_limit=3_000, gas_price=2)
    t2 = call_tx(ana, 4, contract_address(ana.address, 2), gas_limit=1_000)
    _minar(bc, [t1, t2])
    vm = bc.contract_state("vm")
    assert vm.receipts[t1.tx_id]["status"] == "error" and "sin gas" in vm.receipts[t1.tx_id]["error"]
    assert vm.receipts[t1.tx_id]["gas_used"] == 3_000
    assert vm.receipts[t2.tx_id]["error"] == "división por cero"
    assert vm.contracts[contract_address(ana.address, 1)]["storage"] == {}
    assert bc.get_balance(ana.address) == antes - 3_000 * 2 - 1_000
    _oferta_cuadra(bc)


@pytest.mark.integration
def test_txs_invalidas_rechazan_el_bloque(red):
    bc, ana = red.bc, red.ana
    _minar(bc, [deploy_tx(ana, 1, CONTADOR)])
    addr = contract_address(ana.address, 1)
    pobre = Wallet.generate()
    invalidas = {
        "bytecode mal formado": deploy_tx(ana, 2, bytes([0xEE])),
        "PUSH truncado": deploy_tx(ana, 2, bytes([0x60, 5, 1])),
        "recipient ajeno": deploy_tx(ana, 2, CONTADOR, recipient=addr),
        "gas_limit corto": deploy_tx(ana, 2, CONTADOR, gas_limit=10),
        "saldo para el gas": call_tx(ana, 2, addr, gas_limit=150_000, gas_price=1),
        "sin saldo": call_tx(pobre, 1, addr),
        "contrato inexistente": call_tx(ana, 2, "UPC" + "0" * 32),
        "gas_price 0": call_tx(ana, 2, addr, gas_price=0),
        "gas_limit < base": call_tx(ana, 2, addr, gas_limit=CALL_BASE_GAS - 1),
        "arg negativo": call_tx(ana, 2, addr, args=[-1]),
        "PUPB directo a un contrato": create_transfer_transaction(
            ana.address, addr, 5, ana.private_key_hex, nonce=2),
    }
    for nombre, tx in invalidas.items():
        ok, _ = bc.add_transaction(tx)
        assert not ok, nombre
        ok, why = bc.add_block(mine_candidate(bc, [tx]))
        assert not ok and "inválida" in why, nombre


@pytest.mark.integration
def test_altura_del_mempool_es_la_del_proximo_bloque(red):
    """El minero simula BLOCKHEIGHT con la altura que verá la red (no con 0)."""
    bc, ana, beto = red.bc, red.ana, red.beto
    # Paga 50 a quien llama solo si la altura es par. La TX siguiente de "pobre" solo
    # alcanza con esos 50: si el minero simulara con otra altura, la descartaría.
    paga = assemble("BLOCKHEIGHT; MOD 2; JUMPI fin; PUSH 50; CALLER; TRANSFER; fin: STOP"
                    .replace("; ", "\n"))
    pobre = Wallet.generate()
    _minar(bc, [deploy_tx(ana, 1, paga),
                create_transfer_transaction(beto.address, pobre.address, 400,
                                            beto.private_key_hex, nonce=1)])
    addr = contract_address(ana.address, 1)
    _minar(bc, [call_tx(ana, 2, addr, value=1000)])          # fondea el contrato
    if (bc.height + 1) % 2:
        _minar(bc, [])
    gas = programs.call_code(paga.hex(), storage={}, caller=address_to_int(pobre.address),
                             block_height=bc.height + 1, balance=1000, gas_limit=300).gas_used
    t1 = call_tx(pobre, 1, addr, gas_limit=300)
    t2 = create_transfer_transaction(pobre.address, beto.address, 400 - gas + 50,
                                     pobre.private_key_hex, nonce=2)
    for tx in (t1, t2):
        ok, why = bc.add_transaction(tx)                     # t2 vale solo si t1 paga 50
        assert ok, why
    ok, why = mine_and_add(bc)
    assert ok, why
    assert len(bc.last_block.transactions) == 2
    assert bc.get_balance(pobre.address) == 0
    assert bc.contract_state("vm").receipts[t1.tx_id]["transfers"] == [[pobre.address, 50]]


def _actividad(bc, ana, beto):
    _minar(bc, [deploy_tx(ana, 1, CONTADOR, storage=[[9, 1]]), deploy_tx(beto, 1, REVIERTE)])
    a1, b1 = contract_address(ana.address, 1), contract_address(beto.address, 1)
    _minar(bc, [call_tx(ana, 2, a1, args=[3]), call_tx(beto, 2, b1, args=[1], value=7),
                call_tx(beto, 3, b1, args=[0], value=11)])
    _minar(bc, [call_tx(ana, 3, a1), call_tx(beto, 4, a1, args=[2 ** 255])])


def _estado(bc):
    return bc.contracts.dump_states({n: bc.contract_state(n) for n in bc.contracts.names})


@pytest.mark.integration
def test_determinismo_replace_chain_y_recarga_con_fotos(red):
    bc = Blockchain("f", str(red.tmp / "f"), initial_difficulty=1,
                    authority_address=red.autoridad.address, snapshot_interval=2)
    _minar(bc, [create_mint_transaction(red.autoridad.address, w.address, 100_000,
                                        red.autoridad.private_key_hex, nonce=n)
                for n, w in ((1, red.ana), (2, red.beto))])
    _actividad(bc, red.ana, red.beto)
    esperado = _estado(bc)
    vm = bc.contract_state("vm")
    assert vm.contracts[contract_address(red.ana.address, 1)]["storage"] == {9: 1, 0: 4 + 2 ** 255}
    assert vm.contracts[contract_address(red.beto.address, 1)]["balance"] == 11
    # Otro nodo por replace_chain.
    otro = _cadena(red.tmp / "otro", red.autoridad)
    ok, why = otro.replace_chain([b.to_dict() for b in bc.chain])
    assert ok, why
    assert _estado(otro) == esperado
    # Recarga desde chain.db: con foto (rápida) y reproduciendo todo.
    assert [s.height for s in bc.store.snapshots()]
    bc.close()
    rapida = Blockchain("r", str(red.tmp / "f"), initial_difficulty=1,
                        authority_address=red.autoridad.address, snapshot_interval=2)
    assert rapida.replayed_on_start < rapida.height
    completa = Blockchain("c", str(red.tmp / "f"), initial_difficulty=1,
                          authority_address=red.autoridad.address, snapshot_interval=2,
                          revalidate_on_start="full")
    assert _estado(rapida) == _estado(completa) == esperado
    # La foto conserva las claves de storage como int.
    assert 9 in rapida.contract_state("vm").contracts[contract_address(red.ana.address, 1)]["storage"]
    _oferta_cuadra(rapida)


@pytest.mark.unit
def test_foto_json_ida_y_vuelta():
    c = programs.ProgramContract()
    s = programs.VmState(contracts={"UPCX": {"creator": "a", "code": "00", "storage": {2 ** 200: 1, 3: 4},
                                             "balance": 1, "deployed_at": 1, "calls": 0}})
    import json
    vuelta = c.state_from_json(json.loads(json.dumps(c.state_to_json(s))))
    assert vuelta == s and list(vuelta.contracts["UPCX"]["storage"]) == [2 ** 200, 3]


# ── Por la API: los ejemplos de contratos_estudiantes ────────────────────────

@pytest.fixture
def nodo(tmp_path):
    autoridad = Wallet.generate()
    app = make_app(tmp_path, autoridad=autoridad, mining_difficulty=1, tx_rate_limit=1000)
    return SimpleNamespace(app=app, bc=app.state.node.blockchain, autoridad=autoridad,
                           ana=Wallet.generate(), beto=Wallet.generate(), carla=Wallet.generate())


@pytest_asyncio.fixture
async def client(nodo):
    async with AsyncClient(transport=ASGITransport(app=nodo.app), base_url="http://test") as ac:
        yield ac


async def _ok(r):
    assert r.status_code == 200, r.text
    return r.json()


async def _minar_api(client):
    await _ok(await client.post("/blocks/mine", json={}))


async def _fondear(client, *wallets, monto=100_000):
    for w in wallets:
        await _ok(await client.post("/tokens/mint", json={"recipient": w.address, "amount": monto}))
    await _minar_api(client)


async def _desplegar(client, w, nombre, storage=()):
    r = await _ok(await client.post("/contracts/vm/deploy", json={
        "sender": w.address, "private_key_hex": w.private_key_hex,
        "source": fuente(nombre), "storage": [list(p) for p in storage]}))
    assert "desuso" in r["warning"]
    await _minar_api(client)
    return r["address"]


async def _llamar(client, w, contrato, args=(), value=0):
    r = await _ok(await client.post("/contracts/vm/call", json={
        "sender": w.address, "private_key_hex": w.private_key_hex, "contract": contrato,
        "args": list(args), "value": value}))
    return r["tx_id"]


async def _recibo(client, tx_id):
    return await _ok(await client.get(f"/contracts/vm/receipts/{tx_id}"))


async def _saldo(client, w):
    return (await _ok(await client.get(f"/accounts/{w.address}")))["balance"]


@pytest.mark.integration
async def test_ejemplo_contador(client, nodo):
    await _fondear(client, nodo.ana)
    addr = await _desplegar(client, nodo.ana, "contador")
    t1 = await _llamar(client, nodo.ana, addr)
    t2 = await _llamar(client, nodo.ana, addr, args=[5])
    await _minar_api(client)
    assert (await _recibo(client, t1))["return_value"] == 1
    assert (await _recibo(client, t2))["return_value"] == 6
    info = await _ok(await client.get(f"/contracts/vm/{addr}"))
    assert info["storage"] == [[0, 6]] and [l["value"] for l in info["logs"]] == [1, 6]
    assert "NARGS" in info["disassembly"] and info["calls"] == 2
    assert (await _ok(await client.get(f"/contracts/vm/{addr}/storage/0")))["value"] == 6
    lista = await _ok(await client.get("/contracts/vm"))
    assert [c["address"] for c in lista["contracts"]] == [addr]


@pytest.mark.integration
async def test_ejemplo_colecta_exitosa_y_fallida(client, nodo):
    bc = nodo.bc
    await _fondear(client, nodo.ana, nodo.beto, nodo.carla)
    plazo = bc.height + 4
    addr = await _desplegar(client, nodo.carla, "colecta",
                            [[0, nodo.carla.address], [1, 100], [2, plazo]])
    ta = await _llamar(client, nodo.ana, addr, args=[1], value=60)
    tb = await _llamar(client, nodo.beto, addr, args=[1], value=50)
    tc = await _llamar(client, nodo.carla, addr, args=[2])           # antes del plazo
    await _minar_api(client)
    assert (await _recibo(client, ta))["status"] == "ok"
    assert (await _recibo(client, tc))["error"] == "REVERT 13"
    info = await _ok(await client.get(f"/contracts/vm/{addr}"))
    assert info["balance"] == 110
    while bc.height + 1 < plazo:
        await _minar_api(client)
    tarde = await _llamar(client, nodo.ana, addr, args=[1], value=5)  # ya cerró
    robo = await _llamar(client, nodo.ana, addr, args=[2])            # no es beneficiaria
    reemb = await _llamar(client, nodo.ana, addr, args=[3])           # se llegó a la meta
    antes = await _saldo(client, nodo.carla)
    cobro = await _llamar(client, nodo.carla, addr, args=[2])
    await _minar_api(client)
    assert [(await _recibo(client, t))["error"] for t in (tarde, robo, reemb)] == \
        ["REVERT 10", "REVERT 12", "REVERT 15"]
    recibo = await _recibo(client, cobro)
    assert recibo["status"] == "ok" and recibo["transfers"] == [[nodo.carla.address, 110]]
    assert await _saldo(client, nodo.carla) == antes + 110 - recibo["cost"]
    assert (await _ok(await client.get(f"/contracts/vm/{addr}")))["balance"] == 0

    # Colecta que no llega a la meta: cada uno recupera lo suyo.
    plazo = bc.height + 3
    addr = await _desplegar(client, nodo.carla, "colecta",
                            [[0, nodo.carla.address], [1, 1000], [2, plazo]])
    await _llamar(client, nodo.ana, addr, args=[1], value=70)
    await _minar_api(client)
    while bc.height + 1 < plazo:
        await _minar_api(client)
    antes = await _saldo(client, nodo.ana)
    t1 = await _llamar(client, nodo.ana, addr, args=[3])
    t2 = await _llamar(client, nodo.beto, addr, args=[3])             # no aportó
    t3 = await _llamar(client, nodo.carla, addr, args=[2])            # sin meta
    await _minar_api(client)
    r1 = await _recibo(client, t1)
    assert r1["transfers"] == [[nodo.ana.address, 70]]
    assert await _saldo(client, nodo.ana) == antes + 70 - r1["cost"]
    assert (await _recibo(client, t2))["error"] == "REVERT 16"
    assert (await _recibo(client, t3))["error"] == "REVERT 14"
    _oferta_cuadra(bc)


@pytest.mark.integration
async def test_ejemplo_acertijo_primeros_n(client, nodo):
    await _fondear(client, nodo.ana, nodo.beto, nodo.carla)
    addr = await _desplegar(client, nodo.ana, "acertijo", [[0, h(42)], [1, 10], [2, 2]])
    await _llamar(client, nodo.ana, addr, value=30)                   # fondea
    await _minar_api(client)
    antes = await _saldo(client, nodo.beto)
    mal = await _llamar(client, nodo.beto, addr, args=[41])
    bien = await _llamar(client, nodo.beto, addr, args=[42])
    otra = await _llamar(client, nodo.beto, addr, args=[42])          # ya ganó
    carla = await _llamar(client, nodo.carla, addr, args=[42])
    ana = await _llamar(client, nodo.ana, addr, args=[42])            # sin cupos
    await _minar_api(client)
    errores = [(await _recibo(client, t))["error"] for t in (mal, bien, otra, carla, ana)]
    assert errores == ["REVERT 21", "", "REVERT 22", "", "REVERT 20"]
    costo = sum([(await _recibo(client, t))["cost"] for t in (mal, bien, otra)])
    assert await _saldo(client, nodo.beto) == antes + 10 - costo
    info = await _ok(await client.get(f"/contracts/vm/{addr}"))
    assert info["balance"] == 10
    assert 2 not in {k for k, _ in info["storage"]}                   # CUPOS = 0: casilla borrada
    assert [l["value"] for l in info["logs"]] == [address_to_int(nodo.beto.address),
                                                  address_to_int(nodo.carla.address)]


@pytest.mark.integration
async def test_api_rechaza_invalidas_con_400(client, nodo):
    await _fondear(client, nodo.ana)
    base = {"sender": nodo.ana.address, "private_key_hex": nodo.ana.private_key_hex}
    r = await client.post("/contracts/vm/deploy", json={**base, "code": "ee"})
    assert r.status_code == 400 and "bytecode inválido" in r.text
    r = await client.post("/contracts/vm/deploy", json={**base, "source": "PUHS 1"})
    assert r.status_code == 400 and "línea 1" in r.text
    r = await client.post("/contracts/vm/deploy", json={**base, "source": "STOP", "code": "00"})
    assert r.status_code == 400
    r = await client.post("/contracts/vm/call", json={**base, "contract": "UPC" + "1" * 32})
    assert r.status_code == 400 and "inexistente" in r.text
    pobre = Wallet.generate()
    r = await client.post("/contracts/vm/deploy", json={
        "sender": pobre.address, "private_key_hex": pobre.private_key_hex, "code": "00"})
    assert r.status_code == 400 and "Saldo insuficiente" in r.text
    r = await client.post("/contracts/vm/call", json={**base, "contract": "UPC", "args": ["x"]})
    assert r.status_code == 400
    assert (await client.get("/contracts/vm/UPCNADA")).status_code == 404
    assert (await client.get("/contracts/vm/receipts/nada")).status_code == 404


@pytest.mark.integration
async def test_tx_firmada_en_el_cliente_por_post_transactions(client, nodo):
    await _fondear(client, nodo.ana)
    addr = await _desplegar(client, nodo.ana, "contador")
    tx = call_tx(nodo.ana, 2, addr, args=[4])
    d = tx.to_dict()
    await _ok(await client.post("/transactions", json={
        "type": "CONTRACT_CALL", "sender": d["sender"], "recipient": d["recipient"],
        "payload": d["payload"], "nonce": d["nonce"], "signature": d["signature"],
        "public_key": d["public_key"], "timestamp": d["timestamp"]}))
    await _minar_api(client)
    assert (await _recibo(client, tx.tx_id))["return_value"] == 4


@pytest.mark.integration
async def test_simulate_no_cambia_estado(client, nodo):
    await _fondear(client, nodo.ana)
    addr = await _desplegar(client, nodo.ana, "contador")
    altura, estado = nodo.bc.height, _estado(nodo.bc)
    r = await _ok(await client.post("/vm/simulate", json={"contract": addr, "args": [7]}))
    assert r["status"] == "ok" and r["return_value"] == 7 and r["storage"] == [[0, 7]]
    assert r["trace"][0]["op"] == "NARGS" and r["gas_used"] > CALL_BASE_GAS
    assert r["block_height"] == altura + 1
    r = await _ok(await client.post("/vm/simulate", json={
        "source": "bucle:\nJUMP bucle", "gas_limit": 20_000}))
    assert r["status"] == "error" and r["gas_used"] == 20_000 and r["trace_truncated"]
    r = await _ok(await client.post("/vm/simulate", json={
        "source": "CALLER\nRETURN", "caller": nodo.ana.address, "trace": False}))
    assert r["return_value"] == address_to_int(nodo.ana.address) and r["trace"] == []
    assert nodo.bc.height == altura and _estado(nodo.bc) == estado
    assert not nodo.bc.mempool
    assert (await client.post("/vm/simulate", json={"code": "ee"})).status_code == 400
    assert (await client.post("/vm/simulate", json={"contract": "UPCX"})).status_code == 404
    r = await _ok(await client.post("/vm/assemble", json={"source": fuente("contador")}))
    assert bytes.fromhex(r["code"]) == CONTADOR
