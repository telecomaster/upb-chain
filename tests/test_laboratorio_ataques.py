"""Idea 1: laboratorio de ataques en vivo (nodo malicioso real contra nodos honestos reales).

Cada escenario levanta sus nodos en el mismo proceso con P2P real en loopback; las esperas
están acotadas dentro del laboratorio. Lo que se comprueba es lo que ven los nodos HONESTOS.
"""
import json

import pytest

from security.attacks import laboratorio as lab

pytestmark = [pytest.mark.integration, pytest.mark.security]


def test_doble_gasto_pow_con_mayoria_de_hash_reorganiza_y_borra_el_pago():
    # 95 % de los intentos de hash: abandonar (4 bloques atrás) es prácticamente imposible.
    r = lab.doble_gasto("pow", semilla=3, cuota=95, confirmaciones=1)
    assert r["liberada"] and r["exito_ataque"]
    assert r["pago_en_cadena_del_comercio"] is False
    assert r["robo_en_cadena_del_comercio"] is True
    assert r["saldo_comercio"] == 0 and r["saldo_complice"] == 100
    assert r["profundidad_reorg"] >= 1
    assert r["punta_comercio_antes"] != r["punta_comercio_despues"]
    assert any(a["tipo"] == "CHAIN_REORG" for a in r["alertas"])


def test_doble_gasto_pbft_falla_y_el_pago_sigue_certificado():
    r = lab.doble_gasto("pbft", semilla=1)
    assert r["exito_ataque"] is False
    assert r["pago_en_cadena_del_comercio"] is True
    assert r["robo_en_cadena_del_comercio"] is False
    assert r["certificado_del_pago"] == "OK"
    assert r["punta_sin_cambios"] and r["puntas_iguales"] and r["altura_honesta"] == 2
    assert r["altura_bifurcacion"] > r["altura_honesta"]           # la bifurcación era más larga
    assert "firma inválida" in r["motivo_rechazo_certificado_falso"]
    assert "se necesitan 3" in r["motivo_rechazo_solo_firma_propia"]
    assert r["saldo_comercio"] == 100 and r["saldo_complice"] == 0
    assert r["mensajes_pbft_rechazados"]["r1"] >= 2                # votos COMMIT falsificados
    assert any(a["tipo"] == "INVALID_BLOCK" for a in r["alertas"])


def test_sybil_con_tls_y_lista_blanca_se_rechaza_con_alerta_sin_tls_solo_avisa():
    r = lab.sybil("pow", identidades=3)
    con, sin = r["con_tls"], r["sin_tls"]
    assert r["exito_ataque"] is False
    assert con["aceptados"] == 0 and not any(i["aceptado"] for i in con["intentos"])
    assert len(con["intentos"]) == 2 * 3 + 1
    mensajes = [a["mensaje"] for a in con["alertas"]]
    assert any("atacante@" in m for m in mensajes)                 # CN válido fuera de la lista
    assert any("certificado inválido" in m for m in mensajes)      # CA pirata
    # Sin TLS la lista blanca no autentica: los Sybil entran y solo se avisa.
    assert sin["aceptados"] == 3
    assert sorted(a["mensaje"].split(": ", 1)[1] for a in sin["alertas"]) == [
        f"sybil_{i} (no autenticado)" for i in range(3)]


def test_equivocacion_pbft_alerta_y_confirma_un_solo_bloque():
    r = lab.equivocacion("pbft", semilla=1)
    assert r["equivocacion_detectada"]
    assert {a["nodo"] for a in r["alertas"]} == {"r1", "r2", "r3"}
    assert r["bloques_distintos_confirmados_en_altura_1"] == 1
    assert r["exito_ataque"] is False
    assert all(e["vista"] >= 1 and e["primario"] != "r0" for e in r["estado_replicas"].values())


def test_barrido_reorg_sin_hash_nunca_gana_y_pbft_no_aplica():
    r = lab.barrido_reorg("pow", semilla=1, cuotas=(0,), intentos=1)
    assert r["filas"][0]["exitos"] == 0 and r["exito_ataque"] is False
    assert "MEDIDO EN PROCESO" in " ".join(r["narrativa"])
    assert lab.barrido_reorg("pbft")["aplica"] is False


def test_cli_imprime_narrativa_y_json(capsys):
    import importlib.util
    from pathlib import Path
    ruta = Path(__file__).resolve().parent.parent / "scripts" / "laboratorio_ataques.py"
    spec = importlib.util.spec_from_file_location("laboratorio_ataques", ruta)
    cli = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cli)
    resultado = cli.main(["--escenario", "sybil", "--consenso", "pow", "--identidades", "1"])
    salida = capsys.readouterr().out
    assert "== Laboratorio de ataques: sybil (pow) ==" in salida
    assert "Veredicto: el ataque FALLÓ." in salida
    assert json.loads(salida[salida.index("{"):]) == json.loads(json.dumps(resultado))
    with pytest.raises(SystemExit):
        cli.main(["--escenario", "inventado"])
