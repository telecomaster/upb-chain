"""Cobertura de `security/monitor.py`: umbrales de alerta, niveles, ventanas y consultas.

El reloj del módulo se sustituye por uno falso (sólo en `security.monitor`) para que las
ventanas de tiempo sean deterministas. Los tests usan `SecurityMonitor` directamente porque
el monitor no depende de ningún nodo.
"""
import time

import pytest

import security.monitor as monitor_mod
from security.monitor import AlertLevel, SecurityMonitor

pytestmark = pytest.mark.unit


class _RelojFalso:
    """Sustituto del módulo `time`: `time()` devuelve `t`, que el test avanza a mano.
    Arranca en el instante real para que las alertas (timestamp por defecto real) sean
    coherentes con las ventanas calculadas por el monitor."""

    def __init__(self):
        self.t = time.time()

    def time(self):
        return self.t

    def avanzar(self, segundos):
        self.t += segundos


@pytest.fixture
def reloj(monkeypatch):
    rj = _RelojFalso()
    monkeypatch.setattr(monitor_mod, "time", rj)
    return rj


@pytest.fixture
def mon(reloj):
    return SecurityMonitor()


def _tx(sender="UPB_EMISOR_A", fee=0.0):
    return {"sender": sender, "type": "DATA_RECORD", "fee": fee}


def _tipos(mon):
    return [a["event_type"] for a in mon.get_alerts(limit=10_000)]


# ── Límite de TX por dirección ───────────────────────────────────────────────

def test_cien_tx_en_la_ventana_no_alertan_la_centesima_primera_si(mon):
    for _ in range(SecurityMonitor.TX_RATE_LIMIT):
        mon.on_transaction(_tx())
    assert "TX_RATE_LIMIT" not in _tipos(mon)  # exactamente el límite no es anomalía
    mon.on_transaction(_tx())
    alerta = mon.get_alerts(limit=1)[0]
    assert alerta["event_type"] == "TX_RATE_LIMIT"
    assert alerta["level"] == AlertLevel.WARNING
    assert alerta["metadata"]["tx_count"] == SecurityMonitor.TX_RATE_LIMIT + 1
    assert alerta["metadata"]["offenses"] == 1


def test_las_tx_antiguas_salen_de_la_ventana(mon, reloj):
    for _ in range(SecurityMonitor.TX_RATE_LIMIT):
        mon.on_transaction(_tx())
    reloj.avanzar(SecurityMonitor.TX_RATE_WINDOW + 1)
    mon.on_transaction(_tx())  # sólo queda esta dentro de la ventana
    assert "TX_RATE_LIMIT" not in _tipos(mon)


def test_reincidencia_escala_a_critico_en_la_quinta_infraccion(mon):
    for _ in range(SecurityMonitor.TX_RATE_LIMIT):
        mon.on_transaction(_tx())
    for _ in range(5):  # infracciones 1..5
        mon.on_transaction(_tx())
    alertas = mon.get_alerts(level=AlertLevel.WARNING) + mon.get_alerts(level=AlertLevel.CRITICAL)
    niveles = [a["level"] for a in sorted(alertas, key=lambda a: a["metadata"]["offenses"])]
    assert niveles == [AlertLevel.WARNING] * 4 + [AlertLevel.CRITICAL]
    assert mon.get_threat_summary()["suspicious_addresses"] == {"UPB_EMISOR_A": 5}


def test_on_tx_rate_limited_escala_igual_y_registra_el_limite(mon):
    niveles = []
    for _ in range(5):
        mon.on_tx_rate_limited("UPB_SPAM", count=101, limit=100)
        niveles.append(mon.get_alerts(limit=1)[0]["level"])
    assert niveles == [AlertLevel.WARNING] * 4 + [AlertLevel.CRITICAL]
    ultima = mon.get_alerts(limit=1)[0]
    assert ultima["metadata"]["limit"] == 100
    assert ultima["metadata"]["tx_count"] == 101
    assert "rechazada" in ultima["message"]


# ── Comentarios de fee y percentiles ─────────────────────────────────────────

def test_percentil_sin_historial_es_cero(mon):
    assert mon.compute_fee_percentile() == 0.0


def test_fees_negativas_y_no_numericas_no_entran_al_historial(mon):
    mon.on_transaction(_tx(fee=-1))
    mon.on_transaction({"sender": "X", "fee": "caro"})
    assert mon.compute_fee_percentile() == 0.0
    mon.on_transaction(_tx(fee=7))
    assert mon.compute_fee_percentile() == 7.0


def test_percentil_100_es_el_maximo_y_crece_con_el_percentil(mon):
    for fee in range(1, 21):
        mon.on_transaction(_tx(fee=fee))
    assert mon.compute_fee_percentile(100) == 20
    valores = [mon.compute_fee_percentile(p) for p in (10, 50, 90, 95, 100)]
    assert valores == sorted(valores)
    assert valores[0] < valores[-1]


def test_percentil_95_de_veinte_valores_en_rango_de_nearest_rank(mon):
    for fee in range(1, 21):
        mon.on_transaction(_tx(fee=fee))
    assert mon.compute_fee_percentile() == 19  # 19 = ceil(0.95 * 20), nearest-rank


def test_percentil_95_de_diez_valores_es_el_decimo(mon):
    for fee in range(1, 11):
        mon.on_transaction(_tx(fee=fee))
    assert mon.compute_fee_percentile(95) == 10


def test_fee_alta_critica_desde_cinco_veces_el_percentil(mon):
    mon.on_high_fee_transaction(_tx("UPB_RICO", fee=50), percentile_95=10)
    alerta = mon.get_alerts(limit=1)[0]
    assert alerta["event_type"] == "HIGH_FEE"
    assert alerta["level"] == AlertLevel.CRITICAL
    assert alerta["metadata"]["fee_ratio"] == 5.0


def test_fee_justo_debajo_del_quintuple_es_advertencia(mon):
    mon.on_high_fee_transaction(_tx(fee=49), percentile_95=10)
    assert mon.get_alerts(limit=1)[0]["level"] == AlertLevel.WARNING


def test_fee_con_percentil_cero_no_divide_y_es_advertencia(mon):
    mon.on_high_fee_transaction(_tx(fee=3), percentile_95=0)
    alerta = mon.get_alerts(limit=1)[0]
    assert alerta["level"] == AlertLevel.WARNING
    assert alerta["metadata"]["fee_ratio"] == 0.0


def test_on_high_fee_añade_la_fee_al_historial(mon):
    mon.on_high_fee_transaction(_tx(fee=42), percentile_95=0)
    assert mon.compute_fee_percentile() == 42.0


# ── Bloques: dificultad y tasa ───────────────────────────────────────────────

def _bloque(dificultad):
    return {"header": {"difficulty": dificultad}}


def test_cambio_de_dificultad_exactamente_50_por_ciento_no_alerta(mon):
    for d in (10, 10, 15):
        mon.on_block(_bloque(d))
    assert "DIFFICULTY_SPIKE" not in _tipos(mon)


def test_cambio_de_dificultad_mayor_de_50_por_ciento_alerta(mon):
    for d in (10, 10, 16):
        mon.on_block(_bloque(d))
    alerta = mon.get_alerts(limit=1)[0]
    assert alerta["event_type"] == "DIFFICULTY_SPIKE"
    assert alerta["level"] == AlertLevel.WARNING
    assert _base(alerta["metadata"]) == {"previous": 10, "current": 16}


def test_dos_bloques_no_bastan_para_detectar_salto(mon):
    mon.on_block(_bloque(10))
    mon.on_block(_bloque(100))
    assert _tipos(mon) == []


def test_dificultad_previa_cero_no_divide_por_cero(mon):
    for d in (0, 0, 5):
        mon.on_block(_bloque(d))
    assert _tipos(mon) == []


def test_tasa_de_bloques_por_minuto(mon, reloj):
    for _ in range(3):
        mon.on_block(_bloque(4))
        reloj.avanzar(30)
    # 3 bloques en 60 s entre el primero y el último => 3 por minuto
    assert mon.get_threat_summary()["avg_block_rate_per_min"] == 3.0


def test_tasa_de_bloques_cero_con_menos_de_dos_o_sin_tiempo(mon):
    assert mon.get_threat_summary()["avg_block_rate_per_min"] == 0.0
    mon.on_block(_bloque(4))
    assert mon.get_threat_summary()["avg_block_rate_per_min"] == 0.0
    mon.on_block(_bloque(4))  # mismo instante: elapsed = 0
    assert mon.get_threat_summary()["avg_block_rate_per_min"] == 0.0


# ── Eventos de consenso y red ────────────────────────────────────────────────

def test_reorganizacion_de_tres_bloques_es_critica(mon):
    mon.on_chain_reorg(depth=2)
    assert mon.get_alerts(limit=1)[0]["level"] == AlertLevel.WARNING
    mon.on_chain_reorg(depth=3)
    assert mon.get_alerts(limit=1)[0]["level"] == AlertLevel.CRITICAL
    assert _base(mon.get_alerts(limit=1)[0]["metadata"]) == {"depth": 3, "total_reorgs": 2}
    assert mon.get_threat_summary()["chain_reorgs"] == 2


def test_bloque_invalido_y_par_desconocido(mon):
    mon.on_invalid_block("firma rota", "nodo_7")
    alerta = mon.get_alerts(limit=1)[0]
    assert (alerta["event_type"], alerta["level"]) == ("INVALID_BLOCK", AlertLevel.WARNING)
    assert _base(alerta["metadata"]) == {"node_id": "nodo_7", "reason": "firma rota"}
    mon.on_unknown_peer("10.0.0.9:8001")
    alerta = mon.get_alerts(limit=1)[0]
    assert (alerta["event_type"], alerta["level"]) == ("UNKNOWN_PEER", AlertLevel.INFO)


def test_huerfanos_advertencia_y_critico_desde_el_tercero(mon):
    hashes = [f"{i:064x}" for i in range(3)]
    niveles = []
    for h in hashes:
        mon.on_orphan_block(h, "parent not found")
        niveles.append(mon.get_alerts(limit=1)[0]["level"])
    assert niveles == [AlertLevel.WARNING, AlertLevel.WARNING, AlertLevel.CRITICAL]
    meta = mon.get_alerts(limit=1)[0]["metadata"]
    assert meta["total_orphans"] == 3 and meta["block_hash"] == hashes[2]


def test_anomalia_critica_desde_score_0_8(mon):
    mon.on_anomalous_transaction(
        {"sender": "UPB_X", "tx_id": "t1", "type": "DATA_RECORD"},
        {"score": 0.8, "explanation": ["monto atípico", "emisor nuevo"]})
    alerta = mon.get_alerts(limit=1)[0]
    assert alerta["level"] == AlertLevel.CRITICAL
    assert "monto atípico; emisor nuevo" in alerta["message"]
    assert alerta["metadata"]["tx_id"] == "t1"


def test_anomalia_bajo_0_8_es_advertencia(mon):
    mon.on_anomalous_transaction({"sender": "UPB_X"}, {"score": 0.79, "explanation": []})
    assert mon.get_alerts(limit=1)[0]["level"] == AlertLevel.WARNING


def test_equivocacion_pbft_critica_y_recorta_digests(mon):
    digest = "d" * 64
    mon.on_pbft_equivocation("replica-2", view=1, seq=7, kind="PREPARE", digests=[digest, "e" * 64])
    alerta = mon.get_alerts(limit=1)[0]
    assert alerta["event_type"] == "PBFT_EQUIVOCATION"
    assert alerta["level"] == AlertLevel.CRITICAL
    assert alerta["metadata"]["digests"] == ["d" * 16, "e" * 16]


def test_conflicto_certificado_es_critico(mon):
    mon.on_certified_conflict(height=5, ours="a" * 64, theirs="b" * 64)
    alerta = mon.get_alerts(limit=1)[0]
    assert alerta["event_type"] == "PBFT_CONFLICT"
    assert alerta["level"] == AlertLevel.CRITICAL
    assert _base(alerta["metadata"]) == {"height": 5, "ours": "a" * 64, "theirs": "b" * 64}


# ── Consultas de alertas y resumen ───────────────────────────────────────────

def test_get_alerts_filtra_por_nivel_y_conserva_el_orden(mon):
    mon.on_unknown_peer("p1")              # INFO
    mon.on_invalid_block("x", "n1")        # WARNING
    mon.on_chain_reorg(depth=9)            # CRITICAL
    criticas = mon.get_alerts(level=AlertLevel.CRITICAL)
    assert [a["event_type"] for a in criticas] == ["CHAIN_REORG"]
    assert [a["event_type"] for a in mon.get_alerts(limit=2)] == ["INVALID_BLOCK", "CHAIN_REORG"]


def test_get_alerts_devuelve_diccionarios_con_los_campos_del_contrato(mon):
    mon.on_unknown_peer("p1")
    alerta = mon.get_alerts()[0]
    assert set(alerta) == {"level", "event_type", "message", "timestamp", "metadata"}


def test_get_alerts_con_limite_cero_no_devuelve_nada(mon):
    mon.on_unknown_peer("p1")
    assert mon.get_alerts(limit=0) == []


def test_resumen_sin_alertas_es_bajo(mon):
    resumen = mon.get_threat_summary()
    assert resumen["threat_level"] == "BAJO"
    assert resumen["total_alerts"] == 0 and resumen["suspicious_addresses"] == {}


def test_resumen_con_critica_es_critico(mon):
    mon.on_chain_reorg(depth=10)
    assert mon.get_threat_summary()["threat_level"] == "CRÍTICO"


def test_resumen_con_seis_advertencias_es_medio_y_con_cinco_bajo(mon):
    for _ in range(5):
        mon.on_invalid_block("x", "n")
    assert mon.get_threat_summary()["threat_level"] == "BAJO"
    mon.on_invalid_block("x", "n")
    resumen = mon.get_threat_summary()
    assert resumen["threat_level"] == "MEDIO"
    assert resumen["warning_alerts"] == 6


def test_sospechosos_solo_los_que_suman_tres_infracciones(mon):
    for _ in range(2):
        mon.on_tx_rate_limited("UPB_DOS", count=101, limit=100)
    for _ in range(3):
        mon.on_tx_rate_limited("UPB_TRES", count=101, limit=100)
    assert mon.get_threat_summary()["suspicious_addresses"] == {"UPB_TRES": 3}


# ── Categorías ───────────────────────────────────────────────────────────────

def test_categorias_vacias_marcan_none(mon):
    cats = mon.get_alert_categories()
    assert cats == {
        "network": {"count": 0, "max_level": "NONE"},
        "application": {"count": 0, "max_level": "NONE"},
        "consensus": {"count": 0, "max_level": "NONE"},
    }


def test_categorias_cuentan_y_guardan_el_nivel_maximo(mon):
    mon.on_chain_reorg(depth=1)            # consensus WARNING
    mon.on_chain_reorg(depth=5)            # consensus CRITICAL
    mon.on_invalid_block("x", "n")         # network WARNING
    mon.on_tx_rate_limited("UPB_A", 101, 100)  # application WARNING
    cats = mon.get_alert_categories()
    assert cats["consensus"] == {"count": 2, "max_level": AlertLevel.CRITICAL}
    assert cats["network"] == {"count": 1, "max_level": AlertLevel.WARNING}
    assert cats["application"] == {"count": 1, "max_level": AlertLevel.WARNING}


def test_tipo_de_evento_desconocido_cae_en_red(mon):
    from security.monitor import SecurityAlert
    mon._fire(SecurityAlert(level=AlertLevel.INFO, event_type="EVENTO_NUEVO", message="x"))
    assert mon.get_alert_categories()["network"] == {"count": 1, "max_level": AlertLevel.INFO}


# ── Estadísticas de ventana ──────────────────────────────────────────────────

def test_estadisticas_de_ventana_vacia(mon):
    stats = mon.get_rolling_stats(window_minutes=5)
    assert stats == {
        "window_minutes": 5, "tx_rate_per_minute": 0.0, "alert_rate_per_minute": 0.0,
        "unique_senders": 0, "anomaly_ratio": 0.0, "total_tx_in_window": 0,
        "total_alerts_in_window": 0,
    }


def test_estadisticas_cuentan_tx_emisores_y_alertas_en_la_ventana(mon):
    for _ in range(3):
        mon.on_transaction(_tx("UPB_A"))
    for _ in range(2):
        mon.on_transaction(_tx("UPB_B"))
    mon.on_chain_reorg(depth=1)
    stats = mon.get_rolling_stats(window_minutes=5)
    assert stats["total_tx_in_window"] == 5
    assert stats["unique_senders"] == 2
    assert stats["tx_rate_per_minute"] == 1.0
    assert stats["total_alerts_in_window"] == 1
    assert stats["alert_rate_per_minute"] == 0.2
    assert stats["anomaly_ratio"] == 0.0


def test_ratio_de_anomalias_con_la_centesima_primera_tx(mon):
    for _ in range(SecurityMonitor.TX_RATE_LIMIT + 1):
        mon.on_transaction(_tx("UPB_SPAM"))
    stats = mon.get_rolling_stats()
    assert stats["anomaly_ratio"] == round(1 / 101, 4)


def test_tx_fuera_de_la_ventana_no_cuentan(mon, reloj):
    mon.on_transaction(_tx("UPB_VIEJO"))
    reloj.avanzar(5 * 60 + 1)
    mon.on_transaction(_tx("UPB_NUEVO"))
    stats = mon.get_rolling_stats(window_minutes=5)
    assert stats["total_tx_in_window"] == 1
    assert stats["unique_senders"] == 1


def test_ventana_de_un_minuto_divide_entre_uno(mon):
    for _ in range(4):
        mon.on_transaction(_tx())
    stats = mon.get_rolling_stats(window_minutes=1)
    assert stats["tx_rate_per_minute"] == 4.0


# ── Callback y tolerancia a fallos ───────────────────────────────────────────

def test_callback_recibe_cada_alerta(reloj):
    recibidas = []
    mon = SecurityMonitor(alert_callback=recibidas.append)
    mon.on_unknown_peer("p1")
    mon.on_chain_reorg(depth=4)
    assert [a.event_type for a in recibidas] == ["UNKNOWN_PEER", "CHAIN_REORG"]
    assert recibidas[1].level == AlertLevel.CRITICAL


def test_error_en_callback_no_impide_registrar_la_alerta(reloj):
    def roto(_alerta):
        raise RuntimeError("webhook caído")

    mon = SecurityMonitor(alert_callback=roto)
    mon.on_invalid_block("x", "n1")  # no debe propagar la excepción
    assert _tipos(mon) == ["INVALID_BLOCK"]


def _base(meta: dict) -> dict:
    """Metadata sin los campos de explicación (Idea 7), que se prueban en test_explicaciones_monitor."""
    return {k: v for k, v in meta.items() if k not in ("explicacion", "resumen")}
