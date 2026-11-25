"""Regresiones de P1-11: resultados del simulador de ataques y del análisis de cadena."""
from ai.analytics.chain_stats import ChainAnalytics
from security.attacks.simulator import FiftyOnePercentAttack, full_security_analysis


def test_ataque_51_con_50_por_ciento_reporta_exito():
    # Con 50 % el reorg siempre ocurre en la simulación (q >= p): debe reportarse como éxito
    result = FiftyOnePercentAttack().simulate(50.0, 50.0, iterations=200)
    assert result.metrics["simulated_success_rate"] == 1.0
    assert result.success is True


def test_tiempo_promedio_de_bloque_excluye_genesis():
    # Génesis en t=0 y bloques cada 10 s: el promedio debe ser 10 s, no 340 s
    chain = [
        {"header": {"timestamp": 0.0}, "transactions": []},
        {"header": {"timestamp": 1000.0}, "transactions": []},
        {"header": {"timestamp": 1010.0}, "transactions": []},
        {"header": {"timestamp": 1020.0}, "transactions": []},
    ]
    report = ChainAnalytics().analyze(chain)
    assert report.avg_block_time_s == 10.0


def test_cada_escenario_del_analisis_tiene_success_booleano():
    result = full_security_analysis(node_count=2)
    for nombre, entrada in result.items():
        assert isinstance(entrada.get("success"), bool), nombre
