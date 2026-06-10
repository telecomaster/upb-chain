"""
Análisis estadístico y visualización de métricas de UPB-Chain.
Genera reportes sobre throughput, latencia, distribución de TXs y tendencias.
"""
import json
import logging
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("upb_chain.ai.analytics")


@dataclass
class ChainReport:
    generated_at: float = field(default_factory=time.time)
    chain_height: int = 0
    total_transactions: int = 0
    avg_block_time_s: float = 0.0
    throughput_tps: float = 0.0
    tx_type_distribution: dict = field(default_factory=dict)
    top_senders: List[Tuple[str, int]] = field(default_factory=list)
    daily_tx_counts: dict = field(default_factory=dict)
    credential_stats: dict = field(default_factory=dict)
    network_health_score: float = 1.0
    recommendations: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "generated_at": self.generated_at,
            "chain_height": self.chain_height,
            "total_transactions": self.total_transactions,
            "avg_block_time_s": self.avg_block_time_s,
            "throughput_tps": self.throughput_tps,
            "tx_type_distribution": self.tx_type_distribution,
            "top_senders": self.top_senders,
            "daily_tx_counts": self.daily_tx_counts,
            "credential_stats": self.credential_stats,
            "network_health_score": self.network_health_score,
            "recommendations": self.recommendations,
        }


class ChainAnalytics:
    def __init__(self):
        self._block_cache: List[dict] = []
        self._last_analysis: Optional[ChainReport] = None

    def analyze(self, chain: List[dict]) -> ChainReport:
        if not chain:
            return ChainReport()

        self._block_cache = chain
        report = ChainReport()

        report.chain_height = len(chain) - 1
        report.total_transactions = sum(len(b.get("transactions", [])) for b in chain)
        report.avg_block_time_s = self._avg_block_time(chain)
        report.throughput_tps = self._compute_tps(chain)
        report.tx_type_distribution = self._tx_type_distribution(chain)
        report.top_senders = self._top_senders(chain, top_n=10)
        report.daily_tx_counts = self._daily_counts(chain)
        report.credential_stats = self._credential_stats(chain)
        report.network_health_score = self._health_score(report)
        report.recommendations = self._generate_recommendations(report)

        self._last_analysis = report
        logger.info(f"Análisis completado: altura={report.chain_height}, TPS={report.throughput_tps:.4f}")
        return report

    # ── Métricas ──────────────────────────────────────────────────────────────

    def _avg_block_time(self, chain: List[dict]) -> float:
        if len(chain) < 2:
            return 0.0
        times = [b["header"]["timestamp"] for b in chain if "header" in b]
        if len(times) < 2:
            return 0.0
        intervals = [times[i] - times[i - 1] for i in range(1, len(times))]
        return round(sum(intervals) / len(intervals), 3)

    def _compute_tps(self, chain: List[dict]) -> float:
        if len(chain) < 2:
            return 0.0
        first_ts = chain[1]["header"]["timestamp"]
        last_ts = chain[-1]["header"]["timestamp"]
        elapsed = last_ts - first_ts
        if elapsed <= 0:
            return 0.0
        total_tx = sum(len(b.get("transactions", [])) for b in chain[1:])
        return round(total_tx / elapsed, 6)

    def _tx_type_distribution(self, chain: List[dict]) -> dict:
        counter: Counter = Counter()
        for block in chain:
            for tx in block.get("transactions", []):
                tx_type = tx.get("type", "UNKNOWN")
                counter[tx_type] += 1
        total = sum(counter.values()) or 1
        return {k: {"count": v, "pct": round(v / total * 100, 2)} for k, v in counter.most_common()}

    def _top_senders(self, chain: List[dict], top_n: int = 10) -> List[Tuple[str, int]]:
        counter: Counter = Counter()
        for block in chain:
            for tx in block.get("transactions", []):
                sender = tx.get("sender", "")
                if sender:
                    counter[sender] += 1
        return counter.most_common(top_n)

    def _daily_counts(self, chain: List[dict]) -> Dict[str, int]:
        daily: Dict[str, int] = defaultdict(int)
        for block in chain:
            ts = block.get("header", {}).get("timestamp", 0)
            from datetime import datetime
            day = datetime.fromtimestamp(ts).strftime("%Y-%m-%d")
            daily[day] += len(block.get("transactions", []))
        return dict(sorted(daily.items()))

    def _credential_stats(self, chain: List[dict]) -> dict:
        issued = revoked = verified = 0
        institutions: Counter = Counter()
        programs: Counter = Counter()

        for block in chain:
            for tx in block.get("transactions", []):
                tx_type = tx.get("type", "")
                if tx_type == "CREDENTIAL_ISSUE":
                    issued += 1
                    payload = tx.get("payload", {})
                    institutions[payload.get("institution", "N/A")] += 1
                    programs[payload.get("program", "N/A")] += 1
                elif tx_type == "CREDENTIAL_REVOKE":
                    revoked += 1
                elif tx_type == "CREDENTIAL_VERIFY":
                    verified += 1

        return {
            "issued": issued,
            "revoked": revoked,
            "verified": verified,
            "active": issued - revoked,
            "top_institutions": dict(institutions.most_common(5)),
            "top_programs": dict(programs.most_common(5)),
        }

    def _health_score(self, report: ChainReport) -> float:
        score = 1.0
        if report.avg_block_time_s > 60:
            score -= 0.2
        if report.throughput_tps < 0.001 and report.total_transactions > 0:
            score -= 0.1
        cred = report.credential_stats
        if cred.get("issued", 0) > 0:
            revoke_rate = cred.get("revoked", 0) / cred["issued"]
            if revoke_rate > 0.1:
                score -= 0.2
        return round(max(0.0, min(1.0, score)), 3)

    def _generate_recommendations(self, report: ChainReport) -> List[str]:
        recs = []
        if report.avg_block_time_s > 30:
            recs.append("El tiempo de bloque es elevado; considerar reducir dificultad o usar PBFT")
        if report.throughput_tps < 0.01:
            recs.append("TPS bajo; evaluar ajuste de tamaño de bloque o lote de transacciones")
        cred = report.credential_stats
        if cred.get("verified", 0) == 0 and cred.get("issued", 0) > 0:
            recs.append("No hay verificaciones registradas; integrar proceso de verificación de empleadores")
        if report.network_health_score < 0.7:
            recs.append("Puntuación de salud baja; revisar estado de nodos y conectividad")
        if not recs:
            recs.append("Red operando dentro de parámetros óptimos")
        return recs

    def export_report(self, report: ChainReport, path: str) -> None:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(report.to_dict(), f, indent=2, ensure_ascii=False)
        logger.info(f"Reporte exportado a {path}")
