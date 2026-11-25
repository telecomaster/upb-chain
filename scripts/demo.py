"""
Demo completo de UPB-Chain — ejecución sin servidor, ideal para presentaciones.
Muestra el flujo completo: wallet → transacción → minado → verificación → IA → seguridad.
"""
import sys
import tempfile
import time
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from blockchain.core.chain import Blockchain
from blockchain.core.transaction import (
    Transaction,
    TransactionType,
    create_credential_transaction_with_record,
    create_issuer_register_transaction,
    create_vote_transaction,
)
from blockchain.core.wallet import Wallet
from blockchain.consensus.proof_of_work import ProofOfWork, estimate_rpi5_performance
from blockchain.consensus.pbft import InMemoryNetwork, PBFTReplica, ReplicaSet
from blockchain.contracts.credential import CredentialContract, credential_id_of_tx
from ai.anomaly.detector import TransactionAnomalyDetector
from ai.analytics.chain_stats import ChainAnalytics
from security.crypto_utils import benchmark_crypto, generate_keypair, sign_data, verify_signature
from security.attacks.simulator import full_security_analysis
from security.monitor import SecurityMonitor


def separator(title: str):
    w = 60
    print("\n" + "═" * w)
    print(f"  {title}")
    print("═" * w)


def demo():
    print("\n" + "█" * 60)
    print("  UPB-CHAIN — Demo Académico")
    print("  Universidad Privada Boliviana")
    print("  Carrera de Inteligencia Artificial")
    print("█" * 60)

    # ── 1. Blockchain ────────────────────────────────────────────
    separator("1. INICIALIZACIÓN DE LA CADENA")
    # La llave real de la autoridad UPB no está en el repo: el demo usa una
    # autoridad propia (solo cambia quién puede registrar emisores, no el génesis)
    # y una cadena nueva en un directorio temporal en cada ejecución.
    authority_wallet = Wallet.generate()
    chain = Blockchain(node_id="rpi5_node1", data_dir=tempfile.mkdtemp(prefix="upbchain-demo-"),
                       authority_address=authority_wallet.address)
    print(f"✓ Génesis creado: hash={chain.last_block.hash[:24]}…")
    print(f"  Altura: {chain.height} | Nodo: {chain.node_id}")

    # ── 2. Wallets ───────────────────────────────────────────────
    separator("2. GENERACIÓN DE WALLETS CRIPTOGRÁFICAS (ECDSA secp256k1)")
    university_wallet = Wallet.generate()
    student_wallet    = Wallet.generate()
    employer_wallet   = Wallet.generate()
    print(f"✓ Universidad:  {university_wallet.address}")
    print(f"✓ Estudiante:   {student_wallet.address}")
    print(f"✓ Empleador:    {employer_wallet.address}")

    # ── 3. Firma digital ─────────────────────────────────────────
    separator("3. FIRMA DIGITAL Y VERIFICACIÓN")
    message = f"Autorizo emisión de título — {student_wallet.address}"
    priv, pub = university_wallet.private_key_hex, university_wallet.public_key_hex
    signature = sign_data(message, priv)
    valid = verify_signature(message, signature, pub)
    print(f"✓ Mensaje firmado:  {message[:50]}…")
    print(f"✓ Firma (64b):      {signature[:32]}…")
    print(f"✓ Verificación:     {'VÁLIDA ✓' if valid else 'INVÁLIDA ✗'}")

    # ── 4. Contrato de credenciales ──────────────────────────────
    separator("4. CONTRATO INTELIGENTE — CREDENCIALES ACADÉMICAS")
    # Interfaz única de contratos (P1-13): validate + apply sobre un estado.
    contract = CredentialContract(authority_wallet.address)
    state = contract.initial_state()
    tx_reg = create_issuer_register_transaction(
        authority_wallet.address, university_wallet.address, "UPB",
        authority_wallet.private_key_hex, nonce=1)
    ok, reason, state = contract.execute(state, tx_reg.to_dict())
    print(f"✓ Emisor registrado por la autoridad: {ok} ({reason})")

    credential_data = {
        "student_name": "Ana Lucía Mamani Quispe",
        "program": "Ingeniería en Inteligencia Artificial",
        "degree": "Licenciatura en Ingeniería en IA",
        "issue_date": "2025-11-28",
        "credential_type": "DEGREE",
        "institution": "UPB",
        "grade": 91.5,
        "metadata": {
            "thesis": "Detección de Anomalías en Blockchain con Deep Learning",
            "honors": True,
        },
    }
    tx_cred, registro_privado = create_credential_transaction_with_record(
        issuer_address=university_wallet.address,
        student_address=student_wallet.address,
        credential_data=credential_data,
        private_key_hex=university_wallet.private_key_hex,
        nonce=1,   # P0-9: 1.ª TX del emisor
    )
    ok, reason, state = contract.execute(state, tx_cred.to_dict())
    credential = state.get(credential_id_of_tx(tx_cred.to_dict()))
    print(f"✓ Credencial emitida: {credential.credential_id}")
    print(f"  En cadena solo la raiz del compromiso: {credential.fields_root[:32]}... (nombre y nota quedan fuera, P1-2)")
    print(f"  Grado: {credential.degree}")
    print(f"  Nota (solo en el registro privado): {registro_privado['fields']['grade']}/100")

    ok_v, reason_v, _ = state.verify_credential(credential.credential_id)
    print(f"✓ Verificación:       {'VÁLIDA ✓' if ok_v else 'INVÁLIDA'} — {reason_v}")
    ok_d, reason_d, _ = contract.execute(state, tx_cred.to_dict())
    print(f"✓ Emitirla otra vez:  {'aceptada' if ok_d else 'rechazada'} — {reason_d}")

    # ── 5. Transacciones ─────────────────────────────────────────
    separator("5. TRANSACCIONES EN MEMPOOL")
    tx_vote = create_vote_transaction(
        student_wallet.address, "consejo-2025", "lista-A",
        student_wallet.private_key_hex, nonce=chain.next_nonce(student_wallet.address))
    tx_data = Transaction(
        type=TransactionType.DATA_RECORD,
        sender=university_wallet.address,
        recipient="REGISTRY",
        payload={"record": "Acta de grado 2025-11"},
        nonce=2,   # 2.ª TX de la universidad (la credencial usa el nonce 1)
    )
    tx_data.sign(university_wallet.private_key_hex)
    for tx in [tx_reg, tx_cred, tx_vote, tx_data]:
        ok, why = chain.add_transaction(tx)
        print(f"✓ TX {tx.type:<22} id={tx.tx_id[:16]}…  {'en mempool' if ok else 'rechazada: ' + why}")

    # ── 6. Proof of Work ─────────────────────────────────────────
    separator("6. MINADO — PROOF OF WORK (dificultad en bits, P2-5)")
    pow_engine = ProofOfWork()
    candidate = chain.create_candidate_block()
    print(f"  Dificultad exigida por la cadena: {candidate.header.difficulty} bits")
    print(f"  Candidato: índice={candidate.header.index}, TXs={len(candidate.transactions)}")
    t0 = time.perf_counter()
    result = pow_engine.mine(candidate, timeout=60.0, difficulty=candidate.header.difficulty)
    elapsed = time.perf_counter() - t0
    if result:
        chain.add_block(result.block)
        print(f"✓ Bloque minado en {elapsed:.3f}s")
        print(f"  Hash:      {result.hash[:32]}…")
        print(f"  Nonce:     {result.nonce:,}")
        print(f"  Hash rate: {result.hash_rate:,.0f} H/s")
    else:
        print("✗ Timeout — dificultad demasiado alta para demo")

    # ── 7. PBFT ──────────────────────────────────────────────────
    separator("7. CONSENSO PBFT (4 réplicas firmadas, tolera 1 falla)")
    # Red en memoria (sin sockets): 4 réplicas con su propia cadena en modo pbft.
    llaves = [Wallet.generate() for _ in range(4)]
    ids = [f"node_{i + 1}" for i in range(4)]
    rs = ReplicaSet.from_list([{"id": rid, "address": f"127.0.0.1:{8001 + 10 * i}",
                                "public_key": w.public_key_hex}
                               for i, (rid, w) in enumerate(zip(ids, llaves))])
    red = InMemoryNetwork()
    cadenas = []
    for rid, w in zip(ids, llaves):
        bc = Blockchain(node_id=rid, data_dir=tempfile.mkdtemp(prefix="upbchain-pbft-"),
                        consensus="pbft", replica_set=rs)
        cadenas.append(bc)
        red.add(PBFTReplica(rid, w.private_key_hex, rs, bc, red.sender(rid), batch_interval=0))
    red.down = {"node_4"}            # una réplica caída: f = 1 la tolera
    autor = Wallet.generate()
    tx_pbft = Transaction(type=TransactionType.DATA_RECORD, sender=autor.address,
                          recipient="UPB_DEMO", payload={"nota": "demo PBFT"}, nonce=1)
    tx_pbft.sign(autor.private_key_hex)
    for bc in cadenas[:3]:
        bc.add_transaction(tx_pbft)
    red.replicas["node_1"].tick()    # el primario de la vista 0 propone
    estado = red.replicas["node_1"].status()
    cert = cadenas[0].certificates.get(1, {})
    print(f"✓ PBFT: n={estado['n']}, f={estado['f']}, quórum={estado['quorum']} "
          f"(una réplica caída)")
    print(f"  Altura confirmada en las 3 vivas: {[bc.height for bc in cadenas[:3]]}")
    print(f"  Certificado de commit: {len(cert.get('commits', []))} firmas ECDSA, "
          f"mensajes entregados: {red.delivered}")

    # ── 8. Detección de anomalías IA ──────────────────────────────
    separator("8. IA — DETECCIÓN DE ANOMALÍAS EN TRANSACCIONES")
    detector = TransactionAnomalyDetector()
    all_txs = [tx.to_dict() for tx in chain.mempool] + [
        tx for b in chain.chain for tx in b.transactions
    ]
    if len(all_txs) >= 10:
        train_result = detector.train(all_txs)
        print(f"✓ Modelo entrenado: {train_result['samples']} muestras")
    else:
        print(f"  Modo heurístico (pocas muestras: {len(all_txs)})")

    normal_tx = {"type": "CREDENTIAL_ISSUE", "sender": "UPB123", "recipient": "STU456",
                 "payload": {"data": "x"*100}, "fee": 0.0, "timestamp": time.time(), "tx_id": "abc"}
    spam_tx   = {"type": "DATA_RECORD", "sender": "ATTACKER", "recipient": "X",
                 "payload": {"data": "x"*20000}, "fee": 999.0, "timestamp": time.time() - 86400, "tx_id": "xyz"}

    for label, tx_sample in [("TX normal", normal_tx), ("TX sospechosa", spam_tx)]:
        report = detector.predict(tx_sample)
        flag = "⚠ ANOMALÍA" if report.is_anomaly else "✓ Normal"
        print(f"  {label:<18} score={report.score:.3f}  {flag}")
        for exp in report.explanation:
            print(f"    → {exp}")

    # ── 9. Análisis estadístico ───────────────────────────────────
    separator("9. IA — ANÁLISIS ESTADÍSTICO DE LA CADENA")
    analytics = ChainAnalytics()
    chain_data = [b.to_dict() for b in chain.chain]
    report = analytics.analyze(chain_data)
    print(f"✓ Altura:           {report.chain_height}")
    print(f"  Total TXs:        {report.total_transactions}")
    print(f"  Tiempo bloque:    {report.avg_block_time_s:.2f}s")
    print(f"  Salud de red:     {report.network_health_score*100:.0f}%")
    print(f"  Credenciales:     {report.credential_stats}")
    print("  Recomendaciones:")
    for rec in report.recommendations:
        print(f"    • {rec}")

    # ── 10. Seguridad ────────────────────────────────────────────
    separator("10. ANÁLISIS DE SEGURIDAD — SIMULACIÓN DE ATAQUES")
    monitor = SecurityMonitor()
    monitor.on_chain_reorg(depth=2)
    for _ in range(5):
        monitor.on_transaction({"sender": "SPAMMER", "type": "DATA_RECORD", "payload": {}})

    attack_results = full_security_analysis(node_count=2, honest_hash_rate=70, attacker_hash_rate=30)
    for attack_name, result in attack_results.items():
        if attack_name == "_summary":
            continue  # resumen consolidado, no es un escenario de ataque
        status = "VULNERABLE" if result["success"] else "PROTEGIDO"
        print(f"  [{status}] {attack_name.replace('_',' ').upper()}")
        recs = result.get("recommendations", [])
        if recs:
            print(f"    → {recs[0]}")

    threat = monitor.get_threat_summary()
    print(f"\n✓ Nivel de amenaza: {threat['threat_level']}")
    print(f"  Alertas: {threat['total_alerts']} total, {threat['critical_alerts']} críticas")

    # ── 11. Benchmark criptográfico ───────────────────────────────
    separator("11. BENCHMARK CRIPTOGRÁFICO (RPi 5)")
    bench = benchmark_crypto(iterations=5000)
    for algo, metrics in bench.items():
        if "ops_per_sec" in metrics:
            print(f"  {algo:<25} {metrics['ops_per_sec']:>8,} ops/s")
        elif "avg_ms" in metrics:
            print(f"  {algo:<25} {metrics.get('ops_per_sec',0):>8,} ops/s  ({metrics['avg_ms']:.2f} ms/op)")

    rpi_est = estimate_rpi5_performance()
    print(f"\n  Hash SHA-256 estimado RPi5: {rpi_est['hash_rate_per_second']:,} H/s")
    print(f"  Tiempo esperado (16 bits):  {rpi_est['expected_time_16_bits_s']}s")
    print(f"  Tiempo esperado (20 bits):  {rpi_est['expected_time_20_bits_s']}s")

    # ── Resumen final ─────────────────────────────────────────────
    separator("RESUMEN FINAL")
    final_stats = chain.get_stats()
    print(f"  Bloques en la cadena:    {final_stats['total_blocks']}")
    print(f"  Transacciones totales:   {final_stats['total_transactions']}")
    print(f"  Hash último bloque:      {final_stats['last_block_hash'][:32]}…")
    valid, reason = chain.validate_chain()
    print(f"  Integridad de la cadena: {'✓ VÁLIDA' if valid else '✗ COMPROMETIDA'} — {reason}")
    print("\n" + "█" * 60)
    print("  Demo completado exitosamente.")
    print("  UPB-Chain está operativo en Raspberry Pi 5.")
    print("█" * 60 + "\n")


if __name__ == "__main__":
    demo()
