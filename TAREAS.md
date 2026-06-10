# Lista de Tareas — UPB-Chain
## Universidad Privada Boliviana · Carrera de IA

**Leyenda:**
`[ ]` Pendiente &nbsp; `[x]` Completado &nbsp; `[~]` En progreso &nbsp; `[!]` Bloqueado &nbsp; `[-]` Cancelado

**Responsables:** `[DEV]` Desarrollador · `[SEC]` Seguridad · `[DOC]` Documentador · `[TUT]` Tutor

---

## FASE 1 — Preparación de Hardware (Semanas 1–2)

### 1.1 Sistema Operativo y Red
- [ ] `[DEV]` Flashear Raspberry Pi OS 64-bit Bookworm en RPi5 Nodo 1
- [ ] `[DEV]` Flashear Raspberry Pi OS 64-bit Bookworm en RPi5 Nodo 2
- [ ] `[DEV]` Asignar IP fija `192.168.1.101` al Nodo 1
- [ ] `[DEV]` Asignar IP fija `192.168.1.102` al Nodo 2
- [ ] `[DEV]` Verificar ping entre nodos (< 5 ms)
- [ ] `[DEV]` Configurar SSH sin contraseña (`ssh-copy-id`)
- [ ] `[DEV]` Habilitar UFW: puertos 22, 8000, 8001, 8002, 8003
- [ ] `[DEV]` Instalar `fail2ban` para protección SSH

### 1.2 Entorno Python
- [ ] `[DEV]` Instalar Python 3.11+ en Nodo 1
- [ ] `[DEV]` Instalar Python 3.11+ en Nodo 2
- [ ] `[DEV]` Crear entorno virtual `venv` en ambos nodos
- [ ] `[DEV]` Ejecutar `pip install -r requirements.txt` en ambos nodos
- [ ] `[DEV]` Verificar que `from blockchain.core.block import Block` no lanza errores
- [ ] `[DEV]` Ejecutar `scripts/setup_rpi.sh node_1 8000 8001` en Nodo 1
- [ ] `[DEV]` Ejecutar `scripts/setup_rpi.sh node_2 8002 8003` en Nodo 2

### 1.3 Baseline de Hardware
- [ ] `[DEV]` Ejecutar `python scripts/demo.py` en Nodo 1 (medir tiempo total)
- [ ] `[DEV]` Ejecutar `python scripts/demo.py` en Nodo 2 (medir tiempo total)
- [ ] `[DOC]` Registrar hash rate SHA-256 de cada nodo
- [ ] `[DOC]` Registrar temperatura bajo carga (`vcgencmd measure_temp`)
- [ ] `[DOC]` Documentar resultados en `docs/benchmark_hardware.md`

---

## FASE 2 — Core Blockchain (Semanas 3–5)

### 2.1 Estructura de Datos
- [x] `[DEV]` `blockchain/core/block.py` — Bloque con Merkle Tree
- [x] `[DEV]` `blockchain/core/chain.py` — Cadena con fork resolution
- [x] `[DEV]` `blockchain/core/transaction.py` — Modelo de TX firmada
- [x] `[DEV]` `blockchain/core/wallet.py` — Wallet ECDSA secp256k1
- [ ] `[DEV]` Verificar que el bloque génesis se crea correctamente al primer inicio
- [ ] `[DEV]` Verificar que la cadena persiste en disco tras reinicio del proceso

### 2.2 Consenso
- [x] `[DEV]` `blockchain/consensus/proof_of_work.py` — PoW adaptativo
- [x] `[DEV]` `blockchain/consensus/pbft.py` — PBFT completo 4 fases
- [ ] `[DEV]` Medir tiempo de bloque con dificultad 3, 4, 5 en RPi5
- [ ] `[DOC]` Graficar curva de dificultad vs tiempo de bloque
- [ ] `[DEV]` Probar PBFT con 4 nodos simulados (todos en un RPi5)

### 2.3 Red P2P
- [x] `[DEV]` `blockchain/network/node.py` — P2P TCP + gossip + heartbeat
- [ ] `[DEV]` Conectar Nodo 1 y Nodo 2 en red real: `p2p.connect_to_peer('192.168.1.102', 8003)`
- [ ] `[DEV]` Verificar sincronización de cadena: Nodo 1 mina → Nodo 2 actualiza
- [ ] `[DEV]` Probar tolerancia a desconexión: apagar Nodo 2 y reconectar

### 2.4 Testing
- [x] `[DEV]` `tests/test_blockchain.py` — 15+ tests de core
- [x] `[DEV]` `tests/test_consensus.py` — Tests PoW + PBFT
- [x] `[DEV]` `tests/test_security.py` — Tests crypto + ataques
- [ ] `[DEV]` Ejecutar `pytest tests/ -v --tb=short` — todos deben pasar
- [ ] `[DEV]` Alcanzar cobertura de tests > 80 % (`pytest --cov`)
- [ ] `[DOC]` Documentar resultados de tests en `docs/test_report.md`

---

## FASE 3 — Smart Contracts y API (Semanas 6–7)

### 3.1 Contrato de Credenciales
- [x] `[DEV]` `blockchain/contracts/credential.py` — Emisión, verificación, revocación
- [ ] `[DEV]` Registrar institución `UPB` en el contrato con `register_issuer()`
- [ ] `[DEV]` Emitir 5 credenciales de prueba para estudiantes ficticios
- [ ] `[DEV]` Verificar cada credencial usando solo el `credential_id`
- [ ] `[DEV]` Revocar 1 credencial y verificar que falla la verificación posterior
- [ ] `[DEV]` Probar que el estudiante puede consultar todas sus credenciales

### 3.2 API REST
- [x] `[DEV]` `api/app.py` — 20+ endpoints FastAPI
- [ ] `[DEV]` Iniciar API: `uvicorn api.app:app --host 0.0.0.0 --port 8000`
- [ ] `[DEV]` Verificar `GET /health` responde `{"status": "ok"}`
- [ ] `[DEV]` Probar todos los endpoints desde Swagger en `/docs`
- [ ] `[DEV]` Verificar CORS desde navegador externo
- [ ] `[DOC]` Exportar colección Postman/OpenAPI de todos los endpoints

### 3.3 Dashboard
- [x] `[DEV]` `dashboard/templates/index.html` — Dashboard con branding UPB
- [x] `[DEV]` `dashboard/static/upb-logo.svg` — Logo institucional SVG
- [x] `[DEV]` `dashboard/static/upb-icon.svg` — Ícono SVG para favicon
- [ ] `[DEV]` Verificar que el dashboard carga desde red LAN universitaria
- [ ] `[DEV]` Probar formulario de emisión de credencial end-to-end
- [ ] `[DEV]` Verificar gráfica Chart.js en móvil (responsive)

---

## FASE 4 — Inteligencia Artificial (Semanas 8–10)

### 4.1 Detección de Anomalías
- [x] `[DEV]` `ai/anomaly/detector.py` — Isolation Forest + heurísticas
- [ ] `[DEV]` Generar dataset: minar 50+ bloques con TXs variadas
- [ ] `[DEV]` Entrenar modelo: `POST /ai/train`
- [ ] `[DEV]` Inyectar TXs anómalas (payload gigante, fee extremo) y verificar detección
- [ ] `[DOC]` Calcular y documentar: Precisión, Recall, F1, AUC-ROC
- [ ] `[DOC]` Comparar modo heurístico vs Isolation Forest en tabla

### 4.2 Analítica de Cadena
- [x] `[DEV]` `ai/analytics/chain_stats.py` — TPS, distribución TX, salud de red
- [ ] `[DEV]` Generar reporte con `analytics.analyze(chain.chain)`
- [ ] `[DOC]` Crear notebook Jupyter `notebooks/analisis_cadena.ipynb`
- [ ] `[DOC]` Incluir gráficas: distribución temporal de TXs, evolución de TPS
- [ ] `[DOC]` Redactar sección de resultados de IA para el paper

### 4.3 Optimización en RPi5
- [ ] `[DEV]` Medir tiempo de inferencia de `TransactionAnomalyDetector.predict()` en RPi5
- [ ] `[DEV]` Medir consumo RAM durante entrenamiento con 1000 TXs
- [ ] `[DEV]` Optimizar si el tiempo de inferencia > 100 ms

---

## FASE 5 — Ciberseguridad (Semanas 11–12)

### 5.1 Criptografía
- [x] `[SEC]` `security/crypto_utils.py` — ECDSA, AES-GCM, PBKDF2, SHA-256/3/BLAKE2b
- [ ] `[SEC]` Ejecutar `benchmark_crypto(10000)` en RPi5 y documentar tabla comparativa
- [ ] `[SEC]` Verificar que `verify_password()` resiste timing attacks (hmac.compare_digest)
- [ ] `[DOC]` Documentar elección de curva secp256k1 vs NIST P-256 en `docs/`

### 5.2 Simulación de Ataques
- [x] `[SEC]` `security/attacks/simulator.py` — 51%, Sybil, Doble Gasto
- [ ] `[SEC]` Ejecutar `full_security_analysis(node_count=2)` y documentar resultados
- [ ] `[SEC]` Comparar probabilidad de doble gasto con 6 vs 12 vs 30 confirmaciones
- [ ] `[SEC]` Demostrar que PBFT elimina el riesgo de ataque del 51 %
- [ ] `[DOC]` Redactar tabla de amenazas con mitigaciones para el paper

### 5.3 Monitor de Seguridad
- [x] `[SEC]` `security/monitor.py` — Monitor con alertas INFO/WARNING/CRITICAL
- [ ] `[SEC]` Simular spam de TXs (> 100/min) y verificar alerta `TX_RATE_LIMIT`
- [ ] `[SEC]` Simular reorganización de cadena y verificar alerta `CHAIN_REORG`
- [ ] `[SEC]` Verificar que el dashboard muestra alertas en tiempo real
- [ ] `[SEC]` Documentar política de respuesta para cada tipo de alerta

---

## FASE 6 — Integración, Deploy y Presentación (Semanas 13–16)

### 6.1 Deploy en Producción
- [ ] `[DEV]` Ejecutar deploy completo en ambos RPi5 con `setup_rpi.sh`
- [ ] `[DEV]` Verificar servicio `systemd upbchain` arranca automáticamente
- [ ] `[DEV]` Probar reinicio de RPi5 → servicio se recupera solo
- [ ] `[DEV]` Confirmar sincronización de cadena entre nodos tras 1 hora de operación
- [ ] `[DEV]` Test de estrés: 500 TXs consecutivas, medir TPS real en RPi5

### 6.2 Documentación Académica
- [x] `[DOC]` `docs/arquitectura.md` — Documento técnico de arquitectura
- [x] `[DOC]` `docs/PLAN_IMPLEMENTACION.md` — Plan de implementación
- [ ] `[DOC]` Redactar paper IEEE (8–12 páginas) con secciones:
  - [ ] Abstract y Keywords
  - [ ] I. Introducción y motivación
  - [ ] II. Marco teórico (blockchain, PBFT, Isolation Forest)
  - [ ] III. Diseño e implementación
  - [ ] IV. Resultados y evaluación
  - [ ] V. Discusión y trabajo futuro
  - [ ] VI. Conclusiones
  - [ ] VII. Referencias
- [ ] `[DOC]` Diseñar póster A0 con resultados y logo UPB
- [ ] `[DOC]` Preparar presentación de 15 min (máximo 15 diapositivas)
- [ ] `[DOC]` Grabar video demo de 5 minutos

### 6.3 Presentación Final
- [ ] `[TUT]` Revisión del paper por docente tutor (semana 14)
- [ ] `[TUT]` Revisión técnica del sistema en vivo (semana 15)
- [ ] `[DEV]` Ensayo general de presentación (semana 15)
- [ ] `[DEV]` Presentación ante tribunal académico (semana 16)
- [ ] `[DEV]` Publicar repositorio en GitHub institucional UPB
- [ ] `[DOC]` Entregar documentación final a facultad

---

## Backlog — Extensiones Futuras (Post-proyecto)

### Alta prioridad
- [ ] Integración con sistema de notas de la UPB (API REST interna)
- [ ] Zero-Knowledge Proof para verificación privada de credenciales
- [ ] Módulo de votación estudiantil on-chain (gobernanza)

### Media prioridad
- [ ] Añadir Nodo 3 (PC de laboratorio) para red de 3 nodos reales
- [ ] Implementar Proof of Stake como tercer mecanismo de consenso
- [ ] Sharding para escalar a múltiples facultades

### Investigación
- [ ] Graph Neural Network para análisis de patrones en el grafo de transacciones
- [ ] Reinforcement Learning para optimización dinámica de dificultad
- [ ] Análisis comparativo de privacidad vs transparencia (paper)

---

## Progreso General

```
FASE 1 Hardware      ░░░░░░░░░░  0%   [ 0/15 tareas]
FASE 2 Core          ████████░░  79%  [11/14 tareas]
FASE 3 Contratos     ████░░░░░░  43%  [ 3/7  tareas]
FASE 4 IA            ████░░░░░░  36%  [ 2/7  tareas]
FASE 5 Seguridad     ████░░░░░░  43%  [ 3/7  tareas]
FASE 6 Deploy        ░░░░░░░░░░  0%   [ 0/14 tareas]
───────────────────────────────────────────────────
TOTAL                ███░░░░░░░  30%  [19/64 tareas]
```

*Actualizar porcentajes al completar cada tarea.*

---

**Última actualización:** 2026-06-10
**Repositorio:** `E:\Usuario\Documentos\ACADEMICO\IA\blockchain_upb_ia`
