# Plan de Implementación — UPB-Chain
## Blockchain Académica con Inteligencia Artificial

**Universidad Privada Boliviana (UPB)**
**Carrera:** Ingeniería en Inteligencia Artificial
**Área secundaria:** Ciberseguridad en Electrónica y Telecomunicaciones
**Tipo de proyecto:** Proyecto Estrella de Carrera
**Duración total:** 16 semanas (4 meses)
**Fecha de inicio:** Semana 1 del semestre académico

---

## 1. Resumen Ejecutivo

UPB-Chain es una red blockchain permisionada de dos nodos implementada sobre hardware **Raspberry Pi 5** de la universidad. El proyecto demuestra en hardware real los conceptos de sistemas distribuidos, criptografía aplicada, mecanismos de consenso, contratos inteligentes y detección de anomalías mediante Machine Learning. Al concluir, la universidad dispondrá de una plataforma funcional para emitir y verificar credenciales académicas de forma inmutable y descentralizada.

---

## 2. Objetivos

### Objetivo General
Diseñar, implementar y desplegar una blockchain permisionada con capa de Inteligencia Artificial sobre dos nodos Raspberry Pi 5, como plataforma de investigación y demostración académica para la UPB.

### Objetivos Específicos

| # | Objetivo | Área | Criterio de éxito |
|---|----------|------|-------------------|
| OE-1 | Implementar el protocolo blockchain desde cero | IA / Sistemas Distribuidos | Cadena de 100+ bloques sin corrupción |
| OE-2 | Comparar consenso PoW vs PBFT en RPi5 | IA / Redes | Métricas de latencia y TPS publicadas |
| OE-3 | Desplegar smart contracts de credenciales | IA / Legal-Tech | Emitir y verificar 10 credenciales de prueba |
| OE-4 | Entrenar detector de anomalías sobre datos reales | Inteligencia Artificial | AUC-ROC > 0.85 en validación |
| OE-5 | Simular y documentar vectores de ataque | Ciberseguridad | 3 ataques documentados con contramedidas |
| OE-6 | Dashboard accesible desde la red de la universidad | Sistemas / UX | < 2 s de carga, responsive en móvil |

---

## 3. Fases del Proyecto

### FASE 1 — Preparación de Hardware e Infraestructura
**Duración:** Semanas 1–2

#### Actividades

| ID | Actividad | Responsable | Herramientas |
|----|-----------|-------------|--------------|
| F1.1 | Instalar Raspberry Pi OS 64-bit en ambos nodos | Equipo infraestructura | Raspberry Pi Imager |
| F1.2 | Configurar red LAN estática (IP fija por nodo) | Equipo infraestructura | router, switch Gigabit |
| F1.3 | Instalar Python 3.11, pip, venv en ambos RPi5 | Equipo software | apt, pip |
| F1.4 | Clonar repositorio y crear entorno virtual | Equipo software | git, venv |
| F1.5 | Ejecutar benchmark de CPU y disco (baseline) | Equipo IA | scripts/demo.py |
| F1.6 | Verificar conectividad P2P entre nodos | Equipo redes | netcat, ping |
| F1.7 | Configurar SSH sin contraseña entre nodos | Equipo infraestructura | ssh-keygen |

#### Entregables
- [ ] Ambos RPi5 operativos con IP fija
- [ ] Repositorio clonado y dependencias instaladas en ambos nodos
- [ ] Informe de baseline de hardware (CPU, RAM, disco, red)

#### Criterio de salida de fase
Los dos nodos se comunican por TCP en la red LAN de la universidad con latencia < 5 ms.

---

### FASE 2 — Implementación del Core Blockchain
**Duración:** Semanas 3–5

#### Actividades

| ID | Actividad | Módulo | Complejidad estimada |
|----|-----------|--------|----------------------|
| F2.1 | Implementar estructura de bloque + Merkle Tree | `blockchain/core/block.py` | Alta |
| F2.2 | Implementar cadena de bloques con persistencia | `blockchain/core/chain.py` | Alta |
| F2.3 | Implementar modelo de transacciones firmadas | `blockchain/core/transaction.py` | Media |
| F2.4 | Implementar wallet ECDSA secp256k1 | `blockchain/core/wallet.py` | Alta |
| F2.5 | Implementar Proof of Work adaptativo | `blockchain/consensus/proof_of_work.py` | Media |
| F2.6 | Implementar PBFT completo (4 fases) | `blockchain/consensus/pbft.py` | Muy Alta |
| F2.7 | Implementar red P2P con gossip y heartbeat | `blockchain/network/node.py` | Alta |
| F2.8 | Escribir tests unitarios (cobertura > 80 %) | `tests/` | Media |

#### Entregables
- [ ] Suite de tests completa con `pytest tests/ -v` en verde
- [ ] Demo ejecutable: `python scripts/demo.py`
- [ ] Informe de rendimiento: hash rate medido en RPi5

#### Dependencias
- Ninguna (punto de partida del software)

#### Criterio de salida de fase
`python scripts/demo.py` completa los 11 pasos sin errores en ambos RPi5.

---

### FASE 3 — Smart Contracts y Capa de Aplicación
**Duración:** Semanas 6–7

#### Actividades

| ID | Actividad | Módulo | Prioridad |
|----|-----------|--------|-----------|
| F3.1 | Implementar contrato de credenciales académicas | `blockchain/contracts/credential.py` | Alta |
| F3.2 | Definir flujo de emisión y verificación | `api/app.py` | Alta |
| F3.3 | Integrar QR Code para credenciales | `qrcode` lib | Media |
| F3.4 | Implementar API REST completa con FastAPI | `api/app.py` | Alta |
| F3.5 | Documentar todos los endpoints (OpenAPI) | Swagger automático | Baja |
| F3.6 | Prueba end-to-end: emitir → minar → verificar | `tests/` | Alta |

#### Entregables
- [ ] API REST funcional en `http://<nodo>:8000/docs`
- [ ] 10 credenciales de prueba emitidas y verificadas
- [ ] QR Code funcional para cada credencial

#### Casos de uso demostrados
1. **Emisión de título**: Universidad emite `DEGREE` para estudiante graduado
2. **Verificación por empleador**: Empleador verifica con solo el `credential_id`
3. **Revocación**: Universidad revoca credencial emitida por error
4. **Historial**: Consulta todas las credenciales de un estudiante por dirección

---

### FASE 4 — Capa de Inteligencia Artificial
**Duración:** Semanas 8–10

#### Actividades

| ID | Actividad | Algoritmo | Biblioteca |
|----|-----------|-----------|------------|
| F4.1 | Colectar dataset de transacciones de la cadena | — | `chain.get_all_transactions()` |
| F4.2 | Feature engineering para transacciones | Extracción manual | NumPy, Pandas |
| F4.3 | Entrenar Isolation Forest con datos reales | Isolation Forest | scikit-learn |
| F4.4 | Validar detector con conjunto de prueba | AUC-ROC, F1 | scikit-learn |
| F4.5 | Implementar módulo de analítica de cadena | Estadísticas | NumPy, Pandas |
| F4.6 | Generar reportes automáticos de la cadena | Visualización | matplotlib |
| F4.7 | Integrar módulo IA en API REST | FastAPI | Endpoint `/ai/` |
| F4.8 | Documentar resultados para paper académico | LaTeX / Markdown | — |

#### Métricas objetivo

| Métrica | Objetivo |
|---------|----------|
| AUC-ROC (detector anomalías) | > 0.85 |
| Precisión (anomalías reales) | > 80 % |
| Tiempo de inferencia en RPi5 | < 50 ms por TX |
| Tiempo de entrenamiento en RPi5 | < 60 s (1000 TXs) |

#### Entregables
- [ ] Modelo `IsolationForest` entrenado y serializado
- [ ] Reporte de métricas ML (notebook Jupyter)
- [ ] Integración en dashboard: widget de anomalías en tiempo real

---

### FASE 5 — Módulo de Ciberseguridad
**Duración:** Semanas 11–12

#### Actividades

| ID | Actividad | Vector de ataque | Resultado esperado |
|----|-----------|------------------|--------------------|
| F5.1 | Implementar simulación del ataque del 51 % | `simulator.py` | Demostrar vulnerabilidad con < 50 % hash rate |
| F5.2 | Implementar simulación del ataque Sybil | `simulator.py` | Mostrar reducción de riesgo con PoS |
| F5.3 | Implementar simulación de doble gasto | `simulator.py` | Comparar 6 vs 12 confirmaciones |
| F5.4 | Implementar monitor de seguridad en tiempo real | `monitor.py` | Detectar rate limiting y reorgs |
| F5.5 | Documentar vectores, impacto y contramedidas | `docs/` | Tabla de amenazas con mitigaciones |
| F5.6 | Ejecutar benchmark criptográfico en RPi5 | `crypto_utils.py` | Tabla ECDSA/SHA-256/AES comparativa |
| F5.7 | Escribir sección de seguridad para el paper | `docs/paper/` | Sección "Threat Model" completa |

#### Entregables
- [ ] Simulador educativo funcional con resultados reproducibles
- [ ] Monitor de seguridad integrado en dashboard
- [ ] Tabla de vectores de ataque con mitigaciones implementadas

---

### FASE 6 — Integración, Testing Final y Presentación
**Duración:** Semanas 13–16

#### Actividades

| ID | Actividad | Prioridad |
|----|-----------|-----------|
| F6.1 | Deploy completo en ambos RPi5 (`setup_rpi.sh`) | Crítica |
| F6.2 | Prueba de conectividad inter-nodo en LAN universitaria | Crítica |
| F6.3 | Test de estrés: 500 TXs consecutivas | Alta |
| F6.4 | Documentar resultados en paper académico | Alta |
| F6.5 | Preparar póster de presentación con logo UPB | Alta |
| F6.6 | Grabar video demostrativo (5 min) | Media |
| F6.7 | Presentar en feria académica / tribunal | Crítica |
| F6.8 | Publicar repositorio en GitHub institucional | Media |

#### Entregables finales
- [ ] Sistema operativo 24/7 en ambos RPi5
- [ ] Paper académico (8–12 páginas, formato IEEE)
- [ ] Póster A0 con resultados
- [ ] Video demostrativo
- [ ] Presentación de 15 minutos ante tribunal

---

## 4. Cronograma — Diagrama de Gantt

```
SEMANA          1  2  3  4  5  6  7  8  9  10 11 12 13 14 15 16
────────────────────────────────────────────────────────────────
FASE 1 Hardware [██]
FASE 2 Core        [████████]
FASE 3 Contratos               [████]
FASE 4 IA                            [██████]
FASE 5 Seguridad                              [████]
FASE 6 Deploy y Presentación                        [████████]
────────────────────────────────────────────────────────────────
Tests continuos    [═══════════════════════════════════════════]
Documentación      [═══════════════════════════════════════════]
```

---

## 5. Recursos Necesarios

### Hardware (disponible)
| Recurso | Cantidad | Especificación |
|---------|----------|----------------|
| Raspberry Pi 5 | 2 | 16 GB RAM, 128 GB NVMe |
| Switch Gigabit | 1 | Para red LAN privada |
| Cables Ethernet | 2 | Cat6, 2 m |
| Fuentes de alimentación | 2 | 5V / 5A USB-C |

### Software (libre / open source)
| Software | Versión | Licencia |
|----------|---------|----------|
| Raspberry Pi OS 64-bit | Bookworm | Free |
| Python | 3.11+ | PSF |
| FastAPI + Uvicorn | 0.111+ | MIT |
| scikit-learn | 1.4+ | BSD |
| cryptography (PyCA) | 42+ | Apache 2.0 |
| Chart.js | 4.x | MIT |

### Recursos humanos estimados
| Rol | Horas/semana | Semanas | Total |
|-----|-------------|---------|-------|
| Desarrollador principal (IA) | 15 h | 16 | 240 h |
| Desarrollador seguridad | 10 h | 8 (fases 2,5) | 80 h |
| Diseñador / documentador | 5 h | 6 (fases 3,6) | 30 h |
| Docente tutor | 2 h | 16 | 32 h |
| **Total** | | | **382 h** |

---

## 6. Riesgos y Mitigaciones

| ID | Riesgo | Probabilidad | Impacto | Mitigación |
|----|--------|-------------|---------|------------|
| R-1 | Overheating de RPi5 bajo carga sostenida | Media | Alto | Instalar disipadores y monitorear temperatura; reducir dificultad |
| R-2 | Fallo de disco NVMe | Baja | Alto | Backup diario del `data/chain/` a almacenamiento externo |
| R-3 | Dependencias incompatibles en ARM64 | Media | Medio | Probar instalación completa en semana 1; fijar versiones en requirements.txt |
| R-4 | Corte de red universitaria durante demo | Media | Alto | Demo offline preparada (`scripts/demo.py`) sin dependencia de red |
| R-5 | Tiempo de minado excesivo en presentación | Alta | Medio | Usar dificultad=2 para demo rápida; PBFT no requiere minado |
| R-6 | Datos insuficientes para entrenar ML | Media | Medio | Generador de TXs sintéticas incluido en `scripts/demo.py` |

---

## 7. Criterios de Éxito del Proyecto

### Mínimos (proyecto aprobado)
- [ ] Blockchain funcional con ≥ 2 nodos sincronizados
- [ ] API REST respondiendo todos los endpoints documentados
- [ ] Al menos 1 credencial académica emitida y verificada on-chain
- [ ] Tests unitarios con cobertura > 70 %

### Esperados (proyecto notable)
- [ ] Consenso PBFT funcional entre los 2 nodos reales
- [ ] Detector de anomalías ML entrenado con datos reales
- [ ] Dashboard accesible desde navegador en red LAN de UPB
- [ ] Simulador de ataques con documentación de resultados

### Excelentes (proyecto sobresaliente)
- [ ] Paper académico enviado a congreso o revista indexada
- [ ] Zero-Knowledge Proof como extensión implementada
- [ ] Integración con sistema de notas existente de UPB
- [ ] Benchmark comparativo publicado (RPi5 vs servidor convencional)

---

## 8. Metodología de Desarrollo

**Framework:** Scrum académico adaptado
- **Sprint:** 2 semanas
- **Daily standup:** 15 min diarios (equipo)
- **Sprint review:** Cada 2 semanas con docente tutor
- **Retrospectiva:** Al final de cada fase

**Control de versiones:** Git con rama `main` (estable) + ramas `feature/fase-N`
**Gestión de tareas:** Archivo `TAREAS.md` + Issues en GitHub
**Documentación:** Markdown en `docs/` + docstrings en código

---

## 9. Referencias Bibliográficas

1. Nakamoto, S. (2008). *Bitcoin: A Peer-to-Peer Electronic Cash System*. https://bitcoin.org/bitcoin.pdf
2. Castro, M., & Liskov, B. (1999). *Practical Byzantine Fault Tolerance*. OSDI'99.
3. Wood, G. (2014). *Ethereum: A Secure Decentralised Generalised Transaction Ledger*. Ethereum Project Yellow Paper.
4. Liu, F. T., Ting, K. M., & Zhou, Z. H. (2008). *Isolation Forest*. ICDM'08.
5. Johnson, D., Menezes, A., & Vanstone, S. (2001). *The Elliptic Curve Digital Signature Algorithm (ECDSA)*. IJIS.
6. Merkle, R. C. (1988). *A Digital Signature Based on a Conventional Encryption Function*. CRYPTO'87.
7. Zheng, Z., et al. (2018). *Blockchain challenges and opportunities: a survey*. IJWGS.
8. Swan, M. (2015). *Blockchain: Blueprint for a New Economy*. O'Reilly Media.
