# AGENTS.md — UPB-Chain

Instructions for any coding agent (Claude Code, Codex, Cursor, etc.) and for human collaborators.

## What this is

Permissioned academic blockchain for Universidad Privada Boliviana (UPB): credentials that employers
verify by ID/QR, student tokens and badges, PoW + PBFT consensus, Isolation Forest anomaly detection,
an attack lab for teaching, FastAPI + a single-page dashboard. Target hardware is two Raspberry Pi 5
nodes owned by the original author; everything else is developed on laptops with several local nodes.

Spirit: built from scratch, explainable in a paper, runnable on a Pi. Prefer a small hand-written
mechanism that students can read over importing a framework that hides it.

**Current state and the job list live in `docs/ROADMAP.md`.** Read it before starting work. It is
the source of truth for priorities (P0/P1/P2), acceptance criteria and dependencies. `TAREAS.md` and
`docs/PLAN_IMPLEMENTACION.md` are the author's original plan (its progress counts are manual and
overstate what works).

## Environment

- Python 3.12 venv (3.11, the Raspberry Pi OS version, also passes the suite) built with `uv`. On Windows the system `python` is the Store stub: always use
  `venv\Scripts\python.exe` (Linux/RPi: `venv/bin/python`).
- Add dependencies with `uv pip install --python venv\Scripts\python.exe <pkg>` and record them in
  `requirements.txt`.
- Config: copy `.env.example` to `.env`; all env vars are read in one place, `config.py` (`load_settings()`,
  environment variables win over `.env`). Each node needs its own `DATA_DIR` and ports.
  `.env.example` documents every variable (`MINING_DIFFICULTY` in bits, default 16; `CONSENSUS=pow|pbft`; `P2P_TLS`;
  `ADMIN_API_KEY`: set = `X-API-Key` required, empty = loopback only; `METRICS_PUBLIC`; `TX_RATE_LIMIT`;
  `PUBLIC_BASE_URL`; `DID_WEB_DOMAIN`; `REVALIDATE_ON_START`; `SNAPSHOT_INTERVAL`).

## Commands

- Tests: `venv\Scripts\python.exe -m pytest tests -q` (must stay fully green; currently 726 passed + 1 xfailed, ~2.5 min)
- Run a node (from repo root, paths are relative):
  `venv\Scripts\python.exe -m uvicorn api.app:app --host 127.0.0.1 --port 8000`
  Dashboard `/`, Swagger `/docs`, health `/health`. P2P listens on 8001. No auto-reload unless `--reload`.
  Second local node (PowerShell):
  `$env:NODE_ID="node_2"; $env:DATA_DIR="data/node_2"; $env:NODE_PORT="8011"; $env:PEERS="127.0.0.1:8001"; venv\Scripts\python.exe -m uvicorn api.app:app --host 127.0.0.1 --port 8010`
- Demo without server: `venv\Scripts\python.exe scripts\demo.py`
- 4-node network: `ADMIN_API_KEY=... docker compose up --build -d` (key is mandatory; ports 8000/8010/8020/8030 on 127.0.0.1)
- Paper experiments (fixed seeds; `--rapido` for a seconds-long run): `venv\Scripts\python.exe scripts\experiments\run_all.py`;
  PoW vs PBFT race alone: `scripts\experiments\carrera_consensos.py`. Live attack lab: `scripts\laboratorio_ataques.py --escenario ...`
- Consensus rules changed (difficulty in bits, nonces, SQLite): a node with an older `DATA_DIR` must wipe it (e.g. `data/chain`) and resync.
  Collaborators with an old clone (history was rewritten): `git fetch && git reset --hard origin/main`.

## Layout

- `config.py` `Settings` (pydantic-settings, inmutable, validado; `load_settings()`/`build_settings()`; env gana a .env)
- `blockchain/core` block, chain (fork resolution; owns the `ContractRegistry`; keeps `self.chain`
  in memory), transaction, wallet (ECDSA secp256k1), `storage.py` `ChainStore` (P2-4): SQLite
  `<DATA_DIR>/chain.db` (WAL, `synchronous=FULL`) with tables `blocks`, `txs` (index by id/sender/
  recipient), `snapshots` (contract states as JSON every `SNAPSHOT_INTERVAL` blocks); one SQLite
  transaction per append/reorg, never a full rewrite. Startup `REVALIDATE_ON_START=fast` (default:
  cheap header/PoW/Merkle check + latest snapshot + full validation of later blocks) or `full`.
  An old `chain.json` is imported once and kept as `chain.json.migrated`;
  `scripts/exportar_cadena.py` dumps chain.db to JSON. Tests tamper with the DB via
  `tests/helpers.py` (`bloques_en_disco`, `escribir_bloque_en_disco`)
- `blockchain/consensus` proof_of_work, pbft (P1-1: `ReplicaSet` from `PBFT_REPLICAS_FILE`,
  `PBFTReplica` normal case + view change with signed messages, `PBFTTransport` direct delivery,
  `InMemoryNetwork` for demo/unit tests). `CONSENSUS=pow|pbft` is network-wide (handshake rejects a
  mismatch); in pbft blocks have difficulty 0 / nonce 0 and need a commit certificate (2f+1 signed
  COMMITs, table `certificates` in chain.db, outside the block hash). Replica keys:
  `scripts/crear_llave_replica.py`, never committed · `blockchain/network` P2P node (sincronización y peers en `node.py`; P2-6: una conexión persistente por par y canal `ctl`/`pbft`, `P2P_TLS=on` = mTLS TLS 1.3 con contextos en `network/tls.py`, identidad = CN del certificado contra `P2P_ALLOWLIST`; CA privada en `security/pki.py` + `scripts/crear_ca.py`/`emitir_cert_nodo.py`, certificados en `data/tls/`, nunca versionados; sin TLS la lista blanca solo avisa)
- `blockchain/contracts` (P1-13, guía en `docs/contratos.md`): `base.py` interfaz `Contract`
  (`validate`/`apply`/`initial_state`, estado = reproducción de las TXs confirmadas; una TX inválida
  invalida el bloque entero), `registry.py` `ContractRegistry`, `__init__.py` `default_contracts`;
  `accounts.py` saldo y nonce (P0-9, cada TX firmada lleva `nonce` = confirmado + 1, montos enteros),
  `credential.py` credential issue/verify/revoke (P0-6; issuers registered by `ISSUER_REGISTER` TXs
  signed by the genesis authority, key in `data/keys/authority.json`, never committed),
  `voting.py` contrato de referencia (un voto por dirección y elección),
  `programs.py` contrato `vm` (P2-11: `CONTRACT_DEPLOY`/`CONTRACT_CALL`, gas en PUPB)
- `blockchain/vm` (P2-11, guía en `docs/vm.md`): VM de pila (`machine.py`) y ensamblador `.upbasm`
  (`asm.py`); CLI `scripts/upbasm.py`, ejemplos en `contratos_estudiantes/`. Nunca `exec()`
- `ai/anomaly/detector.py`, `ai/analytics/chain_stats.py`
- `security/` crypto_utils, monitor, hardening (checklist de solo lectura en `GET /security/hardening`),
  `attacks/` simulator, eclipse (usado por el simulador y `POST /security/eclipse-simulation`)
- `api/app.py` app factory `create_app(settings)`: estado del nodo en `NodeState` (`app.state.node`), endpoints con `Depends(get_node)`; `app = create_app()` para uvicorn; dos apps por proceso son independientes · `dashboard/templates/index.html`

## Rules

- Code comments, docstrings and docs in Spanish (matches the codebase). Commit messages: Spanish,
  conventional prefix (`fix:`, `feat:`, `docs:`, `test:`, `refactor:`), and the roadmap ID when there
  is one, e.g. `fix(P0-1): génesis determinista`.
- Work lands on `main` in small commits; run the full test suite before each commit.
- One roadmap job per change. Don't mix refactors into feature or fix commits.
- Every bug fix gets a regression test that fails before the fix. Every P0 needs a test that goes
  through the seam (API or two nodes), not only the class in isolation; the existing suite passes
  while the system cannot sync, which is the trap to avoid.
- When a job is done, tick it in `docs/ROADMAP.md` in the same commit.
- Consensus-relevant code must be deterministic: no floats for amounts, no `time.time()`/randomness
  inside validation or contract state transitions.
- Do not claim measured numbers (hash rate, TPS, temperature, AUC) that were not measured; label
  estimates as such. Hardware measurements come from the Pi owner.
- Tests that need their own node build it with `tests.helpers.make_app(tmp_path, ...)` (`create_app` + `Settings`), never by patching module globals; two apps in one process are independent.
- Always pass `encoding="utf-8"` to `open()` (Windows defaults to cp1252).
- Keep it free of deprecated patterns (FastAPI `lifespan`, Pydantic v2, no `utcnow`).
- Firma en el servidor (endpoints con `private_key_hex`) es solo educativa y está en desuso; la firma real va en el navegador (`/billetera`, `dashboard/static/wallet-core.js`, test cruzado con `node` en `tests/test_billetera.py`).
- Never commit `venv/`, `.env`, `data/`, wallets or private keys. Wallet endpoints return private keys
  by design (educational); never expose the API beyond a trusted LAN.
- Remote: upstream is `telecomaster/upb-chain`; collaborators without push access use a fork.
