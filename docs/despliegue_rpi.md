# Despliegue en 2 Raspberry Pi 5 (4 réplicas PBFT, 2 por Pi)

Guía paso a paso (P1-10 y P0-7). Decisión de diseño (ROADMAP, P1-1): **4 réplicas PBFT, 2 por Pi, f = 1**.
Limitación aceptada: si se apaga un Pi caen 2 réplicas, quedan 2 < 2f+1 = 3 y PBFT **se detiene**
hasta que vuelva (ver [arquitectura](arquitectura.md) §4).

Cada comando de esta guía existe tal cual en los scripts (`--help` de cada uno lo confirma). Los
comandos de la **laptop** (Windows) van en PowerShell; los de las **Pi**, en bash.

## 0. Plano de la red

| Equipo | Réplica | API (HTTP) | P2P (mTLS) | Servicio systemd |
|---|---|---|---|---|
| Pi 1 (`IP1`) | `node_1` (primario de la vista 0) | 8000 | 8001 | `upbchain-node_1` |
| Pi 1 | `node_2` | 8010 | 8011 | `upbchain-node_2` |
| Pi 2 (`IP2`) | `node_3` | 8000 | 8001 | `upbchain-node_3` |
| Pi 2 | `node_4` | 8010 | 8011 | `upbchain-node_4` |

Reemplazar `IP1`/`IP2` por las IP fijas reales (reserva DHCP en el router, o IP estática). **La IP
queda escrita en los certificados y en la lista de réplicas**: si cambia, hay que repetir el paso 3.
`USUARIO` es el usuario Linux que se eligió al grabar el SD (en esta guía, `pi`).

Archivos en cada Pi (raíz del proyecto = `~/upb-chain`, nada de esto se versiona):

```
nodes/node_N.env          configuración de la réplica (incluye ADMIN_API_KEY, permisos 600)
keys/pbft_node_N.json     llave privada de firma PBFT de la réplica
keys/authority.json       llave de la autoridad UPB: SOLO en la Pi 1, para node_1 (opcional)
tls/ca.crt                certificado público de la CA
tls/node_N.crt / .key     certificado y llave de la réplica
pbft_replicas.json        lista pública de las 4 réplicas (idéntica en las dos Pi)
data/node_N/              chain.db de la réplica (se crea solo)
```

`ca.key` (la llave de la CA) **no sale de la laptop**.

## 1. Preparar cada Pi (en las dos)

Raspberry Pi OS 64-bit (Bookworm, Python 3.11). Con SSH ya habilitado:

```bash
sudo apt update && sudo apt full-upgrade -y
sudo apt install -y git
sudo timedatectl set-ntp true
timedatectl status          # debe decir "System clock synchronized: yes" (si no, ver §9)
python3 --version           # 3.11.x
hostnamectl set-hostname upb-pi1     # upb-pi2 en la otra: los informes de bench llevan el nombre
```

## 2. Clonar el proyecto (en las dos)

```bash
git clone https://github.com/telecomaster/upb-chain.git ~/upb-chain
cd ~/upb-chain
git log --oneline -1        # anotar el commit: en las dos Pi debe ser el mismo
```

Si ya estaba clonado: `cd ~/upb-chain && git pull`. Las carpetas `nodes/`, `keys/`, `tls/`, `data/`
y el archivo `pbft_replicas.json` están en `.gitignore`: un `git pull` no los toca.

## 3. Generar llaves, CA y certificados (UNA vez, en la laptop)

Desde la raíz del repo en la laptop (necesita el venv con las dependencias):

```powershell
venv\Scripts\python.exe scripts\preparar_despliegue_rpi.py --ip-pi1 IP1 --ip-pi2 IP2 --usuario pi --autoridad-llave data\keys\authority.json
```

Qué hace (usa `crear_llave_replica`, `crear_ca` y `emitir_cert_nodo`; no duplica cripto):

- crea `data\despliegue\ca\ca.crt` y `ca.key`;
- crea las 4 llaves PBFT y **una** `pbft_replicas.json` con el orden `node_1..node_4`
  (direcciones `IP1:8001`, `IP1:8011`, `IP2:8001`, `IP2:8011`);
- emite un certificado por réplica (CN = `node_N`, SAN = la IP de su Pi);
- escribe los 4 `nodes/node_N.env` con una `ADMIN_API_KEY` aleatoria común (la imprime: **guardarla**)
  y el mismo `DID_WEB_DOMAIN` (por defecto `IP1:8000`; `--did-dominio upb.edu.bo` para el dominio
  real), así un VC exportado por cualquier réplica verifica contra cualquier otra;
- arma `data\despliegue\pi1\` y `data\despliegue\pi2\`, cada uno con la estructura de la raíz del
  proyecto y **solo** lo que esa Pi necesita. La llave de autoridad solo va al paquete de la Pi 1
  (`node_1`); sin `--autoridad-llave` las operaciones de emisores y `tokens/mint` darán 503.

`--autoridad-llave` debe ser la llave **original** de la autoridad, la que corresponde a
`GENESIS_AUTHORITY_ADDRESS` (`blockchain/core/block.py`, el génesis fijado). El script compara la
dirección de la llave con esa constante y **aborta** si no coincide; con otra llave la red
arrancaría con `tokens/mint` y los emisores devolviendo 503. No generar una llave nueva con
`crear_llave_autoridad.py` para una red existente (eso solo vale para una red nueva y obliga a que
todos los nodos borren su `DATA_DIR`). `verificar_red.py` (§6) también avisa si ningún nodo tiene
la llave cargada (`authority_key_loaded` en `/health`).

Opciones: `--dir-proyecto` (por defecto `/home/<usuario>/upb-chain`), `--salida`, `--api-base`,
`--p2p-base`, `--admin-key`. No sobrescribe: si `data\despliegue` ya existe y tiene contenido, se
niega (borrarlo a mano para empezar de cero).

## 4. Copiar a cada Pi solo su paquete

```powershell
scp -r data\despliegue\pi1 USUARIO@IP1:~/paquete
scp -r data\despliegue\pi2 USUARIO@IP2:~/paquete
```

En **cada** Pi:

```bash
cp -r ~/paquete/. ~/upb-chain/ && rm -r ~/paquete
chmod 600 ~/upb-chain/keys/* ~/upb-chain/tls/*.key ~/upb-chain/nodes/*.env
ls ~/upb-chain/nodes ~/upb-chain/keys ~/upb-chain/tls
```

Comprobar que la Pi 1 tiene `node_1/node_2` y la Pi 2 `node_3/node_4`, y que **ninguna** tiene
`ca.key`.

## 5. Instalar y arrancar las réplicas (setup_rpi.sh, una vez por réplica)

`setup_rpi.sh` crea el venv, instala `requirements.txt`, conserva el `nodes/node_N.env` que ya
copiamos, crea la unidad `upbchain-node_N` (usuario no root, `EnvironmentFile`, un solo worker),
abre el firewall (ufw: ssh + los dos puertos de la réplica) y espera a que `/health` responda
(hasta 60 s). `sudo` debe ejecutarse desde la sesión del usuario normal (usa `SUDO_USER`; si no,
`sudo UPB_USER=USUARIO bash ...`).

Pi 1:

```bash
cd ~/upb-chain
sudo bash scripts/setup_rpi.sh node_1 8000 8001
sudo SKIP_APT=1 bash scripts/setup_rpi.sh node_2 8010 8011
```

Pi 2:

```bash
cd ~/upb-chain
sudo bash scripts/setup_rpi.sh node_3 8000 8001
sudo SKIP_APT=1 bash scripts/setup_rpi.sh node_4 8010 8011
```

Orden de arranque: no importa. En PBFT cada réplica se conecta con las demás de
`pbft_replicas.json` y reintenta con espera creciente (hasta 60 s) mientras el otro Pi no esté. Lo
más cómodo: ejecutar primero la Pi 1 y después la Pi 2; en cuanto arranca la segunda, la red se
une sola. `PEERS` no hace falta. Los servicios arrancan solos al encender la Pi.

Estado y registros: `systemctl status upbchain-node_1`, `journalctl -u upbchain-node_1 -f`.

## 6. Verificar la red

Desde la laptop (las API están en la LAN; la llave no hace falta para esta lectura):

```powershell
venv\Scripts\python.exe scripts\verificar_red.py http://IP1:8000 http://IP1:8010 http://IP2:8000 http://IP2:8010 --espera 120
```

Debe terminar con `RED LISTA` y código de salida 0. Comprueba: `/health` de los 4; mismo hash de
génesis (y igual al del código local); mismo `CONSENSUS=pbft`; mismo `P2P_TLS=on`; alturas
convergentes; cada nodo con 3 pares activos; misma lista de réplicas (id, dirección, llave
pública), mismo n/f/quórum, cada URL es la réplica que dice ser, misma vista y primario; desfase de
reloj entre nodos < 2 s. También sirve desde una Pi (el script solo usa la biblioteca estándar):
`venv/bin/python scripts/verificar_red.py http://IP1:8000 ...`.

`PBFT: quórum alcanzable` puede salir `WARN` en una red recién arrancada y ociosa (todavía no hubo
mensajes PBFT). Para generar tráfico real, emitir una transacción en `node_1` (la que tiene la
llave de autoridad) y repetir la verificación:

```powershell
# en la laptop, desde la raíz del repo; KEY = la ADMIN_API_KEY que imprimió el paso 3.
# La dirección destino se genera localmente (no usar /wallet/generate por la LAN: devuelve la
# llave privada en claro); también sirve una dirección de la billetera del navegador (/billetera).
$DIR = venv\Scripts\python.exe -c "from blockchain.core.wallet import Wallet; print(Wallet.generate().address)"
$cuerpo = @{ recipient = $DIR; amount = 5 } | ConvertTo-Json -Compress
curl.exe -s -X POST http://IP1:8000/tokens/mint -H "X-API-Key: KEY" -H "Content-Type: application/json" -d $cuerpo.Replace('"','\"')
```

A los pocos segundos las 4 réplicas deben estar en altura 1 (`verificar_red.py` lo confirma) y cada
una debe tener 2f+1 réplicas activas. Esto prueba el camino completo (TX, PBFT con mTLS,
certificado de commit, persistencia).

Panel de cada réplica: `http://IP:PUERTO_API/` (dashboard) y `/consensus`.

## 7. Benchmark (P1-10)

El benchmark corre **en proceso, sin servidor ni puertos**, pero compite por CPU con las réplicas:
parar las de esa Pi mientras mide (con ambas Pi apagadas PBFT queda detenido; es esperado).

```bash
cd ~/upb-chain
sudo systemctl stop upbchain-node_1 upbchain-node_2        # Pi 2: node_3 y node_4
vcgencmd measure_temp; vcgencmd get_throttled              # antes (throttled=0x0 = sin estrangulamiento)
venv/bin/python scripts/bench_rpi.py --rapido --salida ~/bench_$(hostname)    # prueba de humo, segundos
nohup venv/bin/python scripts/bench_rpi.py --salida ~/bench_$(hostname) > ~/bench_$(hostname).log 2>&1 &
tail -f ~/bench_$(hostname).log      # termina con "Escrito: ...md" (la medición completa tarda minutos)
vcgencmd measure_temp; vcgencmd get_throttled              # después
sudo systemctl start upbchain-node_1 upbchain-node_2
```

Opciones de `bench_rpi.py`: `--rapido`, `--salida DIR`, `--consenso pow|pbft|ambos` (por defecto
ambos). Lo importante es que no haya réplicas corriendo en la Pi que se mide (las de la otra Pi no
influyen). El informe incluye `carga_1min`; debe ser baja (< 0,5) al empezar.

**Qué devolver** (de cada Pi, a la laptop con `scp USUARIO@IP:~/bench_*/*  .`):

1. `~/bench_<host>/bench_<host>_completo_<fecha>.md` y `.csv` (y los `rapido` si se quieren);
2. la salida de `vcgencmd measure_temp` y `vcgencmd get_throttled` antes y después;
3. la salida completa de `verificar_red.py` del paso 6;
4. si algo falló: `journalctl -u upbchain-node_N --no-pager -n 200 > ~/log_node_N.txt`.

Se copian a `docs/mediciones/` y se resumen en `docs/benchmark_hardware.md` (sin extrapolar: solo
lo medido en la Pi). Estos números no existen hasta que se ejecuten.

### Freno térmico del minero (opcional, idea 5)

Para que el minado PoW baje su ritmo cuando la Pi se calienta, agregar al `.env` del nodo
`THERMAL_THROTTLE=on` (umbrales `THERMAL_SOFT_C=70`, `THERMAL_HARD_C=80`, `THERMAL_MIN_DUTY=0.2`)
y reiniciar. Es local, no cambia la dificultad ni el consenso. Verificar con
`curl http://127.0.0.1:8000/health` (campo `thermal`). Para medir si ayuda (hipótesis, sin cifras
previas): `venv/bin/python scripts/bench_rpi.py --termico --termico-segundos 300` mina 300 s sin freno
y 300 s con freno y guarda la curva de temperatura y el hash rate en `docs/mediciones/`
(`--rapido` hace una corrida de 2 s de humo). Dejar enfriar la Pi entre corridas.

## 8. Operación diaria

| Acción | Comando (en la Pi) |
|---|---|
| Parar / arrancar una réplica | `sudo systemctl stop upbchain-node_1` / `start` |
| Reiniciar las 2 de una Pi | `sudo systemctl restart upbchain-node_1 upbchain-node_2` |
| Ver registros | `journalctl -u upbchain-node_1 -f` |
| Actualizar el código | `cd ~/upb-chain && git pull` y reiniciar las réplicas (venv: `venv/bin/pip install -r requirements.txt`) |
| Cambiar un valor de `.env` | editar `nodes/node_N.env` y reiniciar esa réplica |

## 9. Solución de problemas

**Reloj / NTP.** Un reloj desviado rompe TLS (certificado "aún no válido"; los certificados nuevos
ya empiezan un día antes, así que solo un desfase de más de un día lo rompe) y los plazos de cambio
de vista de PBFT. Revisar `timedatectl status` en las dos Pi. Sin internet: `sudo timedatectl
set-ntp false && sudo timedatectl set-time "AAAA-MM-DD HH:MM:SS"` en ambas, y comprobar el desfase
con `verificar_red.py` (línea `reloj`).

**Un nodo caído sigue figurando como par activo.** El latido P2P (`P2P_PING_INTERVAL`, 3 s por defecto) consulta a cada par activo; si el proceso murió, el par se marca caído en ese plazo y se reconecta con backoff. Un par colgado o con el cable desconectado (sin RST) tarda `P2P_PING_MISSES` x (`P2P_PING_INTERVAL` + `P2P_PING_TIMEOUT`) en declararse caído (por defecto 2 timeouts de 3 s: unos 9 s). En una red muy cargada (PoW minando en las dos Pi) subir `P2P_PING_TIMEOUT` evita falsos positivos. Medido en portátil con 4 procesos: ~2,6 s (antes ~15 s); no es una medida en Raspberry Pi.

**`verificar_red.py` da FAIL**

| Línea | Causa probable |
|---|---|
| `salud http://...` | servicio caído (`systemctl status`, `journalctl`), firewall (`sudo ufw status`), IP equivocada |
| `génesis` distinto | nodos con versiones distintas del código: `git log -1` en las dos Pi, `git pull`, reiniciar |
| `consenso` / `P2P TLS` distinto | `.env` mal copiado; todos deben tener `CONSENSUS=pbft` y `P2P_TLS=on` |
| `pares P2P` | TLS rechazado (CN del certificado, CA distinta, reloj), puerto P2P cerrado o IP de la lista de réplicas equivocada. Revisar `journalctl -u upbchain-node_N` en ambos extremos |
| `PBFT: conjunto de réplicas` | `pbft_replicas.json` distinto entre Pi: volver a copiar el de `data\despliegue` a las dos |
| `PBFT: réplica propia` | falta `PBFT_KEY_FILE` o `NODE_ID` no figura en la lista |
| `alturas` | una réplica sin sincronizar: esperar o reiniciarla; si persiste, ver la sección siguiente |

**Cambió una regla de consenso, o hay cadenas distintas / `chain.db` dañada.** Hay que borrar los
datos de **las 4 réplicas a la vez** (no las llaves ni los certificados: viven fuera de `data/`) y
volver a arrancar:

```bash
sudo systemctl stop upbchain-node_1 upbchain-node_2      # Pi 2: node_3 y node_4
rm -rf ~/upb-chain/data/node_1 ~/upb-chain/data/node_2   # Pi 2: node_3 y node_4
sudo systemctl start upbchain-node_1 upbchain-node_2
```

Si no se borran en las 4, la réplica con datos viejos rechaza o es rechazada (génesis o reglas
distintas).

**`Longitud de mensaje inválida: N` en el journal.** Un par mandó un marco mayor que el tope de
10 MB. Con la sincronización por lotes (P0-5) ningún nodo actualizado lo hace: casi siempre es una
réplica con código viejo (`git log -1` en las dos Pi). Se registra una sola línea por conexión, sin
traza. Esta versión cambia reglas de consenso (topes de tamaño, P0-3) y el protocolo de
sincronización: actualizar las 4 réplicas a la vez.

**Cambió la IP de una Pi.** La IP está en la lista de réplicas y en el certificado: repetir los
pasos 3 a 5 (borrar antes `data\despliegue` y los `data/node_*` de las 4 réplicas).

**Un Pi apagado.** PBFT se detiene (2 de 4 réplicas); no es un fallo: al volver a encender el Pi las
réplicas se reconectan solas y recuperan los bloques que faltan.

**`Address already in use`.** Otro proceso usa el puerto (¿se arrancó a mano un `uvicorn`?).
`sudo ss -ltnp | grep -E ':(8000|8001|8010|8011)'`.

**503 en emisores o `tokens/mint`.** La réplica no tiene `AUTHORITY_KEY_FILE` (solo `node_1`, y solo
si se pasó `--autoridad-llave`). Las demás réplicas lo devuelven por diseño.

**Después de reiniciar la Pi no arranca nada.** `systemctl is-enabled upbchain-node_1` debe decir
`enabled`; si el servicio falla al arrancar antes de que haya red, `Restart=on-failure` lo reintenta
cada 5 s.

## 10. Simulación en una sola máquina

Para ensayar la guía sin las Pi (los mismos archivos `.env`, TLS activado, 4 procesos `uvicorn` en
loopback), generar los paquetes con `--ip-pi1 127.0.0.1 --ip-pi2 127.0.0.1 --api-base 9300
--p2p-base 9301 --desfase-pi2 40 --dir-proyecto <carpeta>`, copiar `pi1` y `pi2` a `<carpeta>` y
lanzar cada réplica con `uvicorn api.app:app --port <API_PORT>` y las variables de su `.env`.
`uvicorn` debe correr desde la raíz del repo (las rutas relativas y el import `api.app` dependen de
ello). En PowerShell, para arrancar un nodo desde su archivo de entorno:

```powershell
# desde la raíz del repo; ajustar el archivo y el puerto API de la réplica
Get-Content <carpeta>\nodes\node_1.env | Where-Object { $_ -match '^\s*[^#\s][^=]*=' } | ForEach-Object {
    $k, $v = $_ -split '=', 2
    Set-Item -Path "Env:$($k.Trim())" -Value $v.Trim()
}
venv\Scripts\python.exe -m uvicorn api.app:app --host 127.0.0.1 --port 9300
```

Así se validó la guía antes del despliegue (4 réplicas, mTLS, un bloque confirmado,
`verificar_red.py` en verde).
