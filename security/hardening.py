"""
UPB-Chain — Hardening y Mejores Prácticas de Seguridad
Universidad Privada Boliviana · Área de Ciberseguridad

Checklist de seguridad para despliegue en producción en RPi5.
Proporciona 24 checks clasificados por categoría y severidad,
con comandos de verificación bash y pasos de remediación.

Uso típico:
    auditor = HardeningAuditor()
    report  = auditor.run_audit()
    print(auditor.generate_report())
    critical = auditor.get_critical_items()

Nota sobre run_audit():
    Los checks de categoría NETWORK y OS requieren acceso al sistema operativo
    y se marcan como 'MANUAL'. Los checks de CRYPTO, APP y MONITORING se
    evalúan mediante inspección Python pura (sin subprocess ni comandos shell).
    Funciona correctamente en Windows y Linux.
"""
import importlib.util
import logging
import os
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


# ── Enumeraciones y tipos base ────────────────────────────────────────────────

class HardeningCategory(str, Enum):
    NETWORK    = "NETWORK"
    CRYPTO     = "CRYPTO"
    OS         = "OS"
    APP        = "APP"
    MONITORING = "MONITORING"


@dataclass
class HardeningCheck:
    """Representa un único item del checklist de hardening."""
    id:            str
    category:      HardeningCategory
    title:         str
    description:   str
    severity:      str   # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
    check_command: str   # Comando bash para verificación manual
    remediation:   str   # Pasos para resolver el problema


# ── Checklist de 24 items ─────────────────────────────────────────────────────

HARDENING_CHECKS: List[HardeningCheck] = [

    # ── NETWORK (5 checks) ────────────────────────────────────────────────────
    HardeningCheck(
        id="NET-001",
        category=HardeningCategory.NETWORK,
        title="Firewall activo (ufw/iptables)",
        description=(
            "El nodo debe tener un firewall habilitado que restrinja todos los "
            "puertos no utilizados. Sin firewall, cualquier servicio expuesto "
            "es alcanzable desde Internet."
        ),
        severity="CRITICAL",
        check_command="ufw status | grep -i active || iptables -L -n | head -5",
        remediation=(
            "sudo ufw enable && "
            "sudo ufw default deny incoming && "
            "sudo ufw allow 5000/tcp comment 'UPB-Chain API' && "
            "sudo ufw allow 22/tcp comment 'SSH'"
        ),
    ),
    HardeningCheck(
        id="NET-002",
        category=HardeningCategory.NETWORK,
        title="Puerto API REST restringido a LAN",
        description=(
            "El puerto de la API REST no debe estar expuesto a Internet; "
            "solo a la red local de la UPB (192.168.x.x o 10.x.x.x)."
        ),
        severity="HIGH",
        check_command="ss -tlnp | grep ':5000' || netstat -tlnp | grep ':5000'",
        remediation=(
            "Configurar Flask/gunicorn para escuchar en 127.0.0.1:5000 "
            "y colocar un proxy nginx con restricción de IP por subred."
        ),
    ),
    HardeningCheck(
        id="NET-003",
        category=HardeningCategory.NETWORK,
        title="TLS/HTTPS en API REST",
        description=(
            "Las comunicaciones de la API deben ir cifradas con TLS 1.2+. "
            "Sin TLS, las credenciales y datos de transacciones viajan en claro."
        ),
        severity="HIGH",
        check_command=(
            "curl -sk https://localhost:5000/chain 2>&1 | python3 -m json.tool"
        ),
        remediation=(
            "Generar un certificado (Let's Encrypt o auto-firmado) y habilitar "
            "HTTPS en el servidor. Con nginx: ssl_protocols TLSv1.2 TLSv1.3;"
        ),
    ),
    HardeningCheck(
        id="NET-004",
        category=HardeningCategory.NETWORK,
        title="Límite de conexiones P2P por subred /24",
        description=(
            "Limitar el número máximo de conexiones entrantes desde la misma "
            "subred /24 (máx. 2) para prevenir el Eclipse Attack."
        ),
        severity="HIGH",
        check_command=(
            "grep -rn 'per_subnet\\|connection_limit\\|max_per_subnet' "
            "/home/upb/blockchain_upb_ia/ 2>/dev/null"
        ),
        remediation=(
            "Implementar un contador de conexiones por subred /24 en el módulo "
            "P2P y rechazar nuevas conexiones cuando superen el límite."
        ),
    ),
    HardeningCheck(
        id="NET-005",
        category=HardeningCategory.NETWORK,
        title="Lista blanca de peers P2P conocidos",
        description=(
            "El nodo debe mantener una lista de peers confiables (nodos UPB) "
            "con mayor prioridad de conexión para resistir ataques Sybil y Eclipse."
        ),
        severity="MEDIUM",
        check_command=(
            "test -f /home/upb/blockchain_upb_ia/config/trusted_peers.json "
            "&& python3 -m json.tool /home/upb/blockchain_upb_ia/config/trusted_peers.json"
        ),
        remediation=(
            "Crear config/trusted_peers.json con las IPs y claves públicas "
            "de los nodos UPB conocidos y cargarlos en el arranque del nodo."
        ),
    ),

    # ── CRYPTO (4 checks) ─────────────────────────────────────────────────────
    HardeningCheck(
        id="CRY-001",
        category=HardeningCategory.CRYPTO,
        title="ECDSA secp256k1 con clave de 256 bits",
        description=(
            "Las claves criptográficas deben usar ECDSA secp256k1 (equivalente "
            "a RSA-3072). El uso de curvas más débiles compromete todas las firmas."
        ),
        severity="CRITICAL",
        check_command=(
            "python3 -c \"from security.crypto_utils import generate_keypair; "
            "priv, pub = generate_keypair(); print('OK — priv len:', len(priv))\""
        ),
        remediation=(
            "Verificar que crypto_utils.py use ec.SECP256K1() y no curvas más "
            "débiles como P-192 o P-224."
        ),
    ),
    HardeningCheck(
        id="CRY-002",
        category=HardeningCategory.CRYPTO,
        title="Sin algoritmos débiles (MD5, SHA-1)",
        description=(
            "El código no debe usar MD5 ni SHA-1 para propósitos de seguridad. "
            "Ambos tienen colisiones conocidas y son inadecuados para firmas o MACs."
        ),
        severity="HIGH",
        check_command=(
            "grep -rn 'hashlib\\.md5\\|hashlib\\.sha1\\b' "
            "/home/upb/blockchain_upb_ia/security/ --include='*.py'"
        ),
        remediation=(
            "Reemplazar toda ocurrencia de MD5/SHA-1 con SHA-256, SHA3-256 "
            "o BLAKE2b en los módulos de seguridad."
        ),
    ),
    HardeningCheck(
        id="CRY-003",
        category=HardeningCategory.CRYPTO,
        title="Nonces AES-GCM únicos por operación (os.urandom)",
        description=(
            "Cada operación de cifrado AES-GCM debe generar un nonce aleatorio "
            "único (12 bytes de os.urandom). Reutilizar el nonce destruye la "
            "confidencialidad y autenticidad del cifrado."
        ),
        severity="CRITICAL",
        check_command=(
            "grep -n 'os.urandom' "
            "/home/upb/blockchain_upb_ia/security/crypto_utils.py"
        ),
        remediation=(
            "Asegurar que encrypt_aes_gcm() llame a os.urandom(12) en cada "
            "invocación. Nunca usar un nonce fijo o predecible."
        ),
    ),
    HardeningCheck(
        id="CRY-004",
        category=HardeningCategory.CRYPTO,
        title="PBKDF2 con >= 100 000 iteraciones",
        description=(
            "La derivación de contraseñas debe usar al menos 100 000 iteraciones "
            "para ser resistente a ataques de fuerza bruta con GPU/ASIC."
        ),
        severity="HIGH",
        check_command=(
            "grep -n '100_000\\|100000' "
            "/home/upb/blockchain_upb_ia/security/crypto_utils.py"
        ),
        remediation=(
            "Ajustar el parámetro iterations en derive_key() a >=100 000. "
            "Para mayor seguridad, considerar Argon2id (memory-hard)."
        ),
    ),

    # ── OS (5 checks) ─────────────────────────────────────────────────────────
    HardeningCheck(
        id="OS-001",
        category=HardeningCategory.OS,
        title="Actualizaciones de seguridad del sistema aplicadas",
        description=(
            "El sistema operativo del RPi5 debe tener los últimos parches de "
            "seguridad instalados para mitigar vulnerabilidades del kernel y librerías."
        ),
        severity="HIGH",
        check_command=(
            "apt list --upgradable 2>/dev/null | grep -i security | wc -l"
        ),
        remediation=(
            "sudo apt update && sudo apt upgrade -y && sudo apt autoremove -y. "
            "Configurar actualizaciones automáticas de seguridad con unattended-upgrades."
        ),
    ),
    HardeningCheck(
        id="OS-002",
        category=HardeningCategory.OS,
        title="Proceso blockchain ejecutado como usuario no privilegiado",
        description=(
            "El nodo UPB-Chain no debe correr como root. Si el proceso es "
            "comprometido, el atacante no debe obtener acceso de superusuario."
        ),
        severity="CRITICAL",
        check_command=(
            "ps aux | grep -E 'python.*app\\.py|gunicorn|flask' "
            "| grep -v root | grep -v grep"
        ),
        remediation=(
            "Crear usuario dedicado: sudo useradd -r -s /bin/false upbchain. "
            "Ejecutar el servicio systemd con User=upbchain."
        ),
    ),
    HardeningCheck(
        id="OS-003",
        category=HardeningCategory.OS,
        title="Permisos restrictivos en archivos de claves privadas",
        description=(
            "Los archivos que contengan claves privadas deben tener permisos 600 "
            "(solo lectura/escritura por el dueño). Permisos más amplios permiten "
            "que otros usuarios del sistema lean las claves."
        ),
        severity="CRITICAL",
        check_command=(
            "find /home/upb/blockchain_upb_ia/ "
            "-name '*.pem' -o -name '*.key' -o -name 'wallet*' 2>/dev/null "
            "| xargs ls -la 2>/dev/null"
        ),
        remediation=(
            "chmod 600 <archivo_de_clave> && "
            "chown upbchain:upbchain <archivo_de_clave>"
        ),
    ),
    HardeningCheck(
        id="OS-004",
        category=HardeningCategory.OS,
        title="Partición /data separada con cuota de disco",
        description=(
            "Los datos de la blockchain deben almacenarse en una partición separada "
            "para que un ataque de storage bloat no llene el sistema raíz y "
            "no deje el OS inoperable."
        ),
        severity="MEDIUM",
        check_command=(
            "df -h /data 2>/dev/null || echo 'Sin partición /data separada'"
        ),
        remediation=(
            "Crear una partición dedicada /data en la SD/NVMe del RPi5 y montar "
            "los datos de la blockchain allí. Configurar alertas al 80 % de uso."
        ),
    ),
    HardeningCheck(
        id="OS-005",
        category=HardeningCategory.OS,
        title="Journald/syslog habilitado y configurado",
        description=(
            "El sistema de logs del OS debe estar activo para auditoría forense "
            "y detección de incidentes a nivel de sistema operativo."
        ),
        severity="HIGH",
        check_command=(
            "systemctl is-active systemd-journald 2>/dev/null "
            "&& journalctl --no-pager -n 5"
        ),
        remediation=(
            "sudo systemctl enable --now systemd-journald. "
            "Configurar Storage=persistent en /etc/systemd/journald.conf."
        ),
    ),

    # ── APP (5 checks) ────────────────────────────────────────────────────────
    HardeningCheck(
        id="APP-001",
        category=HardeningCategory.APP,
        title="Validación de tamaño máximo de payload de TX",
        description=(
            "La API debe rechazar transacciones con payload mayor al límite "
            "configurado para prevenir el Storage Bloat Attack en el RPi5 "
            "(128 GB de disco disponible)."
        ),
        severity="HIGH",
        check_command=(
            "grep -rn 'MAX_PAYLOAD\\|max_payload\\|MAX_CONTENT_LENGTH' "
            "/home/upb/blockchain_upb_ia/ --include='*.py'"
        ),
        remediation=(
            "Agregar MAX_PAYLOAD_BYTES = 10_000 y validar "
            "len(json.dumps(tx)) <= MAX_PAYLOAD_BYTES en el endpoint POST /transactions/new."
        ),
    ),
    HardeningCheck(
        id="APP-002",
        category=HardeningCategory.APP,
        title="Rate limiting activado en API REST",
        description=(
            "Los endpoints de la API deben tener límite de velocidad para prevenir "
            "ataques de denegación de servicio y spam de transacciones."
        ),
        severity="HIGH",
        check_command=(
            "grep -rn 'TX_RATE_LIMIT\\|flask_limiter\\|rate_limit\\|RateLimiter' "
            "/home/upb/blockchain_upb_ia/ --include='*.py'"
        ),
        remediation=(
            "Integrar Flask-Limiter o usar SecurityMonitor.on_transaction() "
            "para detectar y rechazar direcciones con exceso de peticiones."
        ),
    ),
    HardeningCheck(
        id="APP-003",
        category=HardeningCategory.APP,
        title="Backups automáticos y verificados de la blockchain",
        description=(
            "Debe existir un proceso de backup automático periódico de la "
            "cadena de bloques con verificación de integridad por SHA-256."
        ),
        severity="HIGH",
        check_command=(
            "crontab -l 2>/dev/null | grep -i backup "
            "|| ls -lah /home/upb/backups/ 2>/dev/null"
        ),
        remediation=(
            "Crear scripts/backup.sh con rsync + sha256sum y agregar cron: "
            "'0 2 * * * /home/upb/blockchain_upb_ia/scripts/backup.sh'"
        ),
    ),
    HardeningCheck(
        id="APP-004",
        category=HardeningCategory.APP,
        title="Secretos en variables de entorno (sin hardcoded)",
        description=(
            "Claves API, contraseñas y secretos NO deben estar hardcoded en el "
            "código fuente. Un secreto en el repo es un secreto comprometido."
        ),
        severity="CRITICAL",
        check_command=(
            r"grep -rn 'SECRET_KEY\s*=\s*[\"'\''][^\"'\''$]' "
            "/home/upb/blockchain_upb_ia/ --include='*.py' | grep -v test"
        ),
        remediation=(
            "Mover todos los secretos a variables de entorno o a un archivo "
            ".env excluido del repositorio (.gitignore). Usar python-dotenv."
        ),
    ),
    HardeningCheck(
        id="APP-005",
        category=HardeningCategory.APP,
        title="Rotación de logs de aplicación configurada",
        description=(
            "Los logs de la aplicación deben rotarse automáticamente para "
            "evitar el llenado del disco por acumulación de registros."
        ),
        severity="MEDIUM",
        check_command=(
            "cat /etc/logrotate.d/upbchain 2>/dev/null "
            "|| ls -lh /home/upb/blockchain_upb_ia/logs/ 2>/dev/null"
        ),
        remediation=(
            "Crear /etc/logrotate.d/upbchain con política: daily, rotate 30, "
            "compress, missingok, notifempty."
        ),
    ),

    # ── MONITORING (5 checks) ─────────────────────────────────────────────────
    HardeningCheck(
        id="MON-001",
        category=HardeningCategory.MONITORING,
        title="SecurityMonitor inicializado en el nodo",
        description=(
            "El módulo security.monitor.SecurityMonitor debe estar instanciado "
            "y activo en producción para detectar ataques en tiempo real."
        ),
        severity="CRITICAL",
        check_command=(
            "python3 -c \"from security.monitor import SecurityMonitor; "
            "m = SecurityMonitor(); print('OK — monitor activo')\""
        ),
        remediation=(
            "Inicializar SecurityMonitor en api/app.py al arranque y conectarlo "
            "al ciclo de vida de la blockchain (on_block, on_transaction, etc.)."
        ),
    ),
    HardeningCheck(
        id="MON-002",
        category=HardeningCategory.MONITORING,
        title="Callback de alertas críticas configurado",
        description=(
            "El SecurityMonitor debe tener un callback para alertas CRITICAL "
            "que notifique a un administrador (email, Telegram, log externo)."
        ),
        severity="HIGH",
        check_command=(
            "grep -rn 'alert_callback\\|SecurityMonitor(' "
            "/home/upb/blockchain_upb_ia/api/ --include='*.py'"
        ),
        remediation=(
            "Pasar alert_callback=<función_de_notificación> al constructor de "
            "SecurityMonitor. Ejemplo: SecurityMonitor(alert_callback=send_email_alert)."
        ),
    ),
    HardeningCheck(
        id="MON-003",
        category=HardeningCategory.MONITORING,
        title="Logs de seguridad persistentes en disco",
        description=(
            "Los eventos de seguridad detectados por el monitor deben persistirse "
            "en disco para auditoría forense posterior."
        ),
        severity="HIGH",
        check_command=(
            "python3 -c \"import logging; "
            "h = logging.getLogger('upb_chain.security'); "
            "print(len(h.handlers), 'handlers configurados')\""
        ),
        remediation=(
            "Agregar un FileHandler al logger 'upb_chain.security' apuntando a "
            "/var/log/upbchain/security.log con nivel WARNING."
        ),
    ),
    HardeningCheck(
        id="MON-004",
        category=HardeningCategory.MONITORING,
        title="Monitoreo de uptime externo configurado",
        description=(
            "Debe existir un servicio externo (healthcheck URL, watchdog systemd) "
            "que detecte si el nodo cae y genere una alerta automática."
        ),
        severity="MEDIUM",
        check_command=(
            "curl -sf http://localhost:5000/health 2>/dev/null "
            "| python3 -m json.tool"
        ),
        remediation=(
            "Exponer GET /health y configurar un monitor externo "
            "(UptimeRobot, Nagios) o un watchdog systemd con WatchdogSec=30s."
        ),
    ),
    HardeningCheck(
        id="MON-005",
        category=HardeningCategory.MONITORING,
        title="Detección de reorganización de cadena activa",
        description=(
            "El nodo debe alertar ante reorganizaciones de más de 3 bloques, "
            "indicador clave de un posible ataque del 51 %."
        ),
        severity="HIGH",
        check_command=(
            "python3 -c \""
            "from security.monitor import SecurityMonitor; "
            "m = SecurityMonitor(); m.on_chain_reorg(4); "
            "print(m.get_alerts()[0]['level'])\""
        ),
        remediation=(
            "Conectar el evento de reorganización del core de la blockchain al "
            "método on_chain_reorg() del SecurityMonitor en api/app.py."
        ),
    ),
]


# ── Auditor ───────────────────────────────────────────────────────────────────

class HardeningAuditor:
    """
    Ejecuta el checklist de hardening y genera un reporte de estado.

    Los checks de NETWORK y OS se marcan como 'MANUAL' porque requieren
    acceso al sistema operativo (firewall, permisos, usuarios).
    Los checks de CRYPTO, APP y MONITORING se evalúan mediante
    inspección Python pura sin subprocess ni comandos shell, lo que
    garantiza compatibilidad con Windows y Linux.
    """

    def __init__(self) -> None:
        self.checks: List[HardeningCheck] = HARDENING_CHECKS
        self._last_audit: Optional[dict] = None

    # ── API pública ───────────────────────────────────────────────────────────

    def run_audit(self) -> dict:
        """
        Ejecuta todos los checks y retorna el resultado consolidado.

        Returns:
            Diccionario con:
              score   (int  0-100): porcentaje de checks pasados.
              passed  (int): checks con estado PASS.
              failed  (int): checks con estado FAIL.
              manual  (int): checks que requieren verificación manual.
              total   (int): número total de checks.
              items   (list): detalle por check con id, title, category,
                              severity y status.
        """
        items = []
        passed = failed = manual = 0

        for check in self.checks:
            status = self._evaluate_check(check)
            items.append({
                "id":       check.id,
                "title":    check.title,
                "category": check.category.value,
                "severity": check.severity,
                "status":   status,
            })
            if status == "PASS":
                passed += 1
            elif status == "FAIL":
                failed += 1
            else:
                manual += 1

        total = len(self.checks)
        score = int(passed / total * 100) if total > 0 else 0

        self._last_audit = {
            "score":  score,
            "passed": passed,
            "failed": failed,
            "manual": manual,
            "total":  total,
            "items":  items,
        }
        return self._last_audit

    def generate_report(self) -> str:
        """
        Genera un reporte markdown del audit.

        Si no se ha ejecutado run_audit() previamente, lo ejecuta ahora.

        Returns:
            String con el reporte en formato Markdown.
        """
        audit = self._last_audit if self._last_audit else self.run_audit()

        _sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        sorted_items = sorted(
            audit["items"],
            key=lambda x: (x["category"], _sev_order.get(x["severity"], 4)),
        )

        lines = [
            "# UPB-Chain — Hardening Security Audit",
            "",
            f"**Score:** {audit['score']}/100  |  "
            f"**PASS:** {audit['passed']}  |  "
            f"**FAIL:** {audit['failed']}  |  "
            f"**MANUAL:** {audit['manual']}  |  "
            f"**Total:** {audit['total']}",
            "",
            "## Checks",
            "",
            "| ID | Categoria | Titulo | Severidad | Estado |",
            "|---|---|---|---|---|",
        ]

        for item in sorted_items:
            lines.append(
                f"| {item['id']} | {item['category']} | {item['title']} "
                f"| {item['severity']} | {item['status']} |"
            )

        # Sección de items críticos pendientes
        critical_pending = [
            i for i in audit["items"]
            if i["severity"] == "CRITICAL" and i["status"] != "PASS"
        ]

        lines += ["", "## Items Criticos Pendientes", ""]

        if critical_pending:
            for item in critical_pending:
                check = next((c for c in self.checks if c.id == item["id"]), None)
                if check:
                    lines += [
                        f"### [{item['status']}] {item['id']}: {item['title']}",
                        f"- **Categoria:** {item['category']}",
                        f"- **Descripcion:** {check.description}",
                        f"- **Remediacion:** {check.remediation}",
                        f"- **Verificacion:** `{check.check_command}`",
                        "",
                    ]
        else:
            lines.append("Todos los items criticos han sido verificados o pasados.")

        return "\n".join(lines)

    def get_critical_items(self) -> List[HardeningCheck]:
        """
        Retorna los checks de severidad CRITICAL que no han pasado.

        Si no se ha ejecutado run_audit() previamente, retorna todos
        los checks CRITICAL del listado (estado desconocido).

        Returns:
            Lista de HardeningCheck con severity == 'CRITICAL' y status != 'PASS'.
        """
        if not self._last_audit:
            return [c for c in self.checks if c.severity == "CRITICAL"]

        pending_ids = {
            item["id"]
            for item in self._last_audit["items"]
            if item["severity"] == "CRITICAL" and item["status"] != "PASS"
        }
        return [c for c in self.checks if c.id in pending_ids]

    # ── Evaluación interna ────────────────────────────────────────────────────

    def _evaluate_check(self, check: HardeningCheck) -> str:
        """
        Evalúa un check individual usando solo inspección Python pura.

        Returns:
            'PASS'   — el check se verificó y aprobó.
            'FAIL'   — el check se verificó y falló.
            'MANUAL' — el check requiere verificación humana/shell.
        """
        cat = check.category
        cid = check.id

        # NETWORK y OS siempre requieren acceso al sistema operativo
        if cat in (HardeningCategory.NETWORK, HardeningCategory.OS):
            return "MANUAL"

        try:
            # ── CRYPTO ───────────────────────────────────────────────────────
            if cid == "CRY-001":
                src = self._read_module_source("security.crypto_utils")
                if src:
                    return "PASS" if "SECP256K1" in src else "FAIL"

            elif cid == "CRY-002":
                src = self._read_module_source("security.crypto_utils")
                if src:
                    has_weak = (
                        "hashlib.md5" in src.lower()
                        or bool(re.search(r"hashlib\.sha1\b", src, re.IGNORECASE))
                    )
                    return "FAIL" if has_weak else "PASS"

            elif cid == "CRY-003":
                src = self._read_module_source("security.crypto_utils")
                if src:
                    return "PASS" if "os.urandom" in src else "FAIL"

            elif cid == "CRY-004":
                src = self._read_module_source("security.crypto_utils")
                if src:
                    has_iterations = "100_000" in src or "100000" in src
                    return "PASS" if has_iterations else "FAIL"

            # ── APP ───────────────────────────────────────────────────────────
            elif cid == "APP-001":
                for mod in ("api.app", "blockchain.blockchain"):
                    src = self._read_module_source(mod)
                    if src and re.search(
                        r"MAX_PAYLOAD|max_payload|MAX_CONTENT_LENGTH", src
                    ):
                        return "PASS"
                return "FAIL"

            elif cid == "APP-002":
                for mod in ("api.app", "security.monitor"):
                    src = self._read_module_source(mod)
                    if src and re.search(
                        r"TX_RATE_LIMIT|rate_limit|flask_limiter|RateLimiter", src
                    ):
                        return "PASS"
                return "MANUAL"

            elif cid == "APP-003":
                # Verificar existencia de directorio de backups o script de backup
                possible_paths = [
                    os.path.join(os.getcwd(), "scripts", "backup.sh"),
                    os.path.join(os.getcwd(), "backups"),
                    "/home/upb/backups",
                ]
                for p in possible_paths:
                    if os.path.exists(p):
                        return "PASS"
                return "MANUAL"

            elif cid == "APP-004":
                # Verificar que no haya secretos hardcoded en el código de API
                src = self._read_module_source("api.app")
                if src:
                    pattern = re.compile(
                        r'(?i)(secret_key|flask_secret|password)\s*=\s*["\'][^"\'$\s]{4,}'
                    )
                    return "FAIL" if pattern.search(src) else "PASS"
                return "MANUAL"

            elif cid == "APP-005":
                import logging.handlers as _lh
                root_logger  = logging.getLogger()
                app_logger   = logging.getLogger("upb_chain")
                all_handlers = root_logger.handlers + app_logger.handlers
                has_file = any(
                    isinstance(h, (logging.FileHandler, _lh.RotatingFileHandler))
                    for h in all_handlers
                )
                return "PASS" if has_file else "MANUAL"

            # ── MONITORING ────────────────────────────────────────────────────
            elif cid == "MON-001":
                spec = importlib.util.find_spec("security.monitor")
                if spec is None:
                    return "FAIL"
                import security.monitor as _mon
                return "PASS" if hasattr(_mon, "SecurityMonitor") else "FAIL"

            elif cid == "MON-002":
                src = self._read_module_source("security.monitor")
                if src:
                    return "PASS" if "alert_callback" in src else "FAIL"

            elif cid == "MON-003":
                sec_logger = logging.getLogger("upb_chain.security")
                parent     = logging.getLogger("upb_chain")
                handlers = sec_logger.handlers + parent.handlers + logging.getLogger().handlers
                has_file = any(isinstance(h, logging.FileHandler) for h in handlers)
                return "PASS" if has_file else "FAIL"

            elif cid == "MON-004":
                return "MANUAL"

            elif cid == "MON-005":
                src = self._read_module_source("security.monitor")
                if src:
                    return "PASS" if "on_chain_reorg" in src else "FAIL"

        except Exception:
            pass

        return "MANUAL"

    @staticmethod
    def _read_module_source(module_name: str) -> Optional[str]:
        """
        Lee el código fuente de un módulo Python sin importarlo ni ejecutarlo.

        Compatible con Windows y Linux usando importlib.util.find_spec().

        Args:
            module_name: Nombre punteado del módulo (ej. 'security.crypto_utils').

        Returns:
            Contenido del archivo .py como string, o None si no se encuentra.
        """
        try:
            spec = importlib.util.find_spec(module_name)
            if spec and spec.origin and os.path.isfile(spec.origin):
                with open(spec.origin, "r", encoding="utf-8") as fh:
                    return fh.read()
        except Exception:
            pass
        return None
