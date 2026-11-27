"""Freno térmico LOCAL del minero (idea 5 del roadmap).

IMPORTANTE: esto NO toca la dificultad ni la validación. La dificultad es consenso
(sale solo de los datos de la cadena, `Blockchain._calculate_difficulty()`) y la
temperatura difiere entre nodos; un nodo que la usara para validar se bifurcaría.
Aquí solo se decide cuánto del tiempo el hilo de minado trabaja: el minero hace
pausas cortas entre lotes de nonces para bajar su ciclo de trabajo ("duty").
Los bloques resultantes son idénticos en validez a los de un minado a toda velocidad.

Curva (hipótesis a MEDIR en la Pi, no un resultado): ciclo 1.0 por debajo de
`soft_c`; baja linealmente hasta `min_duty` en `hard_c`; por encima se queda en `min_duty`.
El firmware de la Pi 5 limita la frecuencia por su cuenta a 85 °C.
Sin sensor (p. ej. Windows) el controlador devuelve ciclo 1.0 y temperatura None.
"""
import subprocess
import time
from typing import Callable, Optional

RUTA_SYSFS = "/sys/class/thermal/thermal_zone0/temp"


def leer_temperatura_soc(ruta: str = RUTA_SYSFS, usar_vcgencmd: bool = True) -> Optional[float]:
    """Temperatura del SoC en °C o None. Primero sysfs (milésimas de grado), luego `vcgencmd`."""
    try:
        with open(ruta, encoding="utf-8") as f:
            return int(f.read().strip()) / 1000.0
    except (OSError, ValueError):
        pass
    if usar_vcgencmd:
        try:
            r = subprocess.run(["vcgencmd", "measure_temp"], capture_output=True, text=True,
                               timeout=3, check=False)
            if r.returncode == 0 and "temp=" in r.stdout:
                return float(r.stdout.split("temp=")[1].split("'")[0])
        except (OSError, ValueError, subprocess.SubprocessError):
            pass
    return None


def ciclo_para(temp_c: Optional[float], soft_c: float, hard_c: float, min_duty: float) -> float:
    """Ciclo de trabajo (min_duty..1.0) para una temperatura; sin lectura = 1.0."""
    if temp_c is None or temp_c <= soft_c:
        return 1.0
    if temp_c >= hard_c:
        return min_duty
    frac = (temp_c - soft_c) / (hard_c - soft_c)
    return 1.0 - frac * (1.0 - min_duty)


class FrenoTermico:
    """Lee la temperatura (como mucho cada `intervalo_s`) y entrega el ciclo de trabajo."""

    def __init__(self, soft_c: float = 70.0, hard_c: float = 80.0, min_duty: float = 0.2,
                 fuente: Optional[Callable[[], Optional[float]]] = None,
                 intervalo_s: float = 1.0,
                 reloj: Callable[[], float] = time.monotonic):
        if hard_c <= soft_c:
            raise ValueError("hard_c debe ser mayor que soft_c")
        if not 0.0 < min_duty <= 1.0:
            raise ValueError("min_duty debe estar en (0, 1]")
        self.soft_c, self.hard_c, self.min_duty = soft_c, hard_c, min_duty
        self._fuente = fuente or leer_temperatura_soc
        self._intervalo = intervalo_s
        self._reloj = reloj
        self._ultima_lectura: Optional[float] = None
        self.temperatura_c: Optional[float] = None
        self.ciclo = 1.0

    def actualizar(self) -> float:
        """Devuelve el ciclo vigente, releyendo el sensor si ya pasó el intervalo."""
        ahora = self._reloj()
        if self._ultima_lectura is None or ahora - self._ultima_lectura >= self._intervalo:
            self._ultima_lectura = ahora
            self.temperatura_c = self._fuente()
            self.ciclo = ciclo_para(self.temperatura_c, self.soft_c, self.hard_c, self.min_duty)
        return self.ciclo

    def pausa_para(self, trabajo_s: float) -> float:
        """Segundos de pausa tras `trabajo_s` de trabajo para lograr el ciclo vigente."""
        d = self.actualizar()
        return 0.0 if d >= 1.0 else trabajo_s * (1.0 / d - 1.0)

    def estado(self) -> dict:
        return {"temperature_c": self.temperatura_c, "duty": round(self.ciclo, 3),
                "soft_c": self.soft_c, "hard_c": self.hard_c, "min_duty": self.min_duty}
