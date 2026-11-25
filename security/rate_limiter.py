"""
Límite de tasa de TX por emisor (P1-5).

Política de admisión al mempool, NO de consenso: nunca se usa al validar
bloques, de modo que dos nodos con límites distintos siguen aceptando la
misma cadena. Ventana deslizante en memoria; el reloj es inyectable para
poder probarla sin dormir.
"""
import threading
import time
from collections import defaultdict, deque
from typing import Callable, Deque, Dict, Tuple


class TxRateLimiter:
    def __init__(self, limit: int = 100, window: float = 60.0,
                 clock: Callable[[], float] = time.time):
        self.limit = limit
        self.window = window
        self._clock = clock
        self._events: Dict[str, Deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, sender: str) -> Tuple[bool, int]:
        """Registra un intento. Devuelve (permitido, TX en la ventana).

        Los intentos rechazados no se cuentan, así que el emisor vuelve a
        poder enviar cuando salen de la ventana las TX aceptadas.
        """
        now = self._clock()
        with self._lock:
            q = self._events[sender]
            while q and q[0] <= now - self.window:
                q.popleft()
            if len(q) >= self.limit:
                return False, len(q)
            q.append(now)
            return True, len(q)
