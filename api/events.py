"""Bus de eventos en proceso para el dashboard en vivo (P2-7).

Se eligió SSE (``GET /events``) y no WebSocket: el flujo es solo servidor -> navegador,
``EventSource`` reconecta solo, viaja por HTTP normal (sin handshake ni librería extra) y
es legible en un paper. Cada app tiene su propio ``EventBus`` (``NodeState.events``).

Los publicadores pueden ser hilos cualquiera (minado, P2P): ``publish`` nunca bloquea ni
espera al cliente. Cada suscriptor tiene una cola acotada (``deque(maxlen)``): si el
cliente es lento se descarta el evento más viejo. El event loop del suscriptor se
despierta con ``loop.call_soon_threadsafe``.
"""
import asyncio
import json
import threading
import time
from collections import deque
from typing import Optional

COLA_MAXIMA = 256
HEARTBEAT_S = 15.0


class Subscription:
    """Cola acotada de un cliente; se crea desde su event loop."""

    def __init__(self, maxlen: int = COLA_MAXIMA):
        self._loop = asyncio.get_running_loop()
        self._items: deque = deque(maxlen=maxlen)   # al llenarse descarta el más viejo
        self._lock = threading.Lock()
        self._wakeup = asyncio.Event()
        self.dropped = 0

    def _push(self, item: dict) -> None:            # se llama desde cualquier hilo
        with self._lock:
            if len(self._items) == self._items.maxlen:
                self.dropped += 1
            self._items.append(item)
        try:
            self._loop.call_soon_threadsafe(self._wakeup.set)
        except RuntimeError:                         # el loop ya se cerró
            pass

    def pending(self) -> int:
        with self._lock:
            return len(self._items)

    async def get(self, timeout: Optional[float] = None) -> Optional[dict]:
        """Siguiente evento; ``None`` si pasa ``timeout`` sin eventos."""
        while True:
            with self._lock:
                if self._items:
                    return self._items.popleft()
                self._wakeup.clear()
            try:
                await asyncio.wait_for(self._wakeup.wait(), timeout)
            except asyncio.TimeoutError:
                return None


class EventBus:
    def __init__(self, maxlen: int = COLA_MAXIMA):
        self._maxlen = maxlen
        self._subs: set = set()
        self._lock = threading.Lock()

    def subscribe(self) -> Subscription:
        sub = Subscription(self._maxlen)
        with self._lock:
            self._subs.add(sub)
        return sub

    def unsubscribe(self, sub: Subscription) -> None:
        with self._lock:
            self._subs.discard(sub)

    def subscriber_count(self) -> int:
        with self._lock:
            return len(self._subs)

    def publish(self, event: str, data: Optional[dict] = None) -> None:
        item = {"event": event, "data": data or {}, "ts": time.time()}
        with self._lock:
            subs = list(self._subs)
        for sub in subs:
            sub._push(item)


def format_sse(item: dict) -> str:
    return f"event: {item['event']}\ndata: {json.dumps(item['data'], default=str)}\n\n"


async def sse_stream(bus: EventBus, is_disconnected=None, heartbeat: float = HEARTBEAT_S):
    """Generador SSE: eventos y un comentario ``: hb`` cada ``heartbeat`` segundos."""
    sub = bus.subscribe()
    try:
        yield ": conectado\n\n"
        while True:
            item = await sub.get(timeout=heartbeat)
            if item is None:
                if is_disconnected is not None and await is_disconnected():
                    return
                yield ": hb\n\n"
            else:
                yield format_sse(item)
    finally:
        bus.unsubscribe(sub)
