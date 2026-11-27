"""Cliente HTTP síncrono sobre ``httpx.AsyncClient`` + ``ASGITransport``.

Sustituye a ``fastapi.testclient.TestClient``, que hoy avisa de deprecación
(Starlette exige ``httpx2`` y ``httpx2`` no es el paquete del proyecto). Se mantiene la
misma forma de uso que ``TestClient`` para no reescribir las pruebas síncronas:

- ``ClienteASGI(app)`` sin ``with``: cada petición corre en su propio bucle (sin lifespan),
  igual que ``TestClient``.
- ``with ClienteASGI(app) as c:``: el lifespan de la app (P2P, PBFT, temporizadores) se
  ejecuta en un bucle propio de la prueba, en un hilo de fondo, hasta salir del ``with``.
- ``client=(host, puerto)`` fija la IP remota (por defecto ``("testclient", 50000)``, como
  ``TestClient``, que la API trata como loopback).
"""
import asyncio
import threading

import httpx


class ClienteASGI:
    def __init__(self, app, client=("testclient", 50000), base_url="http://127.0.0.1"):
        self._app = app
        self._client = client
        self._base_url = base_url
        self._loop = None
        self._hilo = None
        self._ac = None
        self._lifespan = None

    # ── transporte ──────────────────────────────────────────────────────────
    def _cliente_httpx(self):
        transporte = httpx.ASGITransport(app=self._app, client=self._client)
        return httpx.AsyncClient(transport=transporte, base_url=self._base_url)

    async def _una_peticion(self, metodo, url, kwargs):
        async with self._cliente_httpx() as ac:
            return await ac.request(metodo, url, **kwargs)

    async def _con_lifespan(self, metodo, url, kwargs):
        return await self._ac.request(metodo, url, **kwargs)

    def request(self, metodo, url, **kwargs):
        if self._loop is None:   # sin ``with``: sin lifespan, un bucle por petición
            return asyncio.run(self._una_peticion(metodo, url, kwargs))
        return asyncio.run_coroutine_threadsafe(
            self._con_lifespan(metodo, url, kwargs), self._loop).result()

    def get(self, url, **kwargs):
        return self.request("GET", url, **kwargs)

    def post(self, url, **kwargs):
        return self.request("POST", url, **kwargs)

    # ── lifespan ────────────────────────────────────────────────────────────
    def __enter__(self):
        self._loop = asyncio.new_event_loop()
        self._hilo = threading.Thread(target=self._loop.run_forever, daemon=True)
        self._hilo.start()
        asyncio.run_coroutine_threadsafe(self._arrancar(), self._loop).result()
        return self

    async def _arrancar(self):
        self._ac = self._cliente_httpx()
        self._lifespan = self._app.router.lifespan_context(self._app)
        await self._lifespan.__aenter__()

    async def _parar(self):
        await self._lifespan.__aexit__(None, None, None)
        await self._ac.aclose()

    def __exit__(self, *exc):
        asyncio.run_coroutine_threadsafe(self._parar(), self._loop).result()
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._hilo.join()
        self._loop.close()
        self._loop = None
        return False
