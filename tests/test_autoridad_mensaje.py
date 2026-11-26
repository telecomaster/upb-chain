"""Un 503 por falta de autoridad dice si la llave no existe o no es la del génesis."""
from api.cliente_asgi import ClienteASGI
from blockchain.core.wallet import Wallet

from tests.helpers import make_app

CUERPO = {"issuer_address": "UPBx", "institution_code": "UPB"}


def test_llave_que_no_es_la_del_genesis_se_explica(tmp_path):
    # Es lo que pasa tras scripts/crear_llave_autoridad.py: la dirección nueva no es la del génesis.
    ajena = tmp_path / "ajena.json"
    Wallet.generate().export(str(ajena))
    app = make_app(tmp_path, authority_key_file=str(ajena))
    r = ClienteASGI(app).post("/credentials/issuers", json=CUERPO)
    assert r.status_code == 503
    assert "génesis" in r.json()["detail"]


def test_llave_ausente_se_explica(tmp_path):
    app = make_app(tmp_path)
    r = ClienteASGI(app).post("/credentials/issuers", json=CUERPO)
    assert r.status_code == 503
    assert "no existe" in r.json()["detail"]
