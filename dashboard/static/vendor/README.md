# Librerías vendidas (billetera web, P2-1)

`noble-secp256k1.bundle.js` es un paquete ESM minificado (esbuild, `--bundle --format=esm --minify`)
de `entry.src.js`, que reúne:

- `@noble/secp256k1` **2.2.3** (MIT, Paul Miller): ECDSA secp256k1, RFC 6979.
- `@noble/hashes` **1.8.0** (MIT, Paul Miller): `ripemd160` y `sha256`.

SHA-256 de `noble-secp256k1.bundle.js`:

```
99628cd0f16df1dd8cdb352f99db0ac32e1331c7e942404cded43258f45c6755
```

Un test (`tests/test_billetera.py`) comprueba que este hash coincide con el archivo.
Para regenerar: `npm i @noble/secp256k1@2.2.3 @noble/hashes@1.8.0 esbuild` y
`npx esbuild entry.src.js --bundle --format=esm --minify --outfile=noble-secp256k1.bundle.js`;
luego actualice el hash aquí. Licencias: `LICENSE-noble-*.txt`.
