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

## Generador de QR (P1-12, panel del emisor)

`qrcode-generator.esm.js`: `qrcode-generator` **1.4.4** (MIT, Kazuhiko Arase), copiado de npm sin
cambios salvo quitar el envoltorio UMD final y exportarlo como ESM. Licencia: `LICENSE-qrcode-generator.txt`.

## Gráficos y estilos del panel (sin CDN, funciona sin internet)

El panel `/` ya no carga nada de internet (nodos en una LAN de campus que puede no tener salida).

- `chart.umd.js`: `chart.js` **4.4.7** (MIT), build UMD de `chart.js/dist/chart.umd.js` sin cambios (expone `Chart`
  global; el panel usa `new Chart(ctx, {...})`, API 4.x). Licencia: `LICENSE-chartjs.txt`.
  SHA-256: `2812cb8825fdc57469eb2f7bb055e9429244e599920511ee477e828499b632cb`
- `tailwind.css`: CSS estático (~6 KB) generado una vez con `tailwindcss` **3.4.17** a partir de `index.html`,
  en lugar del script "play CDN" (pesado, compila en el navegador). Fuente: `tailwind.in.css`.
  SHA-256: `0cb1a194bbe5b141b85cb6adabcf8e7cf286d887b8f0dfb64c4d9f3170dbe9d8`
  Regenerar tras usar clases Tailwind nuevas en la plantilla (solo el desarrollador; el despliegue no necesita Node):

```
npm i tailwindcss@3.4.17
npx tailwindcss -i dashboard/static/vendor/tailwind.in.css -o dashboard/static/vendor/tailwind.css --content "dashboard/templates/index.html" --minify
```

Luego actualice el hash aquí. `tests/test_sin_cdn.py` falla si una plantilla referencia un script/hoja externa o si los hashes no coinciden.
