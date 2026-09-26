# Aegis Latent Core: paquete para inversores semilla (castellano rioplatense)

**Fecha de creación:** 25 de septiembre de 2026 (2026-09-25)

Esta carpeta es la edición en castellano rioplatense del paquete para inversores de la Orden de Misión XV: los entregables D1 a D10 y la propuesta en una pantalla. La edición en inglés está en otra carpeta, `aegis_investor_pack_en/`. Las dos salen del mismo motor y usan los mismos números.

## Pesos argentinos

Cada monto en dólares lleva entre paréntesis su equivalente en pesos, calculado a **US$ 1 = ARS 1.519,50**. Es la cotización del dólar que publica el BCRA para el 24/09/2026, consultada el 25/09/2026 a las 01:13:25 UTC en:

```
https://api.bcra.gob.ar/estadisticascambiarias/v1.0/Cotizaciones/USD?fechadesde=2026-09-14&fechahasta=2026-09-24
```

La respuesta completa está guardada en `datos/fx/bcra_usd_2026-09-14_2026-09-24.json`. Su SHA-256 es `36cc00cb1d41d2c83dc58bfe0c54d7dcf9429118b967bcdaad3e849343082cc0`.

- **El modelo corre en dólares.** Los pesos convierten cada cifra a una sola cotización: no proyectan inflación ni devaluación. Para los años futuros son una referencia, no un pronóstico en pesos.
- **Etiquetas.** Cada monto en pesos hereda la etiqueta (VERIFIED, MODEL o HYPOTHESIS) del monto en dólares al que acompaña.
- **Redondeo.** En el texto, los pesos se calculan sobre el dólar tal como se muestra. En las tablas se calculan sobre el valor sin redondear, así que pueden diferir en el último dígito.
- **Abreviaturas.** “mil” = miles; “M” = millones. Los dólares se escriben “US$” porque en Argentina “$” solo significa pesos.

## Contenido

| Ruta | Qué es |
|---|---|
| `paquete_inversor_aegis.html` | El paquete. Se abre en un navegador. |
| `img/` | Los seis gráficos en castellano, generados por el motor y por nada más |
| `motor/aegis_financial_engine.py` | El único script detrás de cada tabla, gráfico y cifra del modelo. Es idéntico al de la edición en inglés. |
| `motor/requirements.txt` | Las versiones de las bibliotecas que produjeron estos archivos |
| `datos/model_tables.md` | Todas las tablas del modelo, tal como las escribió el motor |
| `datos/model_outputs.json` | Todas las salidas del modelo y todos los insumos etiquetados. Es idéntico byte a byte al de la edición en inglés. |
| `datos/fx/` | La respuesta de la API del BCRA que respalda la cotización |
| `SHA256SUMS` | Los checksums de todos los demás archivos de esta carpeta |

Hay una copia privada de la página en línea en <https://claude.ai/artifact/1yyWTdAX1KPLDPrgZr4hVz>. Solo puede abrirla su titular hasta que se comparta desde el menú “Share” de la página.

## Verificar y reproducir

```bash
sha256sum -c SHA256SUMS

python3 -m venv .venv && . .venv/bin/activate
pip install -r motor/requirements.txt
python motor/aegis_financial_engine.py --out ./reconstruccion --lang es
cmp reconstruccion/model_tables.md datos/model_tables.md
cmp reconstruccion/model_outputs.json datos/model_outputs.json
for f in img/*.png; do cmp "$f" "reconstruccion/$(basename "$f")"; done
```

Con numpy 2.4.6, matplotlib 3.11.2 y Python 3.11, el motor reprodujo byte a byte cada archivo de `img/` y de `datos/`. Otras versiones de las bibliotecas pueden mover píxeles de los gráficos, pero los números no cambian.

## Notas de lectura

- **Etiquetas.** Cada cifra lleva una etiqueta, cuyo nombre se mantiene en inglés como lo pide la misión. VERIFIED significa leída de una fuente primaria o de un artefacto conservado. MODEL es un supuesto explicitado en el texto. HYPOTHESIS no está probada, y el experimento que la valida está en D10. Cada entregable termina con un censo de sus etiquetas.
- **Idioma del código.** El código y sus comentarios están en inglés. Los textos en castellano de los gráficos y las tablas están dentro del mismo script, detrás de `--lang es`.
- **Sin conexión.** La página carga sus tipografías desde Google Fonts y dibuja sus dos diagramas con Mermaid desde jsDelivr. Sin conexión, las tipografías pasan a las del sistema y los diagramas se ven como su texto fuente.
- **Lo que este paquete no afirma.** Ninguna certificación, cumplimiento legal, admisibilidad judicial, preparación o capacidad de producción, ni aseguramiento externo. El registro de conflictos de D10.4 anota cada insumo recibido que se corrigió o se bajó de categoría, incluida la cotización usada para los pesos (fila 10) y la actualización del kit de Azure (fila 11).
- **Cambios en el motor.** 26/09/2026: se actualizó la fila TRL "Kit de despliegue en Azure" y su costo total de cierre para reflejar el commit de la misma semana del kit de Azure (<code>deploy/azure/phase0</code>, un despliegue y una medición de una VM real); un nuevo insumo VERIFIED, <code>azure_b2als_v2_chilecentral_hourly_usd</code>, registra el precio de lista de esa VM. El consumo mensual de Azure del propio fundador (US$17,54/US$44,77 en la fila 1 de D10.4) sigue sin medirse.
- **Manejo.** Son materiales de búsqueda de inversión, incorporados al repositorio `aegis-latent-core` a pedido del titular el 25/09/2026. No son documentación del producto: la única fuente de afirmaciones sobre las capacidades del producto sigue siendo `docs/CLAIMS_MATRIX.md`.
