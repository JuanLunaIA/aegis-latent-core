> **Status:** Raw, independent reviewer summaries retained for dissent and traceability. Statements below are not normalized evidence. The canonical resolution is `DOCUMENTATION_AND_COMMERCIAL_REVIEW.md` plus the final release manifest.
>
> **Resolved test-count statement:** One reviewer reported 5,518 Python tests collected under its earlier environment; another reported 5,481 without retained support. After the RustWal regression was added, the final local command `pytest -q tests/ --disable-warnings --cov=aegis --cov-fail-under=65` recorded **5,482 passed and 37 skipped** with 91.46% measured line coverage. This is the Python `tests/` result for this branch, not an aggregate multi-language marketing total.

GROUP: commercial-product-procurement-docs-post-pr99
SUMMARY:
Los ocho documentos requieren cambios; ninguno queda en no-change. El defecto dominante es de control de versión: solo README fue actualizado por PR #99 y ahora atribuye a baseline/current release v3.1.0 capacidades que llegaron cuatro días después del tag. Los otros siete siguen fechados 2026-08-18, omiten SDKs OpenAI/Anthropic, SSE pending-terminal, MMR portable, dashboard Next.js 16 y export técnico, y varios contienen la regla pre-streaming 'commit before response'. Comercialmente, las únicas cifras sustentadas por el corpus son hipótesis, no hechos: piloto fijo $10k-$30k/4-8 semanas; Production $40k-$100k anual; Enterprise $100k-$250k+ anual. No hay precio de lista validado ni ACV observado; tampoco valoración IP/startup ni costo de reposición. Las cifras verticales, valuación, replacement cost, ISO/Daubert, HIPAA/EU AI Act/MiFID compliance, SLSA 3+, no-repudio legal, monopolio y defense/tier-1 del pasted content no están sustentados y el pasted content no fue usado como evidencia.
RISKS:
- La auditoría usa locadores del HEAD exacto 45d95188; cualquier edición posterior desplazará líneas.
- El tag publicado v3.1.0 (7ba28acf) no contiene PR #99 (45d95188). Hasta un release nuevo, toda capacidad post-PR debe llamarse main/unreleased, no v3.1.0 release feature.
- `pytest --collect-only` confirmó 5,518 casos recolectados, no una ejecución exitosa completa; tampoco consolida automáticamente suites Rust, SDK TypeScript y dashboard.
- La configuración de workflows para SBOM, attestation y Cosign no prueba por sí sola que un artifact específico de 45d95188 haya sido publicado y verificado.
- No hay evidencia de precio de lista validado, ACV observado, entrevistas mínimas, pilotos pagados, conversiones, renewals o cost-to-serve. Las cifras comerciales documentadas siguen siendo hipótesis.
- No hay valoración IP/startup ni costo de reposición sustentados. Esas categorías no deben mezclarse con precio piloto, precio anual hipotético o ACV.
- LICENSE contiene AGPLv3; no hay texto completo de licencia propietaria en el repositorio. Disponibilidad, alcance y exenciones comerciales dependen de contrato y counsel.
- Formal methods cubren modelos/teoremas acotados, no una equivalencia formal end-to-end de implementación, deployment o compliance.
- El export forense es retained-memory-window y técnico; roots/timestamps necesitan trust anchor independiente. No prueba ISO/IEC 27037, Daubert o admisibilidad.
- Redacción/de-identificación y WAF son controles acotados; no prueban cobertura HIPAA Safe Harbor, universal prompt-injection detection ni legalidad de procesamiento.
- No existe evidencia auditada de superioridad competitiva, monopolio técnico, suitability defense/tier-1, soporte 24/7, HA multi-region o global ordering.

GROUP: Auditoría de claims institucionales/regulatorios frente a pasted_content.txt y PR #99
SUMMARY:
El corpus institucional actual rechaza correctamente la mayor parte de los overclaims mediante DOC-05, UC-021/026 y la matriz genérica, y PR #99 acotó adecuadamente el nuevo streaming. Sin embargo, se requieren actualizaciones P0/P1 para corregir la cita errónea del EU AI Act y cerrar controles explícitos de MiFID II/RTS 25, SLSA, Daubert, Safe Harbor e ISO/IEC 27037. Deben rechazarse certificación Daubert, cumplimiento/admisibilidad automática, no repudio legal, WORM regulatorio y SLSA 3+; sólo son defendibles capacidades técnicas estrechas, condicionadas a configuración, artefacto/run y revisión cualificada.
RISKS:
- PR #99 (merge 45d95188d40792639fdd654369765a7233bef09a, 105 archivos) avanzó SSE exact-byte terminal summary, SDKs/proofs y actualizó CLAIMS_MATRIX/CEG/DOC-01/UC-004; no modificó DOC-05 ni COMPLIANCE_MAPPING y no aporta base para elevar ISO, HIPAA, MiFID, SLSA, Daubert, WORM, no repudio o admisibilidad.
- Persisten nombres/docstrings internos de alto riesgo fuera del alcance editable: `worm_storage.py:1-4,27-40` afirma hardware/physical immutability aunque implementa `dict`; `custody_transfer.py:4-8` dice non-repudiable pese a HMAC; `mifid_record_keeper.py:6-25` usa ‘satisfying’ y afirma que un hash satisface record-keeping. Los documentos ya advierten drift semántico, pero estos tokens pueden reciclarse en marketing.
- La evidencia de supply chain es configuración de workflow, no prueba automática de que cada artefacto publicado tenga firma/atestación válida; debe conservarse URL/run, subject digest, identidad OIDC y verificación.
- La falta de filas MiFID/SLSA/Daubert en la matriz/grafo hace que los gates actuales puedan no detectar afirmaciones literales del contenido pegado.
- Los términos regulatorios deben someterse a revisión jurídica/experta y a evidencia del entorno objetivo; ninguna corrección documental convierte módulos locales en operating effectiveness, certificación o conformidad.

GROUP: Auditoría de documentación técnica posterior al PR #99 (commit 45d95188d40792639fdd654369765a7233bef09a)
SUMMARY:
Se hallaron 18 actualizaciones precisas en los 13 archivos. Bloqueadores principales: comando uvicorn roto, descripción incorrecta de RustWal como WAL autoritativo, dashboard declarado sin export pese a tenerlo, Samples descrito falsamente como la misma UI viva, vector MMR con nombre inexistente, semántica SSE no bifurcada, redacción PII presentada como incondicional, claims de admisibilidad/no repudio y baseline de tests obsoleto. Next.js real es 16.3.2, no 15. PR #99 implementa capacidades valiosas pero no sustenta los claims externos de plataforma enterprise completa, cumplimiento/certificación, Daubert, SLSA 3+ ni valoración económica.
RISKS:
- La auditoría fue estática contra main=45d9518 y el PR #99 fusionado; no se modificó ningún archivo.
- tools/docs/verify_documentation.py reporta PASS, pero solo valida estructura/enlaces requeridos y no detecta contradicciones semánticas como el módulo ASGI inexistente, el vector mal nombrado o el export omitido.
- La colección con .venv produjo 5,518 tests. La ejecución focalizada combinada abortó al recolectar sdk/python porque aegis_sdk no estaba instalado en ese entorno; debe repetirse tras pip install -e './sdk/python[dev]'. El python global tampoco tenía pytest/dependencias, por lo que no se afirma un pass post-PR completo.
- El demo falló en el intérprete global por falta de pydantic_settings antes de aplicar el comando de instalación documentado; esto no falsifica el demo, pero refuerza la necesidad de smoke tests en entorno limpio siguiendo exactamente la guía.
- No se verificaron publicación real de aegis-sdk/@aegis-latent/sdk en registros externos, comportamiento con proveedores reales, power-loss durability, trust-anchor distribution, custodia de claves ni admisibilidad jurídica.
- La reutilización de la versión 3.1.0 para cambios post-release hace ambiguas las cifras y claims; toda evidencia debería anclarse además a commit, digest y run.

GROUP: deployment-operations-security
SUMMARY:
Auditoría estática frente a PR #99 (base e7f6941, head 874445f) y el texto pegado: 26 archivos objetivo revisados, sin modificaciones. Se identificaron 11 actualizaciones, con cinco bloqueadores P0: variables/alias obsoletos, ausencia total de despliegue del dashboard, topología Helm multipod/multiworker incompatible con el WAL por proceso, imágenes `3.1.0` no ligadas al merge y perfiles Compose sin egress/Prometheus config. Las capacidades de SDK, dashboard, formal methods, streaming y supply chain existen con alcances concretos; las afirmaciones de RustWal nativo en serving, SLSA 3+, cumplimiento/certificación legal, no repudio y valoración tier-1 no están sustentadas tal como están redactadas.
RISKS:
- No se pudo ejecutar `helm lint/template` localmente porque `helm` no está instalado; la validación externa observada fue el check exitoso `CI/Helm Lint` de PR #99.
- No se pudo ejecutar `docker compose config` ni inspeccionar manifestos OCI porque Docker no está instalado en el sandbox; por tanto los fallos de runtime Compose requieren confirmación en un host Docker. La ausencia del bind `deploy/docker/prometheus.yml` sí se verificó estáticamente.
- La API de paquetes GHCR devolvió 403/404 para la identidad disponible; no se verificaron de forma independiente firma/SBOM del digest concreto de `3.1.0`.
- Al consultar PR #99 había 30 checks exitosos, 3 skipped, 1 pendiente (CLA) y Docker Build & Push skipped; no debe interpretarse el verde de tests como publicación de una imagen post-merge.
- La rama de trabajo ya contenía un directorio no trackeado `evidence/documentation_audit_2026-08-22/`; no se modificó ningún archivo del repositorio.

GROUP: auditoría de frescura documental, roadmap, gates y claims tras PR #99
SUMMARY:
Se identificaron 16 cambios concretos. Prioridad inmediata: actualizar source baselines/cutoffs del 22-08-2026; revisar el control institucional tras la modificación de tres documentos por PR #99; incorporar los gates Python SDK, TypeScript SDK y dashboard en DOCUMENT_CONTROL, CONTRIBUTING y la plantilla de PR; registrar en ROADMAP las capacidades implementadas post-v3.1.0 sin presentarlas como release; dividir el ítem de retención ya parcialmente completado; e indexar MMR_PROOF_V1 y los README de dashboard/SDK. Las dos plantillas de issue no requieren cambio. pasted_content contiene múltiples claims legal, comercial y técnicamente excesivos; en particular, 5,480 tests es incorrecto frente a 5,481 de la suite Python, Next.js 15 debe ser 16, y no hay soporte para Daubert, conformidad regulatoria, SLSA 3+, monopolio o las valoraciones económicas.
RISKS:
- Los resultados de PR #99 usados aquí provienen del cuerpo del PR y checks de GitHub; no se reejecutaron las suites, por lo que deben citarse como resultados declarados/CI, no como nueva verificación independiente.
- El status de aprobación humana de la suite institucional no pudo inferirse de un merge o check; solo es seguro afirmar que CI pasó y mantener owner/domain approval pendiente hasta un registro firmado.
- v3.1.0 sigue siendo la release pública inmutable; actualizar fechas no debe hacer parecer que capacidades Unreleased de PR #99 están incluidas en ese tag.
- Los conteos históricos de CHANGELOG líneas 40 y 83 no deben borrarse: son correctos dentro de sus baselines; el problema es la ausencia de un resultado post-PR #99 y la mezcla posterior en pasted_content.
- El inventario de corpus incluye los documentos nuevos, pero inventariado no equivale a indexado, asignado a owner o incorporado al mapa de supersession.
- Las afirmaciones de mercado, valoración, conformidad, no repudio, Daubert y SLSA requieren fuentes/evaluaciones externas adicionales; PR #99 por sí solo no las habilita.

GROUP: Auditoría de evidencia histórica y afirmaciones post-merge 45d95188d40792639fdd654369765a7233bef09a
SUMMARY:
No se modificó ningún archivo. Los informes raíz fechados, los directorios evidence por fecha y las salidas forenses generadas son registros históricos append-only: deben preservarse y ser supersedidos, nunca reescritos para acomodar #99. Después de 45d95188… falta un paquete semántico post-merge con índice, manifiesto/hash, tests y coverage exactos, verificación separada de SBOM fuente e imagen OCI, microbenchmark ligado al commit y export autorizado de alertas. De las cifras prioritarias, 5,481 y 91.82% no tienen sustento; el SBOM está verificado sólo para el baseline anterior; la firma Docker tiene evidencia de job exitoso pero no cosign verify por digest; SSE sí tiene cifras, estrictamente in-process; y el número de alertas es desconocido, no cero.
RISKS:
- No existe un paquete de evidencia post-merge completo ligado a 45d95188…; gran parte de la evidencia fuerte corresponde a 43677ed….
- El conteo exacto de tests y la cobertura post-#99 permanecen desconocidos.
- No hay verificación cosign conservada por digest OCI para una imagen concreta del merge #99.
- Los inventarios privados de Dependabot, CodeQL y secret scanning siguen sin auditarse por HTTP 403.
- El benchmark SSE sólo caracteriza transformación local in-process; extrapolarlo a red, WAL o producción sería engañoso.
- La evidencia QA del dashboard usa una instancia local con un registro; no constituye prueba de escala, seguridad de despliegue ni cumplimiento.
- Las afirmaciones comerciales, valoración económica, monopolio técnico, enterprise tier-1 y cobertura regulatoria del pasted content no se derivan de los artefactos técnicos auditados.
- unsafe_remediation.md mezcla código del proyecto con .venv/dependencias y puede producir falsos positivos si se usa como postura actual.
