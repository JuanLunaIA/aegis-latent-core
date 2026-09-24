<!--
Copyright (c) 2026 Juan Luna. All rights reserved.
Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
-->

# Aegis Latent Core
## AI Governance and Evidence Gateway

**Audiencia:** equipos de plataforma, AppSec, AI engineering, compliance, legal y procurement
**Estado:** prospecto de producto. No es certificación, dictamen legal, SLO ni oferta comercial vinculante.
**Last verified:** 2026-09-24 UTC
**Línea base de código:** `5.0.1` con catorce anclas sincronizadas — **publicada el 2026-09-24 en todas las superficies excepto PyPI `aegis-latent-core`**, verificada el mismo día (`docs/RELEASE_STATUS.md` §1.0a); la release anterior es `5.0.0` (2026-09-16, mismas superficies)
**Líneas base externas históricas:** tags anotado firmado `v4.0.2` (`a6eb58dcc03f8b638c8f3e35f0300f5443a926ca`) y ligero `v4.0.1` (`6469904380218584ae0b5221334bc9a46500f5ba`, workflows fallidos); las lecturas por superficie y las líneas base vigentes se declaran una sola vez en [`docs/RELEASE_STATUS.md`](RELEASE_STATUS.md) §1.0–§1.1

> **Paridad con la versión en inglés.** Este documento debe coincidir con [`docs/PROSPECTUS.md`](PROSPECTUS.md) en toda afirmación de hecho. Donde difiera, la versión en inglés gobierna y la discrepancia es un defecto a corregir, no una variante local.

## Baselines

La línea de código actual es **5.0.1** con catorce anclas sincronizadas y es la release publicada más reciente: **publicada el 2026-09-24 en todas las superficies excepto PyPI `aegis-latent-core`**; la release anterior es `5.0.0` (2026-09-16, mismas superficies). Incluye streaming SSE acotado con evidencia `pending-terminal`, Anthropic nativo `POST /v1/messages`, SDKs Python y TypeScript, proofs MMR portables, dashboard forense, export ZIP JCS/DAG-CBOR/CIDv1/PDF/`VERIFY.sh` y el segmento auxiliar `RustWal`.

**La publicación se afirma únicamente a partir de lectura posterior (readback), nunca a partir de metadatos de versión.** El 2026-09-16 se leyeron: el tag anotado firmado `v5.0.0`, el GitHub Release con 31 assets cargados, PyPI `aegis-latent-sdk` `5.0.0`, npm `aegis-latent-sdk` `5.0.0`, y ambas imágenes GHCR con objetos de firma cosign presentes. **No se ejecutaron `cosign verify` ni `gh attestation verify`**, y que un objeto de firma resuelva no es verificación: establece que se subió un objeto, no que valide ni quién lo firmó.

**Una brecha, declarada y no suavizada:** la distribución del gateway, PyPI `aegis-latent-core`, **no se publicó en `5.0.0`** y sigue resolviendo a `4.1.2`. Ningún workflow publica esa distribución, de modo que esperar no lo resuelve. Un `pip install aegis-latent-core` obtiene código `4.1.2`; para el gateway en `5.0.0` use los assets del GitHub Release o `ghcr.io/juanlunaia/aegis-latent-core:5.0.0`. Véase [`docs/RELEASE_STATUS.md`](RELEASE_STATUS.md) §1.0.

## Resumen ejecutivo

Aegis Latent Core es un gateway compatible con OpenAI para tráfico de IA gobernado; el código v4 integrado también expone Anthropic nativo `POST /v1/messages` conservando sus wire types. Autentica clientes, aplica política de solicitudes y egress, ejecuta controles WAF y de sesión, aplica rate limiting distribuido, reenvía al proveedor configurado y persiste evidencia firmada antes de devolver una respuesta gobernada no-streaming exitosa. En streaming, el header inicial es `pending-terminal`; el relay acotado persiste un resumen terminal firmado antes del marcador terminal de protocolo y el proof se recupera después de terminar. El registro enlaza hashes de solicitud y respuesta, cadena, metadata del signer, identificadores de request y estado de durabilidad dentro de los límites declarados.

El producto central es un **límite de evidencia**. No convierte automáticamente un sistema, modelo, organización o jurisdicción en compliant. Proporciona un punto de control y rutas reproducibles de evidencia para un programa de gobernanza más amplio.

## Capacidades y límites

| Capacidad | Resultado | Límite |
|---|---|---|
| Ingress de proveedores y SDKs | Superficie compatible con OpenAI y, en el código v4 integrado, Anthropic `POST /v1/messages`; Python es drop-in mediante subclases oficiales y TypeScript usa wrappers provider-native con SDKs oficiales como peer dependencies. | Parámetros, streaming y errores de cada proveedor requieren pruebas propias. |
| Evidencia durable firmada | Hash, firma, WAL, flush y `fsync` antes del camino de éxito gobernado. | Storage, backups, host e inmutabilidad externa dependen del despliegue. |
| Evidencia de errores | Registra errores upstream, circuit-open y fallos de red cuando el boundary sigue disponible. | Un fallo de storage después de admission es incidente fail-closed, no éxito. |
| WAF y policy | Normalización, patrones críticos, guardas estructurales y análisis local. | Es boundary de aplicación; HTTP/2 en ingress es separado. |
| Key rotation | Keyring HMAC versionado con overlap, expiry, reload atómico y `key_id`. | Tres réplicas y secret manager requieren evidencia real de despliegue. |
| Enrichment acotado | Análisis opcional después de la evidencia authoritative. | Puede retrasarse o rechazarse sin debilitar la evidencia. |
| Proof y export forense | El código v4 integrado ofrece proofs MMR portables, dashboard read-only y ZIP acotado con manifest JCS, ledger DAG-CBOR/CIDv1, proof JSON, PDF técnico y `VERIFY.sh`. | La raíz requiere un trust anchor independiente; no determina admisibilidad legal. |

## Evidencia de resiliencia y WAF

El código v4 integrado conserva además un benchmark SSE in-process acotado de 7 rondas × 1.000 eventos deterministas. Excluye red, proveedor y latencia de WAL durable; no demuestra capacidad ni SLO. El segmento nativo `RustWal` es auxiliar y el ledger JSONL conserva la autoridad de replay.

El harness local ofrece 10k RPS durante 0,25 s con 2 ms de `fsync` inyectado. La medición vigente (2026-09-16, tras el motor de commit agrupado) observó **2.500 requests ofrecidos → 2.500 commits durables**, cero fallos, cero IDs faltantes ni duplicados e integridad válida, con p50 33,545 ms, p99 51,875 ms y 200 llamadas a `fsync`. La corrida anterior del mismo harness, previa al commit agrupado, registró p99 836,35 ms y 2.501 llamadas a `fsync`.

**Dos advertencias que no deben omitirse.** Las dos corridas se ejecutaron en hosts distintos, de modo que la diferencia en milisegundos no es un aumento de velocidad controlado; lo que es independiente del host es el recuento de `fsync`. Y la latencia mide encolamiento bajo sobresuscripción deliberada, no sobrecarga por request: el costo real por commit medido con un `fsync` real por nodo es de 808,565 µs/op. Es fault injection acotado, no capacidad aceptada de producción ni un SLO (`UC-017`).

**Corrección registrada:** una versión anterior de este documento afirmaba «10.000 commits durables» y «p99 1.189,89 ms». Ambas cifras son falsas y están formalmente retractadas en `UC-018`; el artefacto retenido siempre contuvo 2.500 registros.

El corpus WAF local contiene 15 casos maliciosos y 8 benignos. El resultado observado fue cero bypasses y cero falsos positivos para ese corpus. El intervalo estadístico sigue siendo amplio porque la muestra es pequeña. HTTP/2 fragmentation y `nuclei-templates/waf-bypass` no están ejecutados en ese resultado.

## Assurance y compliance

El proyecto separa evidencia del repositorio, aceptación del despliegue y assurance independiente. No afirma SOC 2, HIPAA, FedRAMP, conformidad con EU AI Act, GDPR, validación FIPS 140, admisibilidad judicial ni SLO del cliente. El cliente debe validar ingress, storage, backup/restore, secret manager, key rotation, kernel, Redis, TLS, network policy, retention e incident response.

ML-DSA-65 es dependency-gated. Que el backend nativo esté disponible no prueba constant-time, certificación ni no-repudiación. La frase aceptable antes de una evaluación adecuada es: “no se ha detectado leakage estadísticamente significativo bajo el experimento nombrado”; nunca “constant-time” sin evidencia y revisión cualificada.

## Evaluación y adquisición

La secuencia recomendada es evaluación local, replay de evidencia, piloto controlado, security review, paquete de procurement y rollout de producción. El paquete debe contener tag inmutable, hashes, SBOM, provenance, release gate, claim matrix, threat model, deployment guide, runbooks, reportes WAF/backpressure, disclosure policy, retention statement, support matrix y rollback criteria.

El modelo comercial se organiza como Community/OSS, Team/Pilot, Production, Enterprise y un futuro Sovereign/OEM. Los rangos de pricing son hipótesis no vinculantes pendientes de entrevistas, cost-to-serve, quotes y pilotos pagados. Véanse [`COMMERCIAL.md`](../COMMERCIAL.md), [`PRODUCT_BRIEF_US.md`](PRODUCT_BRIEF_US.md), [`BUYER_GUIDE_US.md`](BUYER_GUIDE_US.md) y [`COMMERCIAL_STRATEGY_US.md`](COMMERCIAL_STRATEGY_US.md).

## No objetivos

Aegis no es un LLM, un WAF universal, un sistema universal de model safety, un firewall de red, un secret manager, un servicio de backup inmutable, una certificadora, un dictamen de admisibilidad ni un reemplazo de identity, privacy, retention, compliance o incident response. La topología actual tampoco afirma orden global cross-replica o HA multi-region. `zk_proof` y public anchoring siguen siendo superficies abiertas o dependientes de backend.

La fuente comercial y técnica canónica para nuevos lectores es el README US-English y [`docs/PROSPECTUS.md`](PROSPECTUS.md).

## Documentos relacionados

- [`README.md`](../README.md)
- [`docs/CLAIMS_MATRIX.md`](CLAIMS_MATRIX.md)
- [`docs/COMPLIANCE_MAPPING.md`](compliance/COMPLIANCE_MAPPING.md)
- [`docs/FAQ_PROCUREMENT.md`](FAQ_PROCUREMENT.md)
- [`docs/SECURITY_ASSURANCE_ROADMAP.md`](SECURITY_ASSURANCE_ROADMAP.md)
