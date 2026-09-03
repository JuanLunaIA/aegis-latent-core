<!--
Copyright (c) 2026 Juan Luna. All rights reserved.
Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
-->

# Aegis Latent Core
## AI Governance and Evidence Gateway

**Audiencia:** equipos de plataforma, AppSec, AI engineering, compliance, legal y procurement
**Estado:** candidato de código/release y prospecto de producto; no se afirma publicación externa y no es certificación, dictamen legal, SLO ni oferta comercial vinculante.
**Last verified:** 2026-08-27 UTC
**Candidato de código/release:** `4.1.2` con 14 anclas sincronizadas; no se afirma publicación externa de `v4.1.2` antes de una lectura posterior exitosa
**Línea base externa histórica:** tag ligero `v4.0.1` en `6469904380218584ae0b5221334bc9a46500f5ba` con workflows fallidos; PyPI/npm observados en `4.0.0` sin procedencia atribuida

## Baselines

El candidato actual de código/release es **4.1.2** y contiene 14 anclas sincronizadas. Streaming SSE acotado con evidencia `pending-terminal`, Anthropic nativo `POST /v1/messages`, SDKs Python y TypeScript, proofs MMR portables, dashboard forense, export ZIP JCS/DAG-CBOR/CIDv1/PDF/`VERIFY.sh` y el segmento auxiliar `RustWal` son capacidades del código candidato. No constituyen un tag o GitHub Release externo `v4.1.2`, publicación en PyPI/npm/OCI ni aceptación de release para producción; se requiere una lectura posterior exitosa.

## Resumen ejecutivo

Aegis Latent Core es un gateway compatible con OpenAI para tráfico de IA gobernado; el código v4 integrado también expone Anthropic nativo `POST /v1/messages` conservando sus wire types. Autentica clientes, aplica política de solicitudes y egress, ejecuta controles WAF y de sesión, aplica rate limiting distribuido, reenvía al proveedor configurado y persiste evidencia firmada antes de devolver una respuesta gobernada no-streaming exitosa. En streaming, el header inicial es `pending-terminal`; el relay acotado persiste un resumen terminal firmado antes del marcador terminal de protocolo y el proof se recupera después de terminar. El registro enlaza hashes de solicitud y respuesta, cadena, metadata del signer, identificadores de request y estado de durabilidad dentro de los límites declarados.

El producto central es un **límite de evidencia**. No convierte automáticamente un sistema, modelo, organización o jurisdicción en compliant. Proporciona un punto de control y rutas reproducibles de evidencia para un programa de gobernanza más amplio.

## Capacidades y límites

| Capacidad | Resultado | Límite |
|---|---|---|
| Ingress de proveedores y SDKs | Superficie compatible con OpenAI y, en el código v4 integrado, Anthropic `POST /v1/messages`; Python es drop-in mediante subclases oficiales y TypeScript usa wrappers provider-native con SDKs oficiales como peer dependencies. | Parámetros, streaming y errores de cada proveedor requieren pruebas propias; estas adiciones no se atribuyen a v3.1.0. |
| Evidencia durable firmada | Hash, firma, WAL, flush y `fsync` antes del camino de éxito gobernado. | Storage, backups, host e inmutabilidad externa dependen del despliegue. |
| Evidencia de errores | Registra errores upstream, circuit-open y fallos de red cuando el boundary sigue disponible. | Un fallo de storage después de admission es incidente fail-closed, no éxito. |
| WAF y policy | Normalización, patrones críticos, guardas estructurales y análisis local. | Es boundary de aplicación; HTTP/2 en ingress es separado. |
| Key rotation | Keyring HMAC versionado con overlap, expiry, reload atómico y `key_id`. | Tres réplicas y secret manager requieren evidencia real de despliegue. |
| Enrichment acotado | Análisis opcional después de la evidencia authoritative. | Puede retrasarse o rechazarse sin debilitar la evidencia. |
| Proof y export forense | El código v4 integrado ofrece proofs MMR portables, dashboard read-only y ZIP acotado con manifest JCS, ledger DAG-CBOR/CIDv1, proof JSON, PDF técnico y `VERIFY.sh`. | La raíz requiere un trust anchor independiente; no determina admisibilidad legal. |

## Evidencia de resiliencia y WAF

El código v4 integrado conserva además un benchmark SSE in-process acotado de 7 rondas × 1.000 eventos deterministas. Excluye red, proveedor y latencia de WAL durable; no demuestra capacidad ni SLO. El segmento nativo `RustWal` es auxiliar y el ledger JSONL conserva la autoridad de replay.

El release v3.1.0 conserva un harness local con 10.000 requests ofrecidos a 10k RPS y 2 ms de `fsync` inyectado: observó 10.000 commits durables, cero fallos, cero IDs faltantes, cero duplicados e integridad válida; el p99 de commit fue 1.189,89 ms. Es un fault injection acotado, no capacidad aceptada de producción ni un SLO.

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
