<!--
Copyright (c) 2026 Juan Luna. All rights reserved.
Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
-->

# Aegis Latent Core 3.1.0 Candidate
## AI Governance and Evidence Gateway

**Audiencia:** equipos de plataforma, AppSec, AI engineering, compliance, legal y procurement
**Estado:** prospecto de producto y guía de evaluación; no es certificación, dictamen legal ni oferta comercial vinculante.

## Resumen ejecutivo

Aegis Latent Core es un gateway compatible con OpenAI para tráfico de IA gobernado. Autentica clientes, aplica política de solicitudes y egress, ejecuta controles WAF y de sesión, aplica rate limiting distribuido, reenvía al proveedor configurado y persiste evidencia firmada antes de devolver una respuesta gobernada exitosa. El registro enlaza hashes de solicitud y respuesta, cadena, metadata del signer, identificadores de request y estado de durabilidad dentro de los límites declarados.

El producto central es un **límite de evidencia**. No convierte automáticamente un sistema, modelo, organización o jurisdicción en compliant. Proporciona un punto de control y rutas reproducibles de evidencia para un programa de gobernanza más amplio.

## Capacidades y límites

| Capacidad | Resultado | Límite |
|---|---|---|
| Gateway compatible con OpenAI | Punto estable para integrar políticas y proveedores. | Parámetros, streaming y errores de cada proveedor requieren pruebas propias. |
| Evidencia durable firmada | Hash, firma, WAL, flush y `fsync` antes del camino de éxito gobernado. | Storage, backups, host e inmutabilidad externa dependen del despliegue. |
| Evidencia de errores | Registra errores upstream, circuit-open y fallos de red cuando el boundary sigue disponible. | Un fallo de storage después de admission es incidente fail-closed, no éxito. |
| WAF y policy | Normalización, patrones críticos, guardas estructurales y análisis local. | Es boundary de aplicación; HTTP/2 en ingress es separado. |
| Key rotation | Keyring HMAC versionado con overlap, expiry, reload atómico y `key_id`. | Tres réplicas y secret manager requieren evidencia real de despliegue. |
| Enrichment acotado | Análisis opcional después de la evidencia authoritative. | Puede retrasarse o rechazarse sin debilitar la evidencia. |

## Evidencia de resiliencia y WAF

El candidate v3.1.0 ejecutó un harness local con 10.000 requests ofrecidos a 10k RPS y 2 ms de `fsync` inyectado: observó 10.000 commits durables, cero fallos, cero IDs faltantes, cero duplicados e integridad válida; el p99 de commit fue 1.189,89 ms. Es un fault injection acotado, no capacidad aceptada de producción ni un SLO.

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
