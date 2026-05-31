# Política de seguridad

## Versiones soportadas

| Versión | Soportada |
| :--- | :--- |
| 2.x | Sí |
| 1.x | No |

## Reportar una vulnerabilidad

**No abras un issue público** para vulnerabilidades de seguridad.

Usa [GitHub Security Advisories](https://github.com/JuanLunaIA/aegis-latent-core/security/advisories/new) en el repositorio **JuanLunaIA/aegis-latent-core**, o contacta al mantenedor por los canales privados de GitHub.

Objetivo de respuesta:

- Acuse de recibo en **48 horas**
- Mitigación o plan en **14 días** (según gravedad)

Seguimos divulgación coordinada. Los reportes pueden acreditarse en el changelog salvo que pidan anonimato.

## Buenas prácticas al desplegar

- Define siempre `AEGIS_API_KEYS` en producción; no uses `AEGIS_AUTH_DISABLED`.
- No versiones `.env`, claves PEM ni el archivo `*.wal.jsonl` con datos reales.
- Restringe el acceso a `/v1/audit/*` con claves de solo lectura (`AEGIS_AUDIT_API_KEYS`).
