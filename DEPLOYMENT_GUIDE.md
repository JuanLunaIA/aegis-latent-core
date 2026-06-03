# Guía de Despliegue Profesional y CI/CD — Aegis Latent Core

Este documento detalla la infraestructura de entrega continua implementada para transformar este repositorio en un producto de grado industrial.

## 🚀 Automatización con GitHub Actions

He configurado dos flujos de trabajo principales en `.github/workflows/`:

1.  **CI (Integración Continua) — `ci.yml`**:
    *   **Linting:** Usa `Ruff` para asegurar que el código cumple con los estándares de estilo.
    *   **Type Checking:** Usa `Mypy` para validación estática de tipos (crítico para evitar bugs en producción).
    *   **Security Scan:** Usa `Bandit` y `pip-audit` para detectar vulnerabilidades en el código y dependencias.
    *   **Rust Extension:** Compila y testea automáticamente la extensión de alto rendimiento en Rust.
    *   **Docker:** Construye y firma (vía Cosign) la imagen oficial cada vez que hay un commit en `main` o un nuevo Release.

2.  **Release (Entrega Continua) — `release.yml`**:
    *   Se activa automáticamente al crear un tag (ej. `git tag v2.0.0 && git push --tags`).
    *   **Empaquetado:** Genera archivos `.whl` y `.tar.gz`.
    *   **Integridad Forense:** Genera hashes **SHA-256** para cada artefacto, permitiendo la verificación de integridad por parte de clientes finales.
    *   **Publicación:** Crea un Release en GitHub con los binarios y el registro de cambios.

## 🛡️ Seguridad de la Cadena de Suministro (Supply Chain)

Para cumplir con estándares gubernamentales y militares (como la Executive Order 14028 de EE.UU.):

*   **SBOM (Software Bill of Materials):** Se ha incluido el script `scripts/generate_sbom.sh` que genera un inventario completo de dependencias en formato JSON.
*   **Firma de Imágenes:** El pipeline de Docker usa `Cosign` para firmar criptográficamente las imágenes, asegurando que nadie pueda suplantar tu software en el registro.

## 📦 Distribución en Packages

Las imágenes de Docker ahora se publicarán automáticamente en **GitHub Container Registry (GHCR)**:
`ghcr.io/JuanLunaIA/aegis-latent-core:latest`

## 🛠️ Cómo activar los Releases

Para lanzar una nueva versión oficial:

1.  Actualiza la versión en `pyproject.toml`.
2.  Crea un tag de git:
    ```bash
    git tag -a v2.0.0 -m "Release v2.0.0: Resumen de mejoras"
    git push origin v2.0.0
    ```
3.  GitHub Actions se encargará del resto.

---
**Preparado por:** Manus AI
**Estado:** Enterprise-Ready
