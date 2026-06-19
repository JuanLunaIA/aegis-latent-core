---
description: Generar documentación técnica. Ejemplo: /document src/services/auth.py README
---

Generá documentación técnica para: $ARGUMENTS

**Tipos de docs y formato según target:**

**README.md** (para módulos/proyectos):
```markdown
# [Nombre]
> Una línea: qué hace y para quién.

## Prerequisites
[Dependencias con versiones mínimas]

## Installation
[Comandos exactos, copiables sin modificación]

## Configuration
[Variables de entorno con descripción, tipo, default, required/optional]

## Usage
[Ejemplos concretos — el caso más común primero]

## Architecture
[Diagrama de componentes si hay múltiples módulos]

## API Reference
[Endpoints/funciones públicas con params, return types, exceptions]

## Development
[Setup de dev, cómo correr tests, cómo contribuir]
```

**Runbook** (para operaciones):
```markdown
# Runbook: [Operación]
Last updated: [ISO 8601]

## Trigger
[Cuándo ejecutar este runbook]

## Steps
1. [Comando exacto con expected output]
2. [Verificación de éxito]
3. [Rollback si falla: comando exacto]

## Escalation
[Cuándo y a quién escalar]
```

**ADR** (Architectural Decision Record):
Ver formato en /architect command.

**API Reference** (para módulos Python):
- Generar docstrings estilo Google para cada función pública
- Incluir: Args, Returns, Raises, Example
- Nunca inventar comportamiento — solo documentar lo que el código hace

**Reglas:**
- No prose filler: "This module provides..." → no
- Comandos copiables: probados antes de incluirlos
- Versiones exactas, no rangos vagos
- Links a código fuente donde aplique
