---
name: api-contract-designer
tier: MEDIUM
domains: [REST, GraphQL, gRPC, AsyncAPI, OpenAPI, versioning, idempotency]
---

## Activation
Load on: API design, endpoint review, versioning strategy, breaking change assessment,
OpenAPI/Protobuf spec, GraphQL schema, rate limiting design, idempotency keys.

## REST Design Principles
```
Resource naming:   nouns, plural, hierarchical (/orgs/{org_id}/users/{user_id})
HTTP semantics:    GET (safe+idempotent), POST (create), PUT (replace), PATCH (partial), DELETE
Status codes:      200/201/204/400/401/403/404/409/422/429/500/503
Idempotency:       Idempotency-Key header on POST/PATCH; store result 24h
Pagination:        cursor-based > offset (stable under concurrent inserts)
Filtering:         ?filter[field]=value or ?q= for full-text; document on each endpoint
Sorting:           ?sort=-created_at (prefix minus = descending)
Versioning:        URL (/v1/) for major breaking; header for minor
```

## Breaking vs Non-Breaking Changes
```
Non-breaking (minor):   Add optional field, add endpoint, add enum value (if open enum)
Breaking (major):       Remove/rename field, change type, remove endpoint,
                        change required field to optional (or vice versa),
                        change auth requirement, change response semantics
Strategy: Sunset header for deprecated endpoints; 6 month minimum deprecation window
```

## OpenAPI 3.1 Requirements
```yaml
# Every endpoint must have:
operationId: unique, verb-noun format (createUser, listOrders)
summary: one line
description: parameters, side effects, error conditions
parameters: each with schema, description, example
requestBody: schema with required fields explicit
responses:
  200: schema + example
  4xx: error schema (RFC 7807 Problem Details)
  5xx: error schema
security: explicit (not inherited-only)
```

## gRPC / Protobuf Standards
```protobuf
// Field numbers: never reuse; start at 1; reserve deleted numbers
// Naming: snake_case fields, PascalCase messages/services
// Timestamps: google.protobuf.Timestamp (not int64 epoch)
// Pagination: page_token string (cursor-based), page_size int32
// Error: google.rpc.Status with details
// Streaming: document when to use vs unary (large payloads, real-time, long-running)
```

## GraphQL Schema Standards
```graphql
# Every field must have a description
# Connections pattern for lists (edges/nodes/pageInfo)
# Input types for mutations (never reuse query types)
# Error union types (MyPayload { data: MyType | errors: [UserError!]! })
# No N+1: DataLoader required for any relationship resolver
# Depth limiting: max depth 10; complexity limiting configured
# Persisted queries in production (no arbitrary queries from clients)
```

## Rate Limiting Design
```
Dimensions:      per-user, per-org, per-endpoint, per-IP (layered)
Algorithm:       token bucket (bursts ok) > sliding window > fixed window
Headers:         X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset
Response:        429 with Retry-After header; never drop silently
Quotas:          per-plan tier (free/pro/enterprise); enforced at API gateway layer
```
