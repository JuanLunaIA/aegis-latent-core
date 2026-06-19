---
description: "Análisis de costo cloud y recomendaciones de optimización. Ejemplo: /cost-analysis aws us-east-1"
---

Análisis de costos para: $ARGUMENTS

**Datos necesarios (pegar output de los siguientes comandos):**
```bash
# AWS — top services por costo último mes
aws ce get-cost-and-usage \
  --time-period Start=$(date -d '30 days ago' +%Y-%m-%d),End=$(date +%Y-%m-%d) \
  --granularity MONTHLY \
  --metrics BlendedCost \
  --group-by Type=DIMENSION,Key=SERVICE \
  --query 'ResultsByTime[0].Groups[*].[Keys[0],Metrics.BlendedCost.Amount]' \
  --output table

# EC2 utilization — instancias candidatas a rightsizing
aws cloudwatch get-metric-statistics \
  --namespace AWS/EC2 --metric-name CPUUtilization \
  --statistics Average --period 86400 \
  --start-time $(date -d '14 days ago' -u +%Y-%m-%dT%H:%M:%SZ) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%SZ)

# Unattached EBS volumes
aws ec2 describe-volumes \
  --filters Name=status,Values=available \
  --query 'Volumes[*].[VolumeId,Size,CreateTime]' \
  --output table
```

**Análisis output:**
1. **Top 3 cost drivers** — servicio, costo/mes, % del total, tendencia (↑↓)
2. **Rightsizing opportunities** — instancias < 20% CPU avg últimas 2 semanas
3. **Waste** — recursos sin uso: EBS sin adjuntar, Load Balancers sin targets, snapshots > 90d
4. **Savings estimate** — ahorro anualizado de cada recomendación
5. **Priority order** — por impacto (mayor ahorro × menor riesgo primero)

**Output format:**
```
PRIORIDAD | RECURSO | COSTO ACTUAL | AHORRO ESTIMADO/AÑO | ACCIÓN | RIESGO
HIGH      | EC2 i3.xlarge idle | $847/mo | $10,164/yr | Downsize a t3.medium | LOW
```
