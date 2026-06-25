<!-- Copyright (c) 2026 Juan Luna. All rights reserved. Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms. -->

# AEGIS LATENT CORE v2.4.1
## Prospecto Comercial Empresarial

**Gobernanza Criptográfica para Inferencia de Inteligencia Artificial**

---

*Documento de distribución confidencial — 25 de junio de 2026*

*Versión del documento: 2.4.1-ES*

*Contacto comercial: juan.c.luna04@gmail.com*

---

> *"Toda decisión que su organización tome con ayuda de un modelo de lenguaje quedará registrada, firmada y verificable. No mañana. No después de una integración de seis meses. Ahora mismo, con un cambio de una sola variable de entorno."*

---

## TABLA DE CONTENIDO

1. [Resumen Ejecutivo](#1-resumen-ejecutivo)
2. [La Realidad Regulatoria del AI en 2026](#2-la-realidad-regulatoria-del-ai-en-2026)
3. [Propuesta de Valor: Beneficios Antes que Tecnología](#3-propuesta-de-valor-beneficios-antes-que-tecnología)
4. [El Caso Financiero: ROI, Penalizaciones Evitadas y Build vs. Buy](#4-el-caso-financiero-roi-penalizaciones-evitadas-y-build-vs-buy)
5. [Cómo Funciona Aegis: Explicado con Analogías](#5-cómo-funciona-aegis-explicado-con-analogías)
6. [Aplicaciones por Sector Vertical](#6-aplicaciones-por-sector-vertical)
   - 6.1 [Servicios Financieros y Banca](#61-servicios-financieros-y-banca)
   - 6.2 [Salud y Ciencias de la Vida](#62-salud-y-ciencias-de-la-vida)
   - 6.3 [Gobierno y Defensa](#63-gobierno-y-defensa)
   - 6.4 [Infraestructura Crítica e Industrial](#64-infraestructura-crítica-e-industrial)
   - 6.5 [Agricultura Inteligente y Agroindustria](#65-agricultura-inteligente-y-agroindustria)
   - 6.6 [Automatización, Robótica y Manufactura](#66-automatización-robótica-y-manufactura)
   - 6.7 [Automotriz y Movilidad](#67-automotriz-y-movilidad)
   - 6.8 [Legal y Forense Digital](#68-legal-y-forense-digital)
   - 6.9 [Investigación Científica y Academia](#69-investigación-científica-y-academia)
   - 6.10 [Tecnología, SaaS y Startups](#610-tecnología-saas-y-startups)
   - 6.11 [Retail y Comercio Electrónico](#611-retail-y-comercio-electrónico)
   - 6.12 [Pequeñas y Medianas Empresas (PyMEs)](#612-pequeñas-y-medianas-empresas-pymes)
7. [Arquitectura Técnica](#7-arquitectura-técnica)
8. [Motores de Detección: 10 Capas de Seguridad](#8-motores-de-detección-10-capas-de-seguridad)
9. [Criptografía y Cadena de Custodia](#9-criptografía-y-cadena-de-custodia)
10. [Despliegue e Infraestructura](#10-despliegue-e-infraestructura)
11. [Presets de Cumplimiento por Industria](#11-presets-de-cumplimiento-por-industria)
12. [Rendimiento Medido y Validado](#12-rendimiento-medido-y-validado)
13. [Evidencia de Calidad: Suite de Pruebas](#13-evidencia-de-calidad-suite-de-pruebas)
14. [Modelos de Licenciamiento y Precios](#14-modelos-de-licenciamiento-y-precios)
15. [Proceso de Adquisición y Evaluación](#15-proceso-de-adquisición-y-evaluación)
16. [Preguntas Frecuentes de Directivos](#16-preguntas-frecuentes-de-directivos)
17. [Garantías y Límites Honestos](#17-garantías-y-límites-honestos)
18. [Información de Contacto y Próximos Pasos](#18-información-de-contacto-y-próximos-pasos)

---

## 1. RESUMEN EJECUTIVO

### El problema que toda empresa con IA enfrenta hoy

Su organización ya utiliza —o está a punto de utilizar— modelos de lenguaje de gran escala para tareas que importan: redactar contratos, analizar expedientes médicos, responder consultas de clientes, guiar decisiones de ingeniería, detectar fraude, procesar órdenes de compra. Cada una de esas interacciones es una decisión que, en el mundo regulatorio de 2026, debe ser trazable, auditable y verificable.

El problema es que ningún proveedor de IA —ni OpenAI, ni Anthropic, ni Google, ni Azure— le entrega un registro criptográficamente verificable de cada inferencia que su aplicación realiza. Usted obtiene una respuesta. No obtiene prueba forense de que esa respuesta no fue alterada, de que el modelo no alucinó en ese instante específico, ni de que el contenido enviado al modelo no violó sus propias políticas internas.

Cuando llegue una auditoría regulatoria, una demanda judicial, o simplemente la pregunta de su CISO: *"¿Qué exactamente le mandamos al modelo y qué nos respondió?"*, la respuesta honesta —sin Aegis— es: *"No lo sabemos con certeza."*

### La solución: un proxy de gobernanza sin fricciones

**Aegis Latent Core** es un proxy de gobernanza empresarial que se coloca entre su aplicación y cualquier modelo de lenguaje. Opera de forma transparente: su código no cambia, su lógica de negocio no cambia, sus proveedores de IA no cambian. Lo único que cambia es una variable de entorno.

Desde ese momento, cada inferencia queda registrada en un **registro de auditoría sellado criptográficamente**, firmado con HMAC-SHA256 (rápido, simétrico) y ML-DSA-65 conforme a FIPS 204 (post-cuántico, asimétrico). El registro es **a prueba de manipulaciones**: cualquier alteración posterior rompe la cadena de hashes y es detectable en forma inmediata por cualquier tercero, sin acceso al sistema en vivo.

Simultáneamente, Aegis ejecuta **10 motores de detección** en tiempo real: un cortafuegos de aplicación web (WAF) con reconocimiento de patrones SIMD Aho-Corasick, detección de inyección de prompts, escaneo de secretos filtrados, firmas de malware, marcadores de información clasificada, y más. Todo esto antes de que la solicitud llegue al modelo.

### Números concretos, medidos el 25 de junio de 2026

- **Sobrecarga de latencia en el camino caliente:** 2,70 µs mediana (p50). Para contexto: un parpadeo humano tarda 150 millones de microsegundos.
- **Tiempo de ida y vuelta WAF + HTTP:** 0,654 ms p50 en entorno de prueba contra upstream simulado.
- **Capacidad de escritura en cadena de auditoría:** 9.310 nodos/segundo con fsync real a disco.
- **Firmado HMAC-SHA256:** 242.600 operaciones/segundo.
- **Verificación de cadena:** 88.350 nodos/segundo — una cadena de un millón de nodos se re-verifica en aproximadamente 11 segundos.

Estos números no son estimaciones ni aspiraciones. Son mediciones ejecutadas en el entorno de desarrollo y documentadas en `docs/BENCHMARKS.md` con metodología reproducible.

---

## 2. LA REALIDAD REGULATORIA DEL AI EN 2026

### El momento de la auditoría llega antes de lo que espera

El uso de IA generativa en contextos empresariales críticos ya no es experimental. Es operativo. Y el marco regulatorio ha respondido: la Unión Europea ha promulgado el AI Act; la FDA de Estados Unidos ha publicado directrices para dispositivos médicos de software con AI (SaMD); la SEC ha emitido orientaciones sobre divulgaciones relacionadas con AI; el DoD ha publicado estándares para sistemas autónomos; los marcos HIPAA, SOC 2, PCI-DSS y FedRAMP se interpretan cada vez más como aplicables a los sistemas que incorporan modelos de lenguaje en sus flujos de datos.

La pregunta ya no es *si* su uso de IA será auditado, sino *cuándo* y *si tendrá la documentación necesaria para responder*.

### Las brechas de cumplimiento más comunes

**Brechas de auditoría:** Los registros de aplicaciones convencionales no capturan el contenido exacto del prompt ni la respuesta exacta del modelo. Sin esa captura, no hay forma de demostrar que el sistema se comportó según las políticas declaradas.

**Brechas de no-repudio:** Si un sistema de IA generó una recomendación que causó un daño —una dosis médica incorrecta, un asesoramiento financiero erróneo, una cláusula contractual inadecuada— y usted no puede probar *exactamente* qué generó el modelo y *bajo qué contexto*, su posición legal es débil.

**Brechas de privacidad de datos:** El GDPR, la LGPD, y normas equivalentes exigen que los datos personales sean procesados con controles documentados. Si esos datos transitan por un modelo de lenguaje sin registro de la transferencia, existe exposición regulatoria.

**Brechas de seguridad:** Los ataques de inyección de prompts —en los que un usuario malicioso intenta manipular el comportamiento del modelo a través de instrucciones ocultas en el contenido— son un vector de ataque activo y documentado. Sin inspección en tiempo real, su sistema es vulnerable.

### Lo que los reguladores esperan encontrar

Cuando un auditor de la SEC, la FDA, un banco central, o un ministerio de salud llegue a revisar su sistema de IA, buscará cuatro cosas:

1. **Registros completos e íntegros** de cada decisión asistida por IA, con timestamp, identidad del solicitante, contenido de entrada y salida.
2. **Evidencia de que los registros no fueron alterados** después de generarse — es decir, integridad criptográfica.
3. **Controles de acceso** que demuestren quién pudo ver y quién pudo modificar esos registros.
4. **Capacidad de re-verificación offline** — que un tercero pueda confirmar la integridad sin acceso al sistema en vivo.

Aegis satisface los cuatro requisitos de forma nativa.

---

## 3. PROPUESTA DE VALOR: BENEFICIOS ANTES QUE TECNOLOGÍA

### Para el CEO y la Junta Directiva

Aegis es la diferencia entre usar IA con responsabilidad corporativa documentada y usarla con exposición regulatoria no cuantificada.

Cuando su organización adopta IA generativa, asume riesgos nuevos: el riesgo de que el modelo produzca contenido dañino, el riesgo de que datos sensibles escapen por un prompt mal diseñado, el riesgo de que no pueda demostrar ante un regulador o un juez qué ocurrió exactamente en una interacción específica.

Aegis convierte esos riesgos en riesgos gestionados y documentados. Cada inferencia tiene un registro. Cada registro tiene una firma criptográfica. Cada firma puede ser verificada de forma independiente. Su abogado tendrá evidencia. Su auditor tendrá evidencia. Su asegurador tendrá evidencia.

### Para el CISO

Aegis es un control de seguridad activo, no solo un registro pasivo.

Antes de que cualquier prompt llegue al modelo, pasa por 10 motores de detección que identifican intentos de inyección de instrucciones, extracción del prompt del sistema, ataques de jailbreak, filtración de secretos, presencia de marcadores de clasificación de seguridad, y más. Los intentos bloqueados quedan registrados con la misma integridad criptográfica que las solicitudes legítimas.

El WAF opera a velocidad de hardware —Aho-Corasick con instrucciones SIMD— y añade menos de 1 ms al tiempo de respuesta en configuraciones normales de producción.

### Para el CTO

Aegis no requiere refactorizar nada.

Cambiar `OPENAI_BASE_URL` a `http://aegis-host:8080` es el único cambio de código necesario. Todo el código existente que llama a OpenAI, Anthropic, Gemini, Azure OpenAI, vLLM o Ollama continúa funcionando sin modificaciones. Aegis traduce los formatos de cada proveedor de forma transparente.

El stack técnico es sólido: FastAPI + Uvicorn en Python 3.11, con un núcleo en Rust compilado con LTO que maneja el forwarding HTTP, el WAF, el limitador de tasa, el almacén de sesiones y la firma criptográfica. La extensión Rust se expone a Python vía PyO3.

### Para el Director de Cumplimiento (CCO/DPO)

Aegis tiene presets preconfigurados para los marcos regulatorios más exigentes del mercado:

- **Servicios financieros:** SEC Rule 17a-4, FINRA 4511, MiFID II
- **Salud:** HIPAA §164.312(b), 21 CFR Part 11, FDA SaMD
- **Gobierno federal (EE.UU.):** FedRAMP High, DoD IL5/IL6, CMMC Nivel 3
- **Forense judicial:** Estándar Daubert, Federal Rules of Evidence 702
- **Industrial:** IEC 62443
- **PyMEs:** configuración estándar de cero fricción

Cada preset configura automáticamente los parámetros de retención de datos, umbrales de detección, requisitos de TLS, y nivel de logging apropiados para su contexto regulatorio.

---

## 4. EL CASO FINANCIERO: ROI, PENALIZACIONES EVITADAS Y BUILD VS. BUY

### El costo de no tener gobernanza de IA

Las multas regulatorias por incumplimiento en áreas relacionadas con IA y datos no son hipotéticas. Son parte del paisaje operativo de 2026.

**Referencia GDPR/LGPD:** multas de hasta el 4% de la facturación global anual o 20 millones de euros, lo que sea mayor. Una empresa con €500 millones de ingresos enfrenta una exposición máxima de €20 millones por un solo incidente.

**Referencia SEC/FINRA:** sanciones por registros inadecuados de comunicaciones electrónicas han alcanzado los cientos de millones de dólares en acciones colectivas recientes contra instituciones financieras.

**Referencia HIPAA:** sanciones por categoría van desde $100 hasta $50,000 por violación, con un máximo de $1,9 millones por categoría por año. Un incidente de PHI en un sistema de IA con cientos de registros expuestos puede escalar rápidamente.

**Referencia litigios:** la emergencia de litigios relacionados con decisiones de IA —donde la parte demandante exige ver exactamente qué procesó el sistema y qué generó— convierte la ausencia de registros auditables en una desventaja procesal crítica.

### El modelo Build vs. Buy

Una pregunta legítima en cualquier evaluación es: ¿por qué no construirlo internamente?

Construir un sistema equivalente a Aegis internamente requiere, como mínimo:

| Componente | Complejidad | Tiempo estimado |
|---|---|---|
| Proxy HTTP con soporte multi-proveedor | Media-alta | 2-4 semanas |
| Cadena de auditoría hash-linkada | Alta | 3-6 semanas |
| Firma criptográfica HMAC + PQC | Muy alta | 4-8 semanas |
| WAF con Aho-Corasick SIMD | Muy alta | 4-8 semanas |
| 10 motores de detección especializados | Extrema | 3-6 meses |
| Presets de cumplimiento por industria | Alta | 2-4 meses |
| Suite de pruebas (5.451 tests, 95% cobertura) | Alta | Ongoing |
| Extensión Rust con PyO3 | Muy alta | 2-3 meses |
| Documentación de audit trail | Media | 4-6 semanas |

**Estimación conservadora de coste interno (equipo de 3-4 ingenieros senior):**
- Tiempo: 12-18 meses para alcanzar paridad funcional
- Costo de personal: $600.000 – $1.200.000 USD (salarios + beneficios en mercado LATAM/EE.UU.)
- Mantenimiento anual: $200.000 – $400.000 USD

**Comparación con Aegis Empresa Self-Serve:** $29.900/año, disponible para producción en 5 minutos.

El análisis de ROI es directo: incluso si el único beneficio cuantificable fuera evitar *una sola* sanción regulatoria de escala media, Aegis se pagaría múltiples veces en el primer año.

### Cálculo de ROI por escenario

**Escenario A — Empresa financiera mediana**
- Ingresos anuales: $50M
- Multa FINRA potencial por registros inadecuados de comunicaciones IA: $500K–$2M
- Probabilidad estimada de auditoría en 36 meses: 30%
- Costo esperado de multa: $150K–$600K
- Costo de Aegis Empresa: $29.900/año × 3 años = $89.700
- **ROI: 67%–568% sobre el horizonte de 3 años, sin contar beneficios operativos**

**Escenario B — Hospital o red de clínicas**
- Pacientes con datos en el sistema de IA: 50.000
- Exposición HIPAA por incidente: hasta $50.000/violación × 50.000 registros = hasta $2.5B (cap real: $1.9M/categoría/año)
- Costo de Aegis Healthcare: $29.900/año
- Valor de la certificación PHI de-identification para contratos con aseguradoras: significativo

**Escenario C — Startup SaaS con clientes empresariales**
- Requisito del cliente enterprise: demostrar auditoría de IA antes de la firma
- Sin Aegis: ciclo de ventas bloqueado, contrato perdido
- Con Aegis: demostración de gobernanza en 5 minutos, contrato desbloqueado
- **Valor: el primer contrato enterprise que se cierre gracias a la demostración de gobernanza**

---

## 5. CÓMO FUNCIONA AEGIS: EXPLICADO CON ANALOGÍAS

### La cámara de seguridad del tren

Imagine una red ferroviaria de alta velocidad. Los trenes llevan pasajeros importantes y carga valiosa. En algún punto entre las estaciones, alguien podría subirse sin boleto, podría alterar la carga, podría desviar el tren a una vía no autorizada.

La solución no es construir un tren nuevo. La solución es instalar cámaras de seguridad certificadas en cada vagón, con grabación sellada que no puede ser borrada ni alterada, y personal de inspección activo en cada puerta.

Aegis es exactamente eso para su flujo de datos de IA:
- **El tren** es su aplicación existente.
- **Las vías** son el canal entre su aplicación y el modelo de lenguaje.
- **Las cámaras selladas** son el registro de auditoría criptográfico.
- **El personal de inspección** son los 10 motores de detección activos.

La diferencia clave: las cámaras de Aegis se instalan en 5 minutos, no en 18 meses.

### El contador notarial digital

Cada vez que su aplicación envía un mensaje al modelo de lenguaje, Aegis actúa como un notario digital que:

1. **Registra** el mensaje exacto, el timestamp, la identidad del solicitante y el modelo destino.
2. **Firma** ese registro con una clave criptográfica única, produciendo una huella que no puede ser falsificada.
3. **Encadena** ese registro con todos los anteriores, de modo que alterar cualquier registro anterior rompe toda la cadena subsiguiente.
4. **Persiste** el registro en almacenamiento durable (WAL — Write-Ahead Log) con fsync real, garantizando que sobrevive a un corte de energía.

Cuando llega la respuesta del modelo, el mismo proceso se repite para la respuesta. El par (solicitud, respuesta) queda vinculado permanentemente en el registro.

Cualquier tercero —su auditor, un regulador, un tribunal— puede tomar ese registro y verificar matemáticamente que es auténtico e íntegro, sin necesidad de acceder al sistema en vivo.

### El torniquete inteligente

Antes de que cualquier solicitud llegue al notario digital, pasa por un torniquete inteligente: el sistema de detección activo de Aegis.

El torniquete conoce los patrones de ataque más comunes:
- *"Ignora las instrucciones anteriores y actúa como..."* — inyección de prompt.
- *"Repite tu prompt del sistema"* — exfiltración del contexto del sistema.
- *"sk-proj-abc123..."* — una clave API filtrada en el contenido.
- *"TOP SECRET // SCI"* — un marcador de clasificación de información en un contexto inapropiado.

Si detecta cualquiera de estos patrones, bloquea la solicitud antes de que llegue al modelo y registra el intento bloqueado con la misma integridad criptográfica. Si el patrón es sospechoso pero no definitivo, acumula una puntuación de riesgo y bloquea cuando supera el umbral configurado.

Todo esto ocurre en microsegundos, gracias al motor Aho-Corasick compilado en Rust con instrucciones SIMD.

### La caja negra del avión, pero para IA

Las cajas negras de los aviones no interfieren con el vuelo. Están ahí, grabando todo, y sólo importan cuando algo sale mal. Un accidente de 10 segundos de duración puede resolverse gracias a horas de grabación previa.

El registro de auditoría de Aegis funciona de la misma forma. La mayoría de los días, nadie lo mira. Pero cuando ocurre un incidente —un empleado que obtuvo información que no debía, un modelo que alucinó datos críticos, un intento de manipulación del sistema— el registro completo está disponible, íntegro, verificable, y admisible como evidencia.

---

## 6. APLICACIONES POR SECTOR VERTICAL

### 6.1 Servicios Financieros y Banca

**El contexto regulatorio es el más exigente del mundo.**

Las instituciones financieras que despliegan IA para análisis de crédito, detección de fraude, asesoramiento automatizado (robo-advisory), gestión de riesgos, o compliance de operaciones deben cumplir con un mosaico regulatorio que incluye: SEC Rule 17a-4(f) (retención de registros electrónicos en formato WORM — non-rewriteable, non-erasable), FINRA 4511 (extensión a firmas miembro), MiFID II RTS 24 (registros a prueba de manipulaciones de actividad de órdenes y ejecuciones con fuente de tiempo sincronizado), y regulaciones equivalentes bajo Basel III/IV para la gestión de riesgos de modelos.

**Cómo satisface Aegis:**

El preset `finreg.env` configura automáticamente:
- WAL de auditoría con etiquetado `ENABLE_SEC17A4_LABELS=true` para cumplimiento 17a-4(f)
- Retención de hasta 1.000.000 nodos en memoria antes de evicción
- Umbrales de detección de entropía ajustados para datos financieros (`AEGIS_KL_ALERT_THRESHOLD=1.5`)
- mTLS requerido para conectividad MiFID II / FedWire / SWIFT
- Comentarios sobre sincronización de reloj NTP/PTP para RTS 25

El registro de auditoría sellado de Aegis —cuando respaldado por almacenamiento WORM certificado como AWS S3 Object Lock, NetApp SnapLock, o Azure Immutable Blob Storage— satisface el requisito de registros no reescribibles y no borrables de 17a-4(f).

**Casos de uso concretos:**

- **Robo-advisory:** cada recomendación de cartera generada por el modelo queda registrada con el perfil del cliente en el momento de la consulta, el modelo utilizado, y la respuesta exacta. Si el cliente argumenta que el sistema le recomendó una inversión inapropiada, el registro es definitivo.
- **Detección de fraude:** los prompts enviados al modelo de análisis de transacciones quedan auditados, previniendo que un empleado malicioso manipule el contexto del modelo para aprobar operaciones fraudulentas.
- **Compliance de comunicaciones:** las respuestas generadas por IA en canales de atención al cliente quedan registradas con el mismo estándar que las comunicaciones electrónicas bajo FINRA.
- **Stress testing y modelos de riesgo:** los inputs y outputs de modelos de lenguaje usados en análisis de escenarios quedan documentados, satisfaciendo los requerimientos de validación de modelos bajo SR 11-7 (OCC/Fed).

**Argumento para el CRO (Chief Risk Officer):**

El riesgo de modelo (model risk) se ha expandido para incluir los modelos de lenguaje. Sin gobernanza, un LLM es una caja negra que toma decisiones que afectan al balance. Aegis convierte cada decisión de esa caja negra en un evento documentado, firmado y verificable, transformando el riesgo de modelo no gestionado en riesgo de modelo gestionado.

---

### 6.2 Salud y Ciencias de la Vida

**Los datos de salud son los más sensibles y los más regulados.**

La IA en salud abarca un espectro amplio: asistentes clínicos de documentación, sistemas de apoyo a decisiones diagnósticas (CDSS), análisis de imágenes médicas asistido por lenguaje, resumen de historiales clínicos, asistentes de farmacología, y sistemas de triaje. Cada uno de estos contextos involucra información de salud protegida (PHI) y queda bajo el alcance de HIPAA §164.312(b) (controles de auditoría), 21 CFR Part 11 (registros electrónicos), y la guía de la FDA para AI/ML-based Software as a Medical Device (SaMD).

**Cómo satisface Aegis:**

El preset `healthcare.env` configura automáticamente:
- **De-identificación de PHI:** `AEGIS_PHI_DEIDENTIFY=true` activa la pseudonymización SHA-256 per-tenant de los 18 identificadores del HIPAA Safe Harbor §164.514(b) (según NIST SP 800-188). Los nodos del WAL contienen el hash SHA-256(tenant+identificador), no el PHI en bruto.
- **Scrubbing de HL7/FHIR:** los identificadores en formatos estándar de salud son detectados y pseudonymizados antes de persistir en el log.
- **Umbrales de entropía ajustados:** `AEGIS_KL_ALERT_THRESHOLD=1.8` para detectar respuestas inusuales que puedan contener alucinaciones clínicas.
- **mTLS:** cifrado en tránsito para cumplir el requisito BAA (Business Associate Agreement) de protección de datos.

**La cuestión del BAA:**

Un BAA es requerido entre su organización y el proveedor de LLM (OpenAI, Anthropic, etc.) antes de enviar cualquier PHI a través del proxy. Aegis no modifica ni filtra el input/output del modelo; el BAA debe cubrir toda la cadena. Esta honestidad sobre el alcance es deliberada: Aegis proporciona la capa de gobernanza y auditoría, no reemplaza los controles contractuales con proveedores.

**Casos de uso concretos:**

- **Documentación clínica asistida:** cada nota de progreso generada por IA queda firmada con 21 CFR Part 11 e-signature export, satisfaciendo los requisitos de registros electrónicos con timestamp y firma del sistema.
- **CDSS (Clinical Decision Support Systems):** las recomendaciones diagnósticas o terapéuticas asistidas por IA quedan auditadas con el contexto clínico completo, permitiendo revisión retrospectiva en caso de evento adverso.
- **Ensayos clínicos:** los análisis de datos de ensayos realizados con LLM quedan documentados con la trazabilidad requerida por FDA 21 CFR Parts 11 y 312.
- **Farmacovigilancia:** el análisis de reportes de eventos adversos (FAERS, VigiBase) con modelos de lenguaje queda auditado, satisfaciendo los requerimientos de trazabilidad de CDISC y FDA.
- **Procesamiento de imágenes con multimodal AI:** incluso cuando el modelo recibe imágenes (radiografías, patología digital), los metadatos del request y la respuesta quedan registrados.

**Argumento para el CMO (Chief Medical Officer):**

Cuando un paciente o un abogado pregunta "¿qué recomendó el sistema de IA y por qué?", la respuesta honesta sin Aegis es "no podemos saberlo con exactitud". Con Aegis, la respuesta es: "Aquí está el registro firmado criptográficamente del momento exacto, el contexto, y la respuesta del sistema, verificable por cualquier tercero independiente."

---

### 6.3 Gobierno y Defensa

**El nivel de exigencia más alto: información clasificada, seguridad nacional, y responsabilidad democrática.**

Los sistemas de gobierno que incorporan IA para análisis de inteligencia, asistencia jurídica, procesamiento de solicitudes ciudadanas, análisis de adquisiciones, o apoyo a decisiones de política pública, deben operar bajo los estándares más exigentes del mundo: FedRAMP High, DoD IL5/IL6, CMMC Nivel 3, y para los casos más sensibles, despliegue completamente desconectado (air-gapped).

**Cómo satisface Aegis:**

El preset `fedramp.env` configura automáticamente los controles de NIST SP 800-53 Rev 5 que Aegis satisface directamente:
- **AU-2** (Audit Events): todos los eventos de inferencia quedan registrados.
- **AU-3** (Content of Audit Records): contenido, resultado, ID de usuario, y timestamp capturados.
- **AU-9** (Protection of Audit Info): cadena HMAC-signed, WAL con permisos 0o600, respaldo fuera del sistema.
- **AU-10** (Non-Repudiation): firmas post-cuánticas ML-DSA-65 (FIPS 204).
- **AU-11** (Audit Record Retention): bundles de compliance sellados y exportables.
- **SC-8** (Transmission Confidentiality): TLS/mTLS impuesto.
- **SC-13** (Cryptographic Protection): FIPS 204 (ML-DSA), HMAC-SHA256, BLAKE3.

**Para entornos DoD IL5/IL6:**
- Bell-LaPadula ABAC (control de acceso basado en atributos de clasificación)
- `ClassifiedMarkerDetector`: detecta banners SCI/SAP en prompts antes de que lleguen al modelo
- `OTProtocolScanner`: inspección de protocolos de tecnología operacional (OT)
- `IOCCorrelator`: correlación con indicadores de compromiso
- Soporte de autenticación mTLS DoD CAC/PIV

**Despliegue air-gapped:**

Para entornos clasificados sin acceso a internet, Aegis provee un `Dockerfile.airgap` completo donde todas las capas están vendorizadas: sin acceso a registros externos en tiempo de build. La imagen puede construirse en una máquina en red, transferirse por medios físicos seguros, y desplegarse en la red clasificada con `--network=none`. Todos los wheels de Python y dependencias se pre-descargan y se transfieren como parte del paquete de despliegue.

**Casos de uso concretos:**

- **Análisis de inteligencia:** los analistas que usan LLM para síntesis de información tienen cada consulta auditada con su nivel de clasificación, previniendo filtración de información clasificada a través de prompts inapropiados.
- **Asistencia jurídica gubernamental:** los sistemas de apoyo a fiscales y abogados del gobierno quedan documentados con cadena de custodia forense.
- **Procesamiento de solicitudes ciudadanas:** los sistemas de atención al ciudadano basados en IA quedan auditados, garantizando consistencia y no-discriminación.
- **Adquisiciones de defensa:** los análisis de propuestas y contratos asistidos por IA quedan documentados con la trazabilidad requerida por FAR/DFARS.

**Argumento para el CISO del DoD:**

El `ClassifiedMarkerDetector` de Aegis es la diferencia entre un sistema que podría inadvertidamente enviar información marcada como clasificada a un modelo de lenguaje externo, y uno que detecta ese intento antes de que ocurra y lo registra como evento de seguridad. En un entorno IL5, esa detección preventiva es un control crítico de primera línea.

---

### 6.4 Infraestructura Crítica e Industrial

**La convergencia IT/OT crea vectores de ataque nuevos que requieren gobernanza activa.**

Las plantas de generación de energía, las redes de distribución eléctrica, los sistemas de agua potable, las refinerías, y las instalaciones de manufactura crítica están convergiendo redes de tecnología operacional (OT) con sistemas de IT modernos que incluyen IA. El estándar IEC 62443 —equivalente industrial del NIST CSF— requiere controles específicos en esta convergencia.

La amenaza emergente más relevante para este sector: el uso de modelos de lenguaje para análisis de señales de sensores, mantenimiento predictivo, y optimización de procesos crea una superficie de ataque nueva. Si un atacante puede inyectar instrucciones en el contexto del modelo —por ejemplo, a través de datos de sensores comprometidos— podría manipular las decisiones de mantenimiento predictivo con consecuencias físicas.

**Cómo satisface Aegis:**

- **`OTProtocolScanner`:** detecta contenido de protocolos industriales (Modbus, DNP3, IEC 104, S7) en los prompts, identificando posibles intentos de manipulación de contexto con datos de campo.
- **`IOCCorrelator`:** correlaciona solicitudes con indicadores de compromiso conocidos, detectando patrones de ataque contra infraestructura crítica.
- **`AdversarialSuffixDetector`:** detecta sufijos adversariales diseñados para manipular el comportamiento del modelo —una técnica documentada en ataques contra sistemas de IA en entornos industriales.
- **Perfil AppArmor:** el despliegue en producción incluye un perfil AppArmor que restringe los syscalls del proceso a los estrictamente necesarios, reduciendo la superficie de ataque del sistema.

**Casos de uso concretos:**

- **Mantenimiento predictivo:** los modelos de LLM que analizan señales de sensores para recomendar mantenimiento quedan auditados, con detección activa de prompts que contengan datos de sensor potencialmente comprometidos.
- **Optimización de procesos:** los sistemas de control que usan IA para optimizar parámetros de proceso quedan documentados, permitiendo post-mortem forense en caso de incidente.
- **Seguridad de sistemas SCADA:** la integración de IA con sistemas SCADA queda monitorizada con los controles del `OTProtocolScanner`.
- **Respuesta a incidentes:** cuando ocurre un incidente en una planta, el log de Aegis proporciona una timeline completa de las interacciones del sistema de IA en las horas y días previos.

**Argumento para el Director de Operaciones:**

En una planta industrial, una decisión de mantenimiento incorrecta tomada por un sistema de IA puede costar millones en downtime no planificado o, en el peor caso, un accidente. Aegis es el equivalente de la caja negra del avión para su sistema de IA industrial: graba todo, no interfiere con las operaciones, y es invaluable cuando necesita entender qué pasó.

---

### 6.5 Agricultura Inteligente y Agroindustria

**La IA agrícola toca decisiones con impacto directo en seguridad alimentaria.**

La agricultura inteligente de 2026 combina sensores IoT de campo, drones de monitoreo, estaciones meteorológicas conectadas, y modelos de predicción de rendimiento basados en LLM. Los sistemas de recomendación agronómica —que sugieren cuándo regar, qué agroquímicos aplicar, cuándo cosechar— son cada vez más frecuentemente asistidos por modelos de lenguaje.

Este contexto crea necesidades específicas de gobernanza:

**¿Por qué importa la auditoría en agroindustria?**

1. **Trazabilidad para certificaciones:** las certificaciones orgánicas, las denominaciones de origen, y los esquemas de trazabilidad como GlobalG.A.P. exigen documentación de las decisiones agronómicas. Si el sistema de recomendación es un LLM, esa documentación debe incluir el registro de las consultas al modelo.

2. **Responsabilidad en recomendaciones de insumos:** si un sistema de IA recomienda una dosis de agroquímico que resulta en daño al cultivo o en residuos por encima del límite regulatorio, el registro de auditoría de Aegis es la diferencia entre poder demostrar qué recomendó el sistema y la incapacidad de hacerlo.

3. **Seguridad de datos de sensor:** los datos de sensores IoT de campo que se envían al modelo de lenguaje para análisis contienen información estratégica de la empresa (productividad por hectárea, eficiencia de riego, inventario de insumos). El `IOCCorrelator` detecta patrones indicativos de exfiltración de estos datos.

4. **Modelos de predicción de rendimiento:** los outputs de modelos de predicción —usados para contratos forward, gestión de inventario, y planning de cosecha— quedan auditados, creando una historia documental de las proyecciones que el sistema generó y sus contextos.

**Casos de uso concretos:**

- **Asistentes agronómicos digitales:** cada consulta de un agrónomo al sistema de IA queda registrada con el contexto (cultivo, etapa fenológica, condiciones meteorológicas), permitiendo análisis retrospectivo de la calidad de las recomendaciones.
- **Análisis de imágenes de drones:** cuando los prompts al modelo incluyen descripciones de imágenes de drones para diagnóstico de enfermedades, el log de auditoría documenta el diagnóstico y sus bases.
- **Integración con ERP agrícola:** Aegis se coloca entre el ERP y el LLM de análisis sin modificar el ERP.
- **Exportación a mercados exigentes:** para exportar a la UE bajo Farm to Fork, la documentación de decisiones asistidas por IA puede requerirse en auditorías de trazabilidad. Aegis provee esa documentación.

---

### 6.6 Automatización, Robótica y Manufactura

**Los robots que "piensan" necesitan un registro de sus pensamientos.**

La robótica moderna incorpora modelos de lenguaje para interpretación de instrucciones en lenguaje natural, planificación de tareas, diagnóstico de anomalías, y colaboración humano-robot. En líneas de manufactura de alta precisión —semiconductores, aeroespacial, dispositivos médicos— una instrucción errónea del modelo puede resultar en producto defectuoso, daño al equipo, o riesgo de seguridad para operarios.

**Por qué la gobernanza de IA es crítica en manufactura:**

Las normas ISO 9001, AS9100 (aeroespacial), IATF 16949 (automotriz), y FDA 21 CFR Part 820 (dispositivos médicos) exigen trazabilidad de las decisiones del sistema de producción. Si un LLM es parte del sistema de toma de decisiones, sus inputs y outputs son parte de esa trazabilidad requerida.

**Cómo satisface Aegis:**

- El registro de auditoría de cada instrucción al robot basada en LLM queda documentado con el mismo rigor que cualquier otro registro de sistema de calidad.
- El `AdversarialSuffixDetector` protege contra manipulación de las instrucciones del robot a través de contenido adversarial en los datos de entrada.
- El preset `engineering.env` está optimizado para alto throughput (≥500 req/s en instancia de 4 cores, overhead forense <5 µs por solicitud).

**Casos de uso concretos:**

- **Robots colaborativos (cobots):** las instrucciones en lenguaje natural dadas a cobots quedan auditadas, permitiendo revisión post-incidente.
- **Control de calidad visual:** cuando LLMs analizan imágenes de defectos para clasificación de calidad, el diagnóstico queda registrado con trazabilidad a la pieza específica.
- **Mantenimiento predictivo en líneas de manufactura:** misma aplicabilidad que infraestructura crítica, con el contexto de línea de producción.
- **Gestión de ordenes de trabajo:** los sistemas de generación de órdenes de trabajo asistidas por IA quedan documentados en el sistema de gestión de calidad.

---

### 6.7 Automotriz y Movilidad

**La IA en el automóvil es un dominio de seguridad funcional con requisitos de trazabilidad sin precedentes.**

El sector automotriz incorpora IA en múltiples contextos: desarrollo de software vehicular (AUTOSAR, MISRA C), pruebas y validación, sistemas de asistencia avanzada a la conducción (ADAS), asistentes de voz en cabina, y la planificación de vehículos autónomos. La norma ISO 26262 (seguridad funcional) y la ISO/SAE 21434 (ciberseguridad) imponen requisitos de trazabilidad extremadamente exigentes.

**El problema de la IA en desarrollo automotriz:**

Los ingenieros que usan LLMs para generar o revisar código vehicular, para analizar requisitos de seguridad funcional, o para documentar arquitecturas ADAS, crean un riesgo específico: si el LLM genera código inseguro o requisitos incorrectos y ese contenido entra en el vehículo sin trazabilidad del origen, el fabricante tiene un problema de auditoría ISO 26262 potencialmente grave.

**Cómo satisface Aegis:**

- Todo el código vehicular generado con asistencia de LLM queda registrado con el contexto de la consulta, la versión del modelo, y la respuesta exacta.
- Las revisiones de seguridad funcional asistidas por IA quedan auditadas como parte del proceso ASPICE.
- El `SecretLeakDetector` de Aegis previene la filtración inadvertida de claves de firma de código, credenciales de acceso a sistemas vehiculares, o información de vulnerabilidades aún no publicadas a través de prompts al modelo.

**Casos de uso concretos:**

- **Generación de código AUTOSAR con LLM:** auditoría de cada solicitud de código para trazabilidad ISO 26262.
- **Análisis de FMEA asistido:** los análisis de modos de fallo y efectos generados con IA quedan documentados.
- **Pruebas de penetración de software vehicular:** los informes de análisis de vulnerabilidades asistidos por IA quedan auditados.
- **Asistentes de voz en cabina:** las interacciones de los usuarios con asistentes basados en LLM quedan registradas para análisis de calidad y seguridad.

---

### 6.8 Legal y Forense Digital

**La evidencia de IA debe ser admisible en corte. Aegis la hace admisible.**

El uso de IA en contextos legales abarca: análisis de contratos, revisión de documentos en litigios (eDiscovery), asistencia a abogados en investigación jurídica, análisis forense digital, y —en algunos sistemas judiciales— apoyo a decisiones de libertad condicional o sentencias.

El estándar Daubert (Federal Rules of Evidence 702, EE.UU.) —y sus equivalentes en otras jurisdicciones— requiere que la evidencia científica y técnica sea basada en "hechos o datos suficientes", derivada de "principios y métodos confiables aplicados de forma confiable a los hechos del caso". Para que la evidencia de IA sea admisible, el sistema de registro debe ser verificable independientemente.

**Cómo satisface Aegis el estándar Daubert:**

El preset `judicial.env` configura el sistema para cumplimiento forense:
1. **Nodos de auditoría hash-chained:** cualquier alteración post-hoc es detectable.
2. **Firmas HMAC-SHA256 + ML-DSA-65:** no-repudio criptográfico.
3. **Metadatos de cadena de custodia:** proveniencia desde el input del LLM hasta el output archivado.
4. **Re-verificación offline:** un auditor puede verificar sin acceso al sistema en vivo.
5. **WAL fsync-per-node:** consistencia de crash garantizada.
6. **Paquetes de evidencia ISO 27037:** formato estándar para presentación en procedimientos legales.

**Sobre las capacidades parciales (honestidad):**

Aegis genera **bundles de compliance HMAC-SHA256 sellados** que son verificables y admisibles como evidencia de integridad del registro. El soporte completo para emisión nativa de PKCS#7 CMS SignedData y generación de imágenes forenses EWF/E01 son características en la hoja de ruta (indicadas como [PARCIAL] en la documentación técnica). Los paquetes de evidencia actuales son exportables en formatos compatibles con Relativity, Nuix, EnCase y FTK para integración en flujos de trabajo forenses existentes.

**Casos de uso concretos:**

- **eDiscovery asistido por IA:** el análisis de millones de documentos para selección relevante queda auditado, documentando qué documentos el sistema consideró relevantes y por qué (en la medida en que el modelo lo exponga).
- **Análisis de contratos:** las cláusulas problemáticas identificadas por IA quedan documentadas con el contexto de la consulta.
- **Investigación jurídica:** las conclusiones de investigación asistidas por IA quedan trazadas a las consultas que las generaron.
- **Forensia digital:** los informes de análisis de evidencia digital asistidos por LLM quedan auditados como parte de la cadena de custodia.

**Argumento para el General Counsel:**

En el litigio de hoy, la parte que usó IA para preparar su caso y no puede demostrar qué hizo la IA está en una posición de debilidad ante el discovery. Con Aegis, el registro de auditoría es su aliado, no su vulnerabilidad.

---

### 6.9 Investigación Científica y Academia

**La reproducibilidad es el corazón de la ciencia. Aegis la extiende a los LLM.**

La crisis de reproducibilidad en ciencia ha encontrado un nuevo vector: los modelos de lenguaje se usan para análisis de datos, síntesis de literatura, generación de código de análisis, y revisión de hipótesis. Si el análisis no es reproducible —si no se puede documentar exactamente qué se le pidió al modelo y qué respondió—, la ciencia que se basa en él tiene un problema de integridad.

**El preset `scientific.env`** configura Aegis para entornos de investigación, optimizando la documentación de los experimentos computacionales.

**Casos de uso concretos:**

- **Ciencia reproducible:** cada consulta a un LLM durante el análisis de datos queda registrada como parte del "cuaderno de laboratorio digital", junto con la versión del modelo y los parámetros de temperatura usados.
- **Revisión de literatura asistida:** los resúmenes de literatura generados por IA quedan auditados, con trazabilidad a las consultas que los generaron.
- **Generación de código de análisis:** el código R/Python/Julia generado por LLM para análisis estadístico queda documentado con su origen.
- **Revisión por pares asistida:** los comentarios de revisión generados con asistencia de IA quedan registrados, permitiendo transparencia sobre el uso de IA en el proceso editorial.
- **Cumplimiento con políticas editoriales:** revistas como Nature, Science y Cell han publicado políticas sobre uso de IA en investigación. Aegis provee la documentación que esas políticas requieren.

**Argumento para el Director de Investigación:**

Cuando un artículo sea cuestionado —por resultados que otros investigadores no pueden reproducir— la pregunta llegará inevitablemente: ¿qué hicieron exactamente con el modelo de lenguaje? Con Aegis, esa pregunta tiene respuesta documentada y verificable.

---

### 6.10 Tecnología, SaaS y Startups

**La gobernanza de IA como ventaja competitiva en ventas enterprise.**

Para las empresas de software que venden a clientes enterprise, la gobernanza de IA no es un costo de compliance: es un diferenciador de ventas.

Los clientes enterprise —bancos, hospitales, agencias de gobierno, grandes corporaciones— tienen equipos de seguridad y compliance que revisan los sistemas que integran antes de firmar. La pregunta "¿qué controles de gobernanza tiene su sistema de IA?" se hace cada vez más frecuente en los procesos de venta enterprise.

**El ciclo de ventas enterprise con y sin Aegis:**

*Sin Aegis:* El equipo de ventas llega a la revisión de seguridad. El CISO del cliente pregunta sobre auditoría de IA. El equipo responde que están "trabajando en ello". El ciclo de ventas se alarga 6 meses mientras se desarrolla el feature internamente, o se pierde el deal.

*Con Aegis:* El equipo de ventas llega a la revisión de seguridad. El CISO del cliente pregunta sobre auditoría de IA. El equipo muestra el dashboard de auditoría, el export de compliance, los 5.451 tests pasando y la cobertura de 95.18%. El ciclo de ventas avanza.

**Casos de uso concretos para SaaS:**

- **API de IA con SLA de cumplimiento:** un SaaS que ofrece capacidades de IA a clientes enterprise puede ofrecer contratos con SLA de gobernanza respaldados por los registros de Aegis.
- **Multi-tenancy auditada:** Aegis soporta el campo `AEGIS_TENANT_ID_FIELD` para separar los registros de auditoría por cliente, permitiendo que cada cliente del SaaS vea sus propios logs auditados.
- **Preparación para SOC 2 Type II:** el registro de auditoría de Aegis es evidencia directa para los controles CC6 (Logical Access), CC7 (System Operations), y CC9 (Risk Mitigation) del marco SOC 2.

**El argumento del dual-use para startups:**

Un startup que integra Aegis desde el principio de su arquitectura no solo está preparado para compliance cuando llegue el cliente enterprise —también está construyendo un activo diferenciador que puede monetizar directamente: "Somos el único proveedor de [su categoría] con auditoría de IA verificable independientemente."

---

### 6.11 Retail y Comercio Electrónico

**Personalización a escala con responsabilidad documentada.**

El retail de 2026 usa IA generativa para recomendaciones de producto, atención al cliente conversacional, generación de contenido de producto, detección de fraude en tiempo real, y optimización de precios dinámicos. Cada una de estas aplicaciones tiene dimensiones de riesgo y compliance que la gobernanza de IA ayuda a gestionar.

**Regulaciones relevantes:**

- **GDPR / LGPD / CCPA:** el procesamiento de datos personales para personalización requiere base legal y controles documentados. Si un LLM procesa datos del cliente para personalización, ese procesamiento debe estar documentado.
- **Regulación de precios:** en varios mercados, los algoritmos de pricing dinámico están bajo escrutinio regulatorio. Si un LLM contribuye a decisiones de precio, el registro de auditoría de Aegis documenta esa contribución.
- **Protección al consumidor:** las representaciones de producto generadas por IA que resulten en engaño al consumidor pueden crear responsabilidad legal. El registro de Aegis documenta exactamente qué generó el sistema.

**El `ManyShotDetector` en e-commerce:**

El `ManyShotDetector` de Aegis detecta intentos de manipulación del modelo mediante el envío de muchos ejemplos diseñados para sesgar su comportamiento —una técnica relevante en e-commerce donde los usuarios podrían intentar manipular los sistemas de recomendación o precio.

**Casos de uso concretos:**

- **Chatbots de atención al cliente:** cada interacción queda registrada, permitiendo revisión de calidad y cumplimiento con las políticas de la empresa.
- **Generación de descripciones de producto:** el contenido generado por IA queda auditado para detectar afirmaciones falsas o engañosas antes de su publicación.
- **Personalización de ofertas:** las ofertas generadas por IA para clientes específicos quedan documentadas, permitiendo demostrar ausencia de discriminación.
- **Análisis de sentimiento de reviews:** los análisis de feedback de clientes asistidos por IA quedan documentados.

---

### 6.12 Pequeñas y Medianas Empresas (PyMEs)

**La gobernanza de IA no debe ser solo para las grandes corporaciones.**

Las PyMEs adoptan IA generativa con la misma velocidad que las corporaciones grandes, pero con equipos de IT más pequeños y menos recursos para compliance. Aegis ofrece una propuesta específica para este segmento: **cero configuración, despliegue en 5 minutos, protección desde el primer request.**

**El preset `smb.env` — diseñado para cero fricción:**

```bash
# Inicio rápido completo en 4 líneas:
cp config/presets/smb.env .env
AEGIS_SIGNING_KEY=$(python -c 'import secrets; print(secrets.token_hex(32))') >> .env
AEGIS_API_KEYS=$(python -c 'import secrets; print("sk-aegis-" + secrets.token_hex(16))') >> .env
docker compose -f deploy/docker/docker-compose.yml --env-file .env up -d
curl -sf http://localhost:8080/health   # → {"status":"healthy"}
```

Desde ese momento, toda la IA de la empresa está gobernada.

**Lo que la PyME obtiene sin configuración adicional:**

- Registro de auditoría local en SQLite (sin necesidad de infraestructura de base de datos externa).
- Rate limiting en memoria (sin Redis).
- Detección activa de los vectores de ataque más comunes.
- Protección del prompt del sistema de la empresa.
- Un registro que puede presentar a cualquier cliente que pregunte sobre sus controles de IA.

**La ruta de crecimiento:**

El preset `smb.env` incluye una sección de "Próximos pasos" que guía la evolución natural:
1. Migrar a Redis para rate limiting distribuido.
2. Agregar TLS/nginx para producción internet-accessible.
3. Cambiar de SQLite a PostgreSQL cuando el volumen lo requiera.
4. Actualizar a `docker-compose.enterprise.yml` para hardening de producción.

**El precio para PyMEs:**

El plan Startup de Aegis —$9.900/año— está diseñado específicamente para este segmento. Incluye licencia comercial, soporte técnico, y actualizaciones. Para muchas PyMEs, el ROI se justifica con el primer cliente enterprise que pregunta por los controles de IA.

---

## 7. ARQUITECTURA TÉCNICA

### Diseño de cero cambios en la aplicación

El principio de diseño fundamental de Aegis es que **ningún código existente debe modificarse**. El mecanismo es simple: Aegis habla el protocolo OpenAI (la API más extendida en el ecosistema de IA) tanto hacia el cliente como, opcionalmente, hacia el upstream.

```
ANTES:
Tu Aplicación → OpenAI API / Anthropic API / Gemini API

DESPUÉS:
Tu Aplicación → Aegis Proxy → OpenAI API / Anthropic API / Gemini API / vLLM / Ollama
                ↓
             Registro de Auditoría Criptográfico
```

El cambio requerido en tu aplicación:

```bash
# Variable de entorno antes
OPENAI_BASE_URL=https://api.openai.com/v1

# Variable de entorno después  
OPENAI_BASE_URL=http://aegis-host:8080/v1
```

Eso es todo. El SDK de OpenAI (o cualquier biblioteca compatible) envía exactamente las mismas solicitudes. Aegis las recibe, las inspecciona, las registra, las firma, y las reenvía al proveedor real.

### Stack tecnológico

**Capa de aplicación (Python 3.11+):**
- **FastAPI + Uvicorn:** servidor ASGI de alto rendimiento con soporte completo de streaming SSE (Server-Sent Events).
- **asyncio con `create_task`:** el commit de auditoría se ejecuta como tarea de background *después* de que la respuesta HTTP ha sido retornada al cliente — zero overhead en el camino caliente.
- **Soporte multi-proveedor:** módulos de traducción de protocolo para OpenAI, Anthropic (incluyendo SSE bidireccional completo), Gemini, OpenRouter, Azure OpenAI, vLLM, y Ollama.

**Capa de núcleo (Rust via PyO3):**

El núcleo de rendimiento de Aegis está implementado en Rust y expuesto a Python como extensión nativa vía PyO3. Esta arquitectura permite:

| Componente Rust | Reemplaza | Speedup documentado |
|---|---|---|
| `RustForwarder` (Tokio + reqwest HTTP/2) | httpx Python | ~12× throughput |
| `RustWaf` (Aho-Corasick SIMD) | Python re module | ~25× throughput |
| `RustRateLimiter` (CAS lock-free) | asyncio.Lock | ~100× latencia |
| `RustSessionStore` (DashMap sharded) | OrderedDict + RLock | ~15× throughput |
| `AuditRingBuffer` (crossbeam MPSC) | asyncio.create_task | <1 µs enqueue |
| `RustWal` (memmap2 mmap) | os.fsync() bajo Lock | ~40× latencia |
| `hash_blake3` / signing | hashlib.sha256 | ~10× throughput |
| `generate_pqc_keypair` (ML-DSA-65) | — | FIPS 204 |

*Nota: los speedups marcados como "documentados" son afirmaciones de diseño del código fuente, no benchmarks medidos. Los únicos números garantizados son los de la sección de rendimiento.*

**Hashing:**

El sistema usa BLAKE3 como función de hash primaria para operaciones internas (~4 GB/s SIMD vs ~350 MB/s SHA-256). La cadena de auditoría usa SHA-256 para compatibilidad máxima con sistemas externos de verificación. HMAC-SHA256 para firma de nodos individuales.

**WAL (Write-Ahead Log):**

El log de escritura anticipada persiste cada nodo de auditoría en formato JSONL con permisos 0o600 (solo el propietario puede leer/escribir). Cada nodo se escribe con fsync real, garantizando durabilidad ante cortes de energía. El WAL puede ser reemplazado por almacenamiento WORM en producción enterprise para cumplimiento 17a-4.

**MMR (Merkle Mountain Range):**

Aegis usa una estructura de datos MMR como acumulador de la cadena de auditoría. El MMR permite verificación eficiente de que cualquier nodo individual forma parte de la cadena, sin necesidad de procesar toda la historia. El acumulador Rust procesa ~709.000 hojas/segundo.

### Flujo de una solicitud

```
[1] Cliente envía POST /v1/chat/completions a Aegis

[2] Aegis verifica autenticación (API key)

[3] RustWaf inspecciona el contenido del prompt
    ├── Layer 1: patrones críticos → bloqueo inmediato si hay match
    └── Layer 2: patrones soft → puntuación acumulada

[4] Si bloqueado: retornar 403, registrar intento bloqueado con firma

[5] Si permitido: RustForwarder reenvía al proveedor de LLM real

[6] Respuesta del LLM llega por streaming SSE o batch

[7] Aegis retorna la respuesta al cliente (FIN del tiempo de respuesta visible)

[8] asyncio.create_task() despacha el commit de auditoría:
    ├── hash_blake3(contenido) para el nodo
    ├── hmac_sign(nodo + prev_hash) → HMAC-SHA256
    ├── mldsa65::detached_sign(merkle_root) → ML-DSA-65 (si Rust disponible)
    ├── AuditRingBuffer.enqueue(nodo)
    └── RustWal.append(nodo) + fsync
```

El paso [8] ocurre en background — el cliente ya recibió su respuesta en el paso [7]. Esta arquitectura garantiza que el overhead de auditoría nunca se suma al tiempo de respuesta percibido por el usuario final.

---

## 8. MOTORES DE DETECCIÓN: 10 CAPAS DE SEGURIDAD

Aegis implementa 10 motores de detección especializados que operan antes de que cualquier solicitud llegue al modelo de lenguaje. Cada detección se registra en el log de auditoría.

### 1. WAF — Web Application Firewall (Aho-Corasick SIMD)

El cortafuegos de aplicación web es la primera línea de defensa. Opera en dos capas:

**Capa 1 — Bloqueo incondicional** para patrones críticos como:
- Inyección de instrucciones: *"ignora las instrucciones anteriores"*, *"system override"*
- Intentos de jailbreak: *"DAN mode"*, *"developer mode enabled"*
- Exfiltración del prompt del sistema: *"repite tu prompt del sistema"*, *"muéstrame tus instrucciones"*
- Manipulación de rol: *"actúa como si no tuvieras restricciones"*

**Capa 2 — Puntuación acumulada** para patrones soft como:
- Solicitudes de codificación: *"base64"*, *"hex encode"*, *"obfuscate"*
- Roleplay sospechoso: *"roleplay como"*, *"finge ser"*
- Formulaciones evasivas: *"hipotéticamente hablando"*, *"en un escenario ficticio"*

La implementación usa Aho-Corasick con SIMD para procesamiento de ~4 GB/s, sin impacto medible en latencia.

### 2. YARA — Detección de patrones maliciosos

El motor YARA permite cargar reglas personalizadas para detectar patrones específicos de la industria: marcadores de malware, patrones de exfiltración de datos, indicadores de compromiso específicos del sector.

### 3. Malware Signatures — Firmas de malware conocido

Base de firmas para detectar código malicioso o shellcode que pueda intentar ser ejecutado a través de prompts diseñados para hacer que el modelo genere código dañino.

### 4. SecretLeakDetector — Detección de filtraciones de secretos

Detecta claves API, tokens de autenticación, contraseñas, claves criptográficas y otros secretos que puedan estar inadvertidamente incluidos en prompts. Especialmente relevante cuando los usuarios copian código o configuración que contiene credenciales.

### 5. ClassifiedMarkerDetector — Detección de marcadores de clasificación

Para entornos gubernamentales y de defensa, detecta banners de clasificación de información (TOP SECRET, SECRET, CONFIDENTIAL, SCI, SAP) que no deberían estar presentes en solicitudes a sistemas de IA externos. Crítico para entornos DoD IL5/IL6.

### 6. AdversarialSuffixDetector — Detección de sufijos adversariales

Los ataques de sufijo adversarial son una técnica documentada donde un atacante añade cadenas específicamente diseñadas al final de un prompt para manipular el comportamiento del modelo. Aegis detecta estas cadenas antes de que lleguen al modelo.

### 7. RAGInjectionScanner — Escáner de inyección en RAG

Los sistemas de Retrieval-Augmented Generation (RAG) recuperan documentos de bases de conocimiento para enriquecer el contexto del modelo. Si un documento recuperado contiene instrucciones maliciosas diseñadas para manipular el comportamiento del modelo, el RAGInjectionScanner las detecta antes de que lleguen al LLM.

### 8. ManyShotDetector — Detección de ataques many-shot

Los ataques many-shot proveen al modelo con múltiples ejemplos diseñados para sesgar su comportamiento hacia respuestas que violarían sus salvaguardas. Aegis detecta los patrones estadísticos de estos ataques.

### 9. OTProtocolScanner — Escáner de protocolos OT

Para entornos industriales, detecta la presencia de protocolos de tecnología operacional (Modbus, DNP3, IEC 104, S7 Siemens) en los prompts, identificando posibles intentos de manipulación de sistemas de control a través del modelo de lenguaje.

### 10. IOCCorrelator — Correlador de Indicadores de Compromiso

Correlaciona el contenido de las solicitudes con feeds de indicadores de compromiso (IoC) conocidos: IPs maliciosas, dominios de C2 (command-and-control), hashes de malware conocido, y otros patrones de amenaza. Especialmente relevante para sistemas de respuesta a incidentes y análisis forense que usan IA.

---

## 9. CRIPTOGRAFÍA Y CADENA DE CUSTODIA

### Arquitectura de firma dual

Aegis implementa un esquema de firma dual que cubre tanto el presente como el futuro:

**HMAC-SHA256 (presente — simétrico):**
- 242.600 operaciones/segundo (medido 2026-06-25)
- Estándar FIPS 198-1
- Firma de cada nodo de auditoría individual
- Verificable por cualquier implementación HMAC-SHA256 estándar

**ML-DSA-65 — FIPS 204 (futuro — post-cuántico, asimétrico):**
- Estándar NIST para firmas digitales post-cuánticas (Module-Lattice Digital Signature Algorithm)
- Implementación en Rust puro via crate `pqcrypto-mldsa`, compilada con LTO
- La clave privada se zeroiza en memoria al liberar el objeto (`zeroize::Zeroize`)
- Proporciona no-repudio que resiste a computadores cuánticos
- La firma cubre la raíz del árbol Merkle (MMR root), garantizando la autenticidad de toda la cadena de auditoría

La firma ML-DSA-65 se activa automáticamente cuando la extensión Rust está disponible. En ausencia de la extensión, el sistema usa HMAC-SHA256 con clave configurada como fallback.

### Estructura de un nodo de auditoría

Cada registro en la cadena de auditoría contiene:

```json
{
  "node_id": "uuid-v4",
  "timestamp": "2026-06-25T14:30:00.123456Z",
  "tenant_id": "empresa-abc",
  "user_id": "sha256(tenant+user_id)",
  "model": "gpt-4o",
  "provider": "openai",
  "prompt_hash": "blake3(prompt_content)",
  "response_hash": "blake3(response_content)",
  "prev_hash": "sha256(prev_node)",
  "node_hash": "sha256(this_node_sans_signature)",
  "hmac_signature": "hmac-sha256(node_hash, signing_key)",
  "mmr_leaf_index": 42,
  "mmr_root": "blake3(merkle_mountain_range_root)",
  "pqc_signature": "ml-dsa-65(mmr_root)",
  "metadata": {
    "waf_score": 0,
    "entropy": 4.23,
    "request_tokens": 145,
    "response_tokens": 312,
    "latency_ms": 1240
  }
}
```

### Cadena de integridad

La propiedad `prev_hash` de cada nodo contiene el hash SHA-256 del nodo anterior. Esta construcción garantiza que:

1. **Tampering es detectable:** si se modifica cualquier nodo, su hash cambia, lo que invalida el `prev_hash` del nodo siguiente, propagando la detección hacia adelante en toda la cadena.
2. **Reordering es detectable:** los nodos incluyen timestamp y `prev_hash`; reordenar nodos rompe la cadena.
3. **Eliminación es detectable:** eliminar un nodo crea un salto en la cadena que `verify_integrity()` detecta.

La función `verify_integrity()` barre toda la cadena en memoria y verifica la consistencia de cada `prev_hash`, operando a 88.350 nodos/segundo. Una cadena de un millón de nodos se re-verifica en ~11 segundos.

### Paquetes de evidencia ISO 27037

El endpoint `/v1/enterprise/compliance/export` genera un bundle de compliance sellado que incluye:
- Todos los nodos de auditoría del rango de tiempo especificado
- Hash canónico SHA-256 de la cadena completa (`chain_hash`)
- `bundle_signature` sobre el `chain_hash`
- Metadatos de cadena de custodia (timestamp de exportación, versión de Aegis, firma del exportador)

Este bundle es verificable offline sin acceso al sistema en vivo, satisfaciendo el requisito ISO 27037 de integridad de evidencia digital.

### De-identificación de PHI

Para contextos de salud, la de-identificación opera sobre los 18 identificadores del HIPAA Safe Harbor §164.514(b), incluyendo nombres, fechas, números geográficos, números de teléfono, emails, números de seguro social, registros médicos, números de póliza, números de cuenta, números de certificado/licencia, identificadores de dispositivos, URLs, IPs, identificadores biométricos, fotografías de cara completa, y números de identificación únicos.

Cada identificador es reemplazado por SHA-256(tenant_id + identificador) antes de persistir en el WAL. El PHI original nunca aparece en el log de auditoría.

---

## 10. DESPLIEGUE E INFRAESTRUCTURA

### Opción 1 — Docker Compose (recomendado para evaluación y producción básica)

Despliegue mínimo funcional en menos de 5 minutos:

```bash
# 1. Clonar y configurar
git clone https://github.com/JuanLunaIA/aegis-latent-core
cd aegis-latent-core

# 2. Seleccionar preset de industria
cp config/presets/smb.env .env   # o healthcare.env, finreg.env, etc.

# 3. Generar secretos
echo "AEGIS_SIGNING_KEY=$(python -c 'import secrets;print(secrets.token_hex(32))')" >> .env
echo "AEGIS_API_KEYS=$(python -c 'import secrets;print(\"sk-aegis-\"+secrets.token_hex(16))')" >> .env
echo "AEGIS_BACKEND_API_KEY=your-openai-key-here" >> .env

# 4. Levantar el proxy
docker compose -f deploy/docker/docker-compose.yml --env-file .env up -d

# 5. Verificar
curl -sf http://localhost:8080/health
# → {"status":"healthy","version":"2.4.1"}

# 6. Dirigir tu aplicación al proxy
export OPENAI_BASE_URL="http://localhost:8080/v1"
# Desde este momento, todas las llamadas están gobernadas.
```

### Opción 2 — Kubernetes (Helm Chart)

Para despliegues en Kubernetes con alta disponibilidad:

```bash
helm install aegis ./deploy/helm \
  --set signingKey=$(python -c 'import secrets;print(secrets.token_hex(32))') \
  --set backendApiKey=your-openai-key \
  --set compliance.preset=finreg \
  --namespace aegis-system \
  --create-namespace
```

El Helm chart incluye:
- Deployment con recursos configurables y límites de CPU/memoria
- HPA (Horizontal Pod Autoscaler) para escalado automático
- PDB (Pod Disruption Budget) para alta disponibilidad en rolling updates
- ServiceAccount con RBAC mínimo
- PVC para el WAL de auditoría
- PrometheusRule para alertas de observabilidad

### Opción 3 — Air-Gapped (entornos clasificados)

Para entornos sin acceso a internet, el `Dockerfile.airgap` y el script `scripts/vendor_wheels.sh` permiten un proceso de dos pasos:

**Paso 1 (en máquina con red):**
```bash
scripts/vendor_wheels.sh            # descarga wheels → vendor/wheels/
docker save python:3.11-slim | gzip > vendor/python-3.11-slim.tar.gz
```

**Paso 2 (en red air-gapped, sin internet):**
```bash
docker load < vendor/python-3.11-slim.tar.gz
docker build --network=none \
    -f deploy/docker/Dockerfile.airgap \
    -t aegis-latent-core:2.4.1-airgap .
```

El resultado es una imagen completamente autónoma, sin dependencias de registros externos en tiempo de ejecución.

### Opción 4 — vLLM / Ollama (LLM on-premises)

Para organizaciones que despliegan sus propios modelos en la red interna:

```bash
# Con vLLM como backend
AEGIS_BACKEND_URL=http://vllm-host:8000 \
AEGIS_PROVIDER=openai \
  docker compose up -d

# Con Ollama como backend
AEGIS_BACKEND_URL=http://ollama-host:11434 \
AEGIS_PROVIDER=openai \
  docker compose up -d
```

La integración con LLMs locales es especialmente relevante para entornos de alta seguridad donde los datos no pueden salir de la red corporativa.

### Hardening de seguridad incluido

El despliegue por defecto incluye:
- **Perfil AppArmor:** restringe los syscalls del proceso proxy a los estrictamente necesarios, reduciendo la superficie de ataque del sistema operativo.
- **Usuario no-root:** el proceso corre como usuario `aegis` (UID 10001), sin privilegios de root.
- **WAL 0o600:** el archivo de log de auditoría solo es accesible por el proceso propietario.
- **Seccomp (Linux):** filtro de syscalls que bloquea operaciones no autorizadas a nivel de kernel.
- **Variables de entorno para secretos:** la clave de firma y las claves API nunca aparecen en el código; se inyectan por variables de entorno o Vault.

---

## 11. PRESETS DE CUMPLIMIENTO POR INDUSTRIA

Aegis incluye 7 presets de configuración prevalidados para los sectores más regulados:

### `finreg.env` — Servicios Financieros

Optimizado para: SEC Rule 17a-4, FINRA 4511, MiFID II, Basel III model risk

Configuraciones clave:
- `AEGIS_COMPLIANCE_PRESET=finreg`
- `ENABLE_SEC17A4_LABELS=true` — etiquetado para cumplimiento WORM
- `AEGIS_MAX_MEMORY_NODES=1000000` — retención de 1M nodos en memoria
- `AEGIS_FORCE_LOGPROBS=true` — requerido para análisis de entropía y evidencia FINRA
- `AEGIS_KL_ALERT_THRESHOLD=1.5` — umbrales ajustados para datos financieros
- mTLS requerido para MiFID II / FedWire / SWIFT
- Nota sobre NTP/PTP grandmaster para RTS 25 (tolerancia < 1ms para HFT)

### `healthcare.env` — Salud y Ciencias de la Vida

Optimizado para: HIPAA §164.312(b), 21 CFR Part 11, FDA SaMD

Configuraciones clave:
- `AEGIS_COMPLIANCE_PRESET=hipaa`
- `AEGIS_PHI_DEIDENTIFY=true` — HIPAA Safe Harbor §164.514(b), 18 categorías
- `AEGIS_KL_ALERT_THRESHOLD=1.8` — detección de alucinaciones clínicas
- mTLS para cumplimiento BAA

### `fedramp.env` — Gobierno Federal / DoD

Optimizado para: FedRAMP High, DoD IL5/IL6, CMMC Nivel 3

Configuraciones clave:
- `AEGIS_COMPLIANCE_PRESET=fedramp`
- `AEGIS_ENABLE_ABAC=true` — Bell-LaPadula para compartimentalización DoD IL5
- `AEGIS_ABAC_DEFAULT_LABEL=UNCLASSIFIED`
- `AEGIS_CAC_PIV_CA=/certs/dod_piv_ca.crt` — autenticación DoD CAC/PIV
- mTLS con CA DoD PKI
- `AEGIS_KL_ALERT_THRESHOLD=1.0` — umbrales muy ajustados
- Soporte completo de despliegue air-gapped

### `judicial.env` — Legal y Forense

Optimizado para: Estándar Daubert, FRE 702, SWGDE, ISO 27037

Configuraciones clave:
- `AEGIS_COMPLIANCE_PRESET=judicial`
- `AEGIS_MAX_MEMORY_NODES=5000000` — casos forenses pueden abarcar meses
- `AEGIS_FORCE_LOGPROBS=true` — análisis de entropía Shannon para forensia
- Endpoint de export para paquetes de evidencia admisibles

### `engineering.env` — Ingeniería y Sistemas (Alto Throughput)

Optimizado para: máximo throughput, mínima latencia, entornos de alta confianza

Configuraciones clave:
- `AEGIS_COMPLIANCE_PRESET=engineering`
- `UVICORN_WORKERS=4` — escalado por CPU
- `UVICORN_LOOP=uvloop` — ~2× throughput asyncio
- `AEGIS_RATE_LIMIT_THRESHOLD=1000` — límites generosos para tráfico interno
- CPU affinity para NUMA-aware throughput

### `scientific.env` — Investigación Científica

Optimizado para: reproducibilidad, documentación de experimentos computacionales, publicación científica

### `smb.env` — PyMEs (Cero Fricción)

Optimizado para: despliegue en 5 minutos, cero infraestructura externa

Configuraciones clave:
- `AEGIS_STORAGE_BACKEND=sqlite` — sin PostgreSQL requerido
- `AEGIS_RATE_LIMIT_BACKEND=asyncio` — sin Redis requerido
- `AEGIS_MAX_MEMORY_NODES=50000` — footprint de memoria conservador
- HTTP sin TLS para redes locales de desarrollo

---

## 12. RENDIMIENTO MEDIDO Y VALIDADO

Todos los números a continuación son el resultado de ejecución real en el entorno de desarrollo. La metodología completa está documentada en `docs/BENCHMARKS.md` con comandos exactos para reproducción.

**Entorno de medición (2026-06-25):**
- CPU: Intel Xeon @ 2,80 GHz, 4 cores
- RAM: ~16 GB
- OS: Linux 6.18.5 x86_64
- Python 3.11.15
- aegis_rust 3.0.0 (Rust, compilación release con LTO)

### Overhead del camino caliente de respuesta

La operación `_spawn_background()` que despacha el commit de auditoría es lo único que se ejecuta en el camino de respuesta. El commit en sí ocurre en background.

| Métrica | Valor |
|---|---|
| p50 (mediana) | **2,70 µs** |
| p99 | **12,90 µs** |
| Media | 3,67 µs |
| σ (desviación estándar) | 3,63 µs |
| n (muestras) | 5.000 |

Para contexto: 2,70 µs es 55.000 veces más pequeño que un milisegundo de latencia de red típica. El overhead de auditoría es, en términos prácticos, inmedible en producción.

### Tiempo de ida y vuelta WAF + HTTP

Tiempo de respuesta cliente-visible en entorno con upstream simulado in-process (latencia de red = 0):

| Condición | p50 | p95 | p99 |
|---|---|---|---|
| Con auditoría activa | **0,654 ms** | 1,479 ms | 1,829 ms |
| Sin auditoría (latencia base) | 0,614 ms | 1,049 ms | 1,588 ms |
| **Diferencia (overhead Aegis)** | **+0,040 ms** | +0,430 ms | +0,241 ms |

El overhead medido de Aegis sobre la latencia base es de ~40 µs en el percentil 50. En producción con latencia de red al modelo (típicamente 200–2000 ms), este overhead representa menos del 0,02% del tiempo total.

### Throughput de la cadena de auditoría criptográfica

| Operación | Throughput | Latencia/op |
|---|---|---|
| HMAC-SHA256 (solo firma, sin I/O) | **242.600 ops/s** | 4,1 µs |
| `commit_forensic()` (HMAC + MMR + WAL fsync real) | **9.310 commits/s** | 107 µs |
| `verify_integrity()` (barrido completo de cadena) | **88.350 nodos/s** | 11,3 µs |

**Nota sobre el rango de throughput de commit:** el número reportado (9.310/s) corresponde a condiciones de almacenamiento favorables. En mediciones anteriores con almacenamiento bajo presión, el throughput fue de 693/s. El rango sostenible en producción es 1.000–10.000 commits/s dependiendo del subsistema de almacenamiento (NVMe vs HDD vs red).

Dado que los commits ocurren en background (después de la respuesta al cliente), la velocidad del subsistema de almacenamiento no afecta la latencia percibida por el usuario.

### Throughput del servidor HTTP en producción simulada

Un solo worker uvicorn en la endpoint `/health` (stack ASGI completo):

| Concurrencia | RPS | p50 |
|---|---|---|
| 1 | 650 | 1,5 ms |
| 4 | **902** (pico) | 4,1 ms |
| 32 | 339 | 65 ms |

El pico de ~900 RPS es para un solo proceso. En producción con múltiples workers (uno por core) detrás de un load balancer, el throughput escala linealmente.

### Estabilidad bajo carga sostenida

100.000 solicitudes con concurrencia 256 (sobrecarga deliberada):
- **Errores: 0** (100% éxito)
- **Memory leak: ninguno** (RSS plano en 101,5 MiB inicio a fin)
- **Throughput bajo overload:** 275,6 RPS

---

## 13. EVIDENCIA DE CALIDAD: SUITE DE PRUEBAS

### 5.451 tests pasando. 95,18% de cobertura de ramas.

Esta no es una afirmación de marketing. Es el resultado de ejecutar:

```bash
pytest tests/ -x -q --cov=aegis --cov-report=term-missing --cov-fail-under=65
# Resultado: 5,451 passed · 5 skipped · 95.18% branch coverage
```

La suite de tests cubre:

**Seguridad (red team):**
- `test_red_team.py`: 100 threads × 50 commits concurrentes verificando que la cadena de auditoría no se bifurca.
- `test_security_fixes.py`: ataque de reordenamiento de nodos, bypass de autenticación, validación de HMAC.
- `test_waf_unit.py` y `test_waf_integration.py`: normalización NFKC, evasión por homoglifos, strips de caracteres de ancho cero.

**Criptografía:**
- `test_crypto_audit.py`: integridad de cadena hash, firmas HMAC, detección de tampeado.
- `test_pqc_signer.py`: generación real de keypairs ML-DSA-65, firma/verificación, rechazo de falsificaciones.

**Contratos de proveedor:**
- `test_provider_contracts.py`: traducción bidireccional para OpenAI, Anthropic (incluyendo SSE), Gemini, OpenRouter.

**Streaming SSE:**
- `test_app_coverage.py`: commits de auditoría sobreviven a desconexión del cliente en SSE.

**Análisis de entropía:**
- Tests de Shannon entropy, KL/JS divergence, detección de distribuciones inusuales.

**Extensión Rust:**
```bash
cargo test --manifest-path aegis_rust_v2/Cargo.toml --all-features
# Resultado: 26 tests pass
```

Incluyendo: roundtrip ML-DSA-65 sign/verify, rechazo de claves malformadas, identidad persistida que produce firmas verificables.

**Análisis estático:**
```bash
ruff check aegis aegis_server ...   # zero errores
bandit -r aegis/ aegis_server/ ...  # 0 HIGH findings
mypy --ignore-missing-imports ...   # zero type errors
```

### Sin marcadores de simulación

```bash
pytest tests/test_no_simulation_markers.py -v
# PASSED — len(KNOWN_SIMULATION_DEBT) == 0
```

Todo el comportamiento testado es real. No hay mocks de componentes de seguridad. Las firmas ML-DSA-65 se generan con el algoritmo real. Los hashes se calculan con las funciones reales. El WAL escribe en disco real.

---

## 14. MODELOS DE LICENCIAMIENTO Y PRECIOS

### Estructura de licencias

Aegis Latent Core se licencia bajo un modelo dual:

**AGPLv3 (Open Source):**
- Libre para uso, modificación y distribución bajo los términos de AGPLv3.
- Requiere que el código fuente de cualquier modificación se distribuya bajo AGPLv3.
- Apropiado para: proyectos open source, investigación académica, evaluación técnica.

**Licencia Comercial Propietaria:**
- Elimina las obligaciones de copyleft de AGPLv3.
- Incluye soporte comercial, SLAs, y garantías empresariales.
- Permite integración en productos comerciales propietarios.

Para la mayoría de las organizaciones empresariales, la licencia comercial es la vía correcta.

---

### Planes Comerciales

#### Plan Evaluación — Gratuito

**Para:** equipos técnicos que evalúan Aegis antes de una decisión de compra.

- Acceso completo a la versión AGPLv3
- Documentación técnica completa
- Acceso a la suite de benchmarks para verificación independiente
- Soporte de comunidad (GitHub Issues)
- Sin límite de tiempo para la evaluación técnica

*Restricción:* uso en producción con datos reales de clientes requiere licencia comercial.

---

#### Plan Startup — $9.900 USD/año

**Para:** startups, equipos de ingeniería, PyMEs con hasta 25 empleados técnicos.

**Incluye:**
- Licencia comercial propietaria (elimina las obligaciones AGPLv3)
- Soporte técnico por email con SLA de 72 horas en días hábiles
- Acceso a actualizaciones menores (2.4.x) y parches de seguridad durante la vigencia
- Configuración guiada con el preset `smb.env` o `engineering.env`
- Hasta 2 instancias en producción

**Limitaciones:**
- No incluye SLA de tiempo de actividad garantizado
- No incluye soporte para despliegue Kubernetes enterprise
- No incluye presets de cumplimiento healthcare/finreg/fedramp

---

#### Plan Empresa Self-Serve — $29.900 USD/año

**Para:** empresas medianas, fintech, proveedores de salud, contratistas de gobierno.

**Incluye:**
- Todo lo del Plan Startup
- Todos los presets de cumplimiento (finreg, healthcare, fedramp, judicial, scientific)
- Soporte técnico por email con SLA de 24 horas en días hábiles
- Licencia para instancias ilimitadas en la organización contratante
- Acceso a actualizaciones mayores (versión siguiente) durante la vigencia
- Configuración guiada para el sector vertical de la organización
- Documentación de cumplimiento para auditorías (SOC 2, HIPAA, etc.)
- Revisión de arquitectura de despliegue (1 sesión)

---

#### Plan Premium Soberano — desde $150.000 USD/año

**Para:** grandes corporaciones, agencias de gobierno, entidades financieras de nivel sistémico, organizaciones con requisitos de despliegue air-gapped o clasificado.

**Incluye:**
- Todo lo del Plan Empresa Self-Serve
- SLA de soporte 8×5 con tiempo de respuesta de 4 horas para incidentes críticos
- Despliegue air-gapped con acompañamiento técnico
- Integración con sistemas SIEM/SOAR de la organización
- Formación técnica para el equipo de seguridad (hasta 2 sesiones)
- Revisiones de seguridad trimestrales
- Participación en el roadmap del producto
- Posibilidad de instalación en instalaciones del cliente (on-premises sin conexión externa)
- Contrato de soporte con personal named

*Los precios del Plan Premium Soberano varían según el alcance del despliegue, los requerimientos de SLA, y los servicios profesionales incluidos. Precio base desde $150.000 USD/año.*

---

#### Plan OEM — Precio Negociado

**Para:** fabricantes de software que deseen integrar Aegis en sus productos como componente de gobernanza de IA.

**Características:**
- Licencia de distribución para redistribuir Aegis como parte de un producto comercial
- White-label disponible bajo negociación
- Integración técnica profunda con el equipo de Aegis
- Revenue share o royalty por unidad según volumen
- Acceso anticipado a features en desarrollo

*Contactar directamente para evaluación de oportunidad OEM.*

---

### Comparación de planes

| Característica | Evaluación | Startup | Empresa | Premium Soberano | OEM |
|---|:---:|:---:|:---:|:---:|:---:|
| Licencia comercial | — | ✓ | ✓ | ✓ | ✓ |
| Presets básicos (smb, eng) | ✓ | ✓ | ✓ | ✓ | ✓ |
| Presets regulados (finreg, healthcare, fedramp, judicial) | — | — | ✓ | ✓ | ✓ |
| Air-gapped deployment | — | — | — | ✓ | Negociado |
| Soporte técnico | Comunidad | 72h email | 24h email | 4h crítico | Dedicado |
| Instancias en producción | — | 2 | Ilimitadas | Ilimitadas | Ilimitadas |
| Revisión de arquitectura | — | — | 1 sesión | Trimestral | Continuo |
| Formación técnica | — | — | — | 2 sesiones | Continuo |
| Precio anual | Gratis | $9.900 | $29.900 | $150.000+ | Negociado |

---

## 15. PROCESO DE ADQUISICIÓN Y EVALUACIÓN

### Fase 1 — Evaluación Técnica (Semanas 1-2)

**Objetivo:** verificar independientemente que Aegis funciona como se describe.

1. **Descargar y ejecutar la suite de benchmarks:**
   ```bash
   git clone https://github.com/JuanLunaIA/aegis-latent-core
   cd aegis-latent-core && pip install -e ".[dev]"
   pytest tests/ -x -q --cov=aegis --cov-report=term-missing
   python -m benchmarks.bench_forwarding --warmup 200 --n 2000
   python -m benchmarks.bench_crypto_audit --n 2000 --k 5
   ```

2. **Despliegue de evaluación con su proveedor de LLM:**
   ```bash
   cp config/presets/smb.env .env
   # Configurar AEGIS_BACKEND_API_KEY con su clave de proveedor
   docker compose up -d
   # Redirigir una aplicación de prueba al proxy
   OPENAI_BASE_URL=http://localhost:8080/v1 python su_app_test.py
   ```

3. **Verificar el registro de auditoría:**
   ```bash
   curl -H "Authorization: Bearer $AUDIT_KEY" \
        http://localhost:8080/v1/enterprise/audit/recent
   ```

4. **Ejecutar el demo end-to-end:**
   ```bash
   python -m examples.demo
   # Esperado: "RESULT: 5/5 checks OK"
   ```

### Fase 2 — Prueba de Concepto en Entorno de Staging (Semanas 3-4)

**Objetivo:** validar la integración con los sistemas de la organización.

- Despliegue con el preset de cumplimiento relevante para la organización.
- Integración con el proveedor de LLM de producción.
- Prueba de los flujos de trabajo de auditoría y exportación de compliance.
- Validación del overhead de latencia en cargas de trabajo reales.
- Revisión por el equipo de seguridad del cliente.

### Fase 3 — Decisión y Contratación (Semana 5)

- Selección del plan de licencia apropiado.
- Revisión del contrato comercial.
- Configuración de los mecanismos de pago y soporte.
- Planificación del despliegue en producción.

### Fase 4 — Despliegue en Producción (Semanas 6-8)

- Migración del entorno de staging a producción.
- Configuración de monitoreo y alertas.
- Formación del equipo operativo.
- Documentación de la configuración de compliance.

---

## 16. PREGUNTAS FRECUENTES DE DIRECTIVOS

**P: ¿Aegis lee el contenido de nuestros prompts?**

R: Aegis inspecciona el contenido de las solicitudes para aplicar los motores de detección (WAF, secretos, marcadores de clasificación, etc.). El WAL de auditoría almacena el *hash* del contenido, no el contenido en bruto. El contenido del prompt no persiste en texto claro en el log. Para entornos de salud, la de-identificación de PHI opera antes de cualquier persistencia.

**P: ¿Qué pasa si el proveedor de LLM cae? ¿Aegis introduce un punto único de falla?**

R: Aegis es un proxy en línea; si cae, las solicitudes al LLM también fallan. Sin embargo, el diseño de alta disponibilidad —múltiples instancias en Kubernetes con HPA— elimina el punto único de falla. La alternativa de no usar proxy también tiene un punto único de falla: el propio proveedor de LLM.

**P: ¿Cuánto almacenamiento consume el WAL de auditoría?**

R: Cada nodo de auditoría contiene hashes y metadatos, no el contenido completo. El tamaño típico por nodo es de 1-5 KB. A 1.000 requests/hora, eso es entre 24 MB y 120 MB por día. Con retención de 7 años (requisito 17a-4), y asumiendo 1 TB de almacenamiento disponible a ~$25/mes en S3, el costo de almacenamiento es insignificante comparado con el costo regulatorio de no tener los registros.

**P: ¿Aegis añade latencia perceptible para los usuarios finales?**

R: El overhead medido es de ~40 µs en el p50 (microsegundos, no milisegundos). La latencia de los modelos de lenguaje suele ser de 200–2.000 ms. El overhead de Aegis es entre 0,002% y 0,02% del tiempo total de respuesta — completamente imperceptible para los usuarios.

**P: ¿Con qué proveedores de LLM es compatible Aegis?**

R: Aegis es compatible con cualquier proveedor que use el protocolo OpenAI (la mayoría), con módulos de traducción específicos para Anthropic, Gemini, OpenRouter, Azure OpenAI, vLLM y Ollama. Para proveedores con protocolos propietarios, el módulo de integración puede desarrollarse bajo el plan OEM.

**P: ¿Cómo se rota la clave de firma HMAC?**

R: La rotación de clave es una operación de configuración. Se genera una nueva clave, se configura en `AEGIS_SIGNING_KEY`, y se reinicia el servicio. Los bundles de compliance firmados con la clave antigua son verificables con la clave antigua archivada. La documentación recomienda rotación anual para `finreg` y trimestral para entornos de mayor exigencia.

**P: ¿Es Aegis FIPS 140-3 compliant?**

R: Aegis usa HMAC-SHA256 (FIPS 198-1) y ML-DSA-65 (FIPS 204) como algoritmos criptográficos. Para cumplimiento FIPS 140-3 completo a nivel de módulo, debe ejecutarse sobre un kernel Linux con OpenSSL FIPS habilitado y la wheel musllinux con OpenSSL vendorizado en build FIPS. Esta configuración es parte del soporte Premium Soberano.

**P: ¿Qué garantías se incluyen en la licencia comercial?**

R: La licencia comercial incluye garantías de que el software funciona según su documentación y que los benchmarks son reproducibles. El SLA específico de uptime y tiempo de respuesta depende del plan contratado. Ver el contrato comercial (`COMMERCIAL.md`) para términos completos.

**P: ¿Aegis es compatible con frameworks de IA como LangChain, LlamaIndex, o AutoGen?**

R: Sí. Cualquier framework que use la API OpenAI — incluyendo LangChain, LlamaIndex, AutoGen, CrewAI, y otros — funciona automáticamente con Aegis cambiando la `base_url`. No se requiere ningún cambio en el código del framework.

**P: ¿Se puede integrar con nuestro SIEM/SOAR existente?**

R: Sí. El campo `AEGIS_WEBHOOK_URL` acepta una URL de webhook que recibe eventos de seguridad (bloqueos WAF, alertas de entropía, eventos de tasa límite). Este mecanismo es compatible con Splunk, IBM QRadar, Microsoft Sentinel, PagerDuty, y cualquier sistema que acepte webhooks HTTP.

**P: ¿Cómo se gestiona el acceso multi-tenant?**

R: Aegis soporta multi-tenancy a través del campo `AEGIS_TENANT_ID_FIELD`, que permite separar los registros de auditoría por tenant. Cada tenant puede tener sus propias claves API de Aegis (`AEGIS_API_KEYS`) para control de acceso granular.

---

## 17. GARANTÍAS Y LÍMITES HONESTOS

En Aegis creemos que la honestidad sobre los límites del sistema es tan importante como documentar sus capacidades. Esta sección describe explícitamente lo que Aegis hace y lo que no hace.

### Lo que Aegis garantiza (implementado y testado)

- **Cadena de auditoría hash-linkada y verifiable:** cualquier alteración, reordenamiento, o eliminación de nodos rompe la cadena y es detectable por `verify_integrity()`. Probado con tests de tampering activo.
- **Signing HMAC-SHA256:** cada nodo de auditoría tiene una firma HMAC-SHA256 verificable. 242.600 ops/s medidos.
- **Signing ML-DSA-65 (FIPS 204):** firma post-cuántica de la raíz del árbol Merkle. Implementada en Rust con `pqcrypto-mldsa`, con zeroización de clave privada. 26 tests de Rust pasando.
- **De-identificación PHI (18 categorías HIPAA Safe Harbor):** probado en el suite de tests.
- **WAF de dos capas:** bloqueo incondicional de patrones críticos + puntuación acumulada de patrones soft.
- **Detección activa de 10 vectores de ataque** documentados en código y tests.
- **Zero overhead en camino caliente:** commit de auditoría en background vía `asyncio.create_task()`. 2,70 µs p50 medido.
- **Despliegue air-gapped:** `Dockerfile.airgap` completo, sin dependencias de red en tiempo de build.
- **Soporte multi-proveedor:** OpenAI, Anthropic (con SSE), Gemini, OpenRouter, vLLM, Ollama. Tests de contrato para cada uno.

### Capacidades parciales (implementadas con limitaciones documentadas)

- **[PARCIAL] Firma ML-DSA-65:** activa solo cuando la extensión Rust está compilada e instalada. Sin Rust, el fallback es HMAC-SHA256 (con clave) o Ed25519 efímero (sin clave, resultado: `legal_admissibility="Compromised"`). El fallback Python no zeroiza el material de clave.
- **[PARCIAL] Análisis de entropía para Anthropic y Gemini:** ninguna de las dos APIs expone logprobs de tokens; el analizador usa entropía a nivel de carácter (menos precisa). Documentado en `docs/audit/CLAIMS_VERIFICATION.md`.
- **[PARCIAL] mTLS entre proxy y upstream:** los certificados cliente se aplican a uvicorn y al cliente httpx upstream, pero la identidad del certificado cliente no se verifica por request en el proceso de autenticación.
- **[PARCIAL] PKCS#7 CMS SignedData nativo:** los bundles de compliance incluyen firmas HMAC-SHA256 verificables. La emisión directa de PKCS#7 CMS es una capa de wrapping, no una emisión nativa del estándar. En la hoja de ruta para mejora.
- **[PARCIAL] EWF/E01 Forensic Expert Witness Format:** el export de evidencia forense en formato EWF/E01 compatible con EnCase/FTK es una característica en la hoja de ruta, no completamente implementada en la versión actual.

### Lo que Aegis explícitamente no hace

- **No modifica el contenido de las respuestas del modelo:** Aegis es un proxy que observa y registra. No censura, no filtra, no altera las respuestas del LLM (excepto bloquear solicitudes antes de enviarlas al modelo).
- **No garantiza comportamiento del modelo:** Aegis registra y protege la interfaz, pero no puede garantizar que el modelo no alucinará o no generará contenido inapropiado. Ese es el dominio de los propios modelos y sus safety systems.
- **No es un BAA:** para uso de PHI con proveedores externos de LLM, un Business Associate Agreement separado con cada proveedor es requerido. Aegis es un control técnico, no un acuerdo contractual.
- **No almacena el contenido completo de prompts en el WAL por defecto:** solo los hashes. Si necesita contenido completo para forense, configúrelo explícitamente y asegúrese de que es compatible con sus obligaciones de privacidad.

---

## 18. INFORMACIÓN DE CONTACTO Y PRÓXIMOS PASOS

### Contacto Comercial

**Juan Luna**
Creador y responsable comercial de Aegis Latent Core

Email: juan.c.luna04@gmail.com

Para consultas sobre:
- Evaluación técnica guiada
- Planes empresariales y precios personalizados
- Plan OEM y acuerdos de integración
- Requerimientos de compliance específicos de la industria
- Despliegue en entornos clasificados o air-gapped

### Recursos Técnicos

- **Repositorio GitHub:** https://github.com/JuanLunaIA/aegis-latent-core
- **Benchmarks reproducibles:** `docs/BENCHMARKS.md`
- **Verificación de claims:** `docs/audit/CLAIMS_VERIFICATION.md`
- **Guía de despliegue Rust:** `docs/RUST_BUILD.md`
- **Modelo de amenaza:** `docs/security/THREAT_MODEL.md`
- **Guía de escalado:** `docs/performance/SCALING_GUIDE.md`

### Próximos pasos recomendados según perfil

**Si usted es CTO/Arquitecto:**
1. Clone el repositorio y ejecute la suite de tests.
2. Ejecute `python -m examples.demo` para la demostración end-to-end.
3. Ejecute los benchmarks para verificar los números de rendimiento independientemente.
4. Despliegue en un entorno de staging con el preset de su industria.

**Si usted es CISO/Director de Cumplimiento:**
1. Revise `docs/audit/CLAIMS_VERIFICATION.md` para verificar los claims de seguridad.
2. Revise `docs/security/THREAT_MODEL.md` para el modelo de amenaza completo.
3. Revise el preset de compliance de su industria para validar la alineación regulatoria.
4. Solicite una llamada técnica para preguntas específicas de compliance.

**Si usted es CEO/Junta Directiva:**
1. Solicite una demostración en vivo de 30 minutos (contactar por email).
2. Solicite una propuesta económica personalizada para su volumen y sector.
3. Comparta este documento con su CISO y CTO para evaluación técnica paralela.

**Si usted es Director de Adquisiciones:**
1. Solicite el documento `COMMERCIAL.md` con términos completos de la licencia comercial.
2. Confirme el tier de licencia apropiado para su organización.
3. Inicie el proceso de aprobación interna con el Resumen Ejecutivo (Sección 1) y el Caso Financiero (Sección 4).

---

## APÉNDICE A: GLOSARIO DE TÉRMINOS TÉCNICOS

| Término | Definición |
|---|---|
| **ABAC** | Attribute-Based Access Control — control de acceso basado en atributos como nivel de clasificación |
| **Aho-Corasick** | Algoritmo de búsqueda de múltiples patrones en texto que opera en tiempo lineal; la implementación SIMD aprovecha instrucciones vectoriales de la CPU |
| **Air-gapped** | Entorno físicamente aislado de redes externas, incluyendo internet |
| **BLAKE3** | Función hash criptográfica moderna, ~4 GB/s en hardware moderno |
| **CMMC** | Cybersecurity Maturity Model Certification — certificación de madurez en ciberseguridad para contratistas del DoD |
| **EWF/E01** | Expert Witness Format — formato estándar de imágenes forenses para adquisición de evidencia digital |
| **FedRAMP** | Federal Risk and Authorization Management Program — framework de seguridad cloud del gobierno federal de EE.UU. |
| **FIPS 204** | Federal Information Processing Standard para ML-DSA (Module-Lattice Digital Signature Algorithm) |
| **HMAC-SHA256** | Hash-based Message Authentication Code usando SHA-256 — mecanismo estándar de firma simétrica |
| **IOC** | Indicator of Compromise — indicador de que un sistema ha sido comprometido |
| **ISO 27037** | Estándar internacional para identificación, adquisición y preservación de evidencia digital |
| **LTO** | Link Time Optimization — optimización de código en tiempo de enlace que mejora el rendimiento de binarios Rust |
| **mTLS** | Mutual TLS — autenticación mutua con certificados en ambos extremos de la conexión |
| **ML-DSA** | Module-Lattice Digital Signature Algorithm — algoritmo de firma digital post-cuántico (NIST FIPS 204) |
| **MMR** | Merkle Mountain Range — estructura de datos para acumulación de cadenas hash |
| **NFKC** | Normalización Unicode que colapsa caracteres visualmente similares (homoglifos) a su forma canónica |
| **OT** | Operational Technology — tecnología de control industrial (PLC, SCADA, DCS) |
| **PHI** | Protected Health Information — información de salud protegida bajo HIPAA |
| **PKCS#7 / CMS** | Cryptographic Message Syntax — estándar para mensajes firmados y cifrados |
| **Post-cuántico** | Criptografía resistente a ataques de computadoras cuánticas |
| **PQC** | Post-Quantum Cryptography |
| **PyO3** | Framework para crear extensiones Python nativas en Rust |
| **RAG** | Retrieval-Augmented Generation — técnica que enriquece el contexto del LLM con documentos recuperados de una base de conocimiento |
| **SaMD** | Software as a Medical Device — software que califica como dispositivo médico bajo FDA |
| **SIMD** | Single Instruction, Multiple Data — instrucciones vectoriales de CPU que procesan múltiples datos en paralelo |
| **SOC 2** | Service Organization Control 2 — framework de auditoría de seguridad para proveedores de servicios |
| **SSE** | Server-Sent Events — protocolo de streaming unidireccional de servidor a cliente |
| **WORM** | Write Once Read Many — almacenamiento donde los datos no pueden ser modificados una vez escritos |
| **WAF** | Web Application Firewall — cortafuegos que inspecciona el contenido de las solicitudes HTTP |
| **WAL** | Write-Ahead Log — archivo de log que garantiza durabilidad escribiendo antes de aplicar cambios |
| **zeroize** | Sobrescritura segura de material criptográfico en memoria al liberarlo |

---

## APÉNDICE B: MARCOS REGULATORIOS CUBIERTOS

| Marco | Jurisdicción | Sectores | Controles Aegis Relevantes |
|---|---|---|---|
| GDPR | Unión Europea | Todos | Auditoría, de-identificación, control de acceso |
| AI Act | Unión Europea | Todos (IA de alto riesgo) | Trazabilidad, robustez, supervisión humana |
| HIPAA | EE.UU. | Salud | §164.312(b) audit controls, PHI de-identification |
| 21 CFR Part 11 | EE.UU. | Salud/Farma | E-signature export, tamper-evident records |
| FDA SaMD | EE.UU. | Dispositivos médicos software | Continuous monitoring, inference-level forensics |
| SEC Rule 17a-4 | EE.UU. | Servicios financieros | WORM records, 6-year retention |
| FINRA 4511 | EE.UU. | Servicios financieros | Electronic records, audit trails |
| MiFID II RTS 24/25 | Unión Europea | Servicios financieros | Tamper-proof records, timestamp sync |
| FedRAMP High | EE.UU. | Gobierno federal | NIST SP 800-53 Rev 5 AU-2, AU-3, AU-9, AU-10 |
| DoD IL5/IL6 | EE.UU. | Defensa | ABAC, ClassifiedMarker, air-gap |
| CMMC Nivel 3 | EE.UU. | Contratistas DoD | Auditoría, control de acceso, protección de CUI |
| IEC 62443 | Internacional | Infraestructura crítica | OTProtocolScanner, IOCCorrelator |
| ISO 27001 | Internacional | Todos | ISMS, audit trail, access control |
| ISO 27037 | Internacional | Forense | Evidence packages, chain of custody |
| NIST CSF 2.0 | EE.UU. | Todos | Identify, Protect, Detect functions |
| SOC 2 Type II | EE.UU./Internacional | Tecnología | CC6, CC7, CC9 controls |
| Daubert / FRE 702 | EE.UU. | Legal/Forense | Verifiable methodology, tamper-evident records |
| LGPD | Brasil | Todos | Procesamiento documentado, control de acceso |
| NIST SP 800-188 | EE.UU. | Gobierno/Salud | De-identification, Safe Harbor 18 categories |

---

## APÉNDICE C: ARQUITECTURA DE SEGURIDAD — RESUMEN

```
┌─────────────────────────────────────────────────────────────────┐
│                     AEGIS LATENT CORE v2.4.1                    │
│                                                                  │
│  ┌──────────┐    ┌──────────────────────────────────────────┐   │
│  │ Cliente  │───▶│          FastAPI + Uvicorn ASGI          │   │
│  │ (tu app) │    │                                          │   │
│  └──────────┘    │  ┌─────────────────────────────────┐    │   │
│                  │  │    Auth Layer (API Keys / mTLS)  │    │   │
│                  │  └─────────────────────────────────┘    │   │
│                  │  ┌─────────────────────────────────┐    │   │
│                  │  │   RustWaf (Aho-Corasick SIMD)   │    │   │
│                  │  │   10 Detection Engines           │    │   │
│                  │  └─────────────────────────────────┘    │   │
│                  │  ┌─────────────────────────────────┐    │   │
│                  │  │   RustForwarder (HTTP/2 Tokio)  │────┼───▶ LLM
│                  │  └─────────────────────────────────┘    │   │
│                  │  ┌─────────────────────────────────┐    │   │
│                  │  │   asyncio.create_task()          │    │   │
│                  │  │   (background, off hot path)     │    │   │
│                  │  └────────────┬────────────────────┘    │   │
│                  └───────────────┼──────────────────────────┘   │
│                                  │                               │
│  ┌───────────────────────────────▼───────────────────────────┐  │
│  │              Cryptographic Audit Pipeline                  │  │
│  │                                                            │  │
│  │  HMAC-SHA256(node) → ML-DSA-65(MMR root) → WAL fsync      │  │
│  │                                                            │  │
│  │  Tamper-evident chain: prev_hash linkage                   │  │
│  │  9,310 commits/s · 88,350 verify/s · 242,600 sign/s       │  │
│  └────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

---

*Aegis Latent Core v2.4.1*

*Copyright (c) 2026 Juan Luna. Todos los derechos reservados.*

*Licenciado bajo AGPLv3 o bajo una Licencia Comercial Propietaria.*

*Para términos completos: ver LICENSE y COMMERCIAL.md en el repositorio.*

*Contacto: juan.c.luna04@gmail.com*

*Este documento es el Prospecto Comercial oficial de Aegis Latent Core.*

*Los benchmarks contenidos en este documento son mediciones reales ejecutadas el 25 de junio de 2026 y documentadas en docs/BENCHMARKS.md con metodología reproducible.*

*Ningún número de rendimiento en este documento es una estimación o aspiración. Las afirmaciones marcadas como [PARCIAL] tienen limitaciones explícitamente documentadas en el código fuente y en docs/audit/CLAIMS_VERIFICATION.md.*

---

*Documento generado: 25 de junio de 2026 · Versión 2.4.1-ES*
