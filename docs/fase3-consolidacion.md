# Consolidación de hallazgos y propuesta de remediación

**Fase:** 3 — Stretch Goal ASVS Level 1
**Paquete:** WBS 5.4
**Fecha:** 25 de septiembre de 2026
**Preparado por:** Lorenzo Mtz

> **Estado:** completo. La decisión de 5.4.3 fue la **Opción B** y quedó registrada en el
> Charter, Sección 10, cambio #6: se abre una **Fase 4 de remediación acotada** a los
> siete gaps de Nivel 1, desglosada en el WBS v1.5 como sección 6.0.

---

## 1. De dónde viene cada hallazgo

Tres ejercicios independientes produjeron tres inventarios:

| Ejercicio | Paquete | Qué produjo |
|---|---|---|
| Recorrido del OWASP Top 10:2025 | 4.5.6 | 5 huecos no registrados en ningún artefacto |
| Threat model STRIDE | 5.2 | 36 amenazas, 14 sin control, en 3 causas raíz |
| Autoevaluación ASVS Level 1 | 5.3 | 12 `fail` sobre 54 evaluados, en 7 problemas |

**El solapamiento es el dato más útil de la consolidación.** Un hallazgo que aparece en los tres ejercicios, por caminos metodológicos distintos, es más sólido que uno que aparece en uno solo — y uno que aparece en uno solo señala qué método aporta algo que los otros no ven.

| Convergencia | Hallazgo |
|---|---|
| **Los tres** | El token de recuperación viaja en la URL |
| **Dos** | Cabeceras de seguridad ausentes · Manejadores de error ausentes · `@login_required` sin *deny by default* |
| **Solo el threat model** | El log no sostiene no repudio (**ASVS L1 no lo puede ver: V16 no tiene requisitos de nivel 1**) · El alcance real del atacante con acceso al disco |
| **Solo el ASVS** | No hay cambio de contraseña autenticado · La reautenticación no invalida la sesión anterior · Sin plazos de remediación documentados |

Lo que solo vio el ASVS tiene una característica común: **son ausencias, no debilidades**. El Top 10 y el threat model evalúan lo que existe; el checklist es el único que pregunta por lo que falta. Y lo que solo vio el threat model es lo que el estándar, a nivel 1, sencillamente no cubre.

---

## 2. Lista priorizada de gaps (WBS 5.4.1)

Criterios de orden: **impacto** si se explota, **costo** de remediar, y **convergencia** (en cuántos ejercicios apareció).

### Nivel 1 — Barato y de alto rendimiento

Todo este nivel cabe en una o dos sesiones de trabajo y cierra ocho incumplimientos de nivel 1.

| # | Gap | Cierra | Costo |
|---|---|---|---|
| G1 | **Cabeceras de seguridad** en un `after_request`: `Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy` | V3.2.1, **TM-34** (por `Referrer-Policy: no-referrer`), A02 | Bajo |
| G2 | **Prefijo `__Host-` en la cookie** de sesión | V3.3.1 | **Una línea** |
| G3 | **Incrementar `session_version` al autenticar** | V7.2.4, TM-02 | **Una línea** |
| G4 | **Manejadores globales de 404 y 500** que no filtren y **que auditen** | TM-14, TM-11 parcial, A10 | Bajo |
| G5 | **Rotación del log** con techo de tamaño | TM-28, R18 parcial, A09 | Bajo |
| G6 | **Validación del nombre de usuario**: lista blanca de caracteres y longitud máxima | V2.1.1, V2.2.1, LL20, A05 | Bajo |
| G7 | **Documentar plazos de remediación** de dependencias basados en riesgo | V15.1.1 | **Un párrafo** |

**Corrección (25 de septiembre de 2026, durante 6.1):** la versión inicial de esta fila decía que G1 cerraba *"V3.4.1 (parcial sin TLS)"*. Era incorrecto: **no se debe emitir `Strict-Transport-Security` sobre HTTP plano** —los navegadores lo ignoran, y si llegara a tomar efecto sin TLS dejaría la aplicación inalcanzable—, así que HSTS entra con G14 y **V3.4.1 sigue en `fail` después de G1**. A cambio, `Referrer-Policy: no-referrer` cierra TM-34 del todo y no parcialmente, mientras el token siga en la URL.

G2 y G3 son de una línea cada uno y cierran, entre los dos, un incumplimiento de nivel 1 y un hallazgo nuevo. **G3 es el de mejor relación valor/costo de toda la lista**: el mecanismo (`session_version`) existe desde la Fase 1, y solo falta invocarlo en un momento más.

### Nivel 2 — Trabajo real, valor alto

| # | Gap | Cierra | Costo |
|---|---|---|---|
| G8 | **Cambio de contraseña autenticado**, pidiendo la actual y la nueva | V6.2.2, V6.2.3 | Medio — ruta, plantilla y pruebas |
| G9 | **Comprobación contra contraseñas filtradas** (al menos las 3000 peores que cumplan la política) | V6.2.4, V6.3.1 | Medio |
| G10 | **Mover el token de recuperación fuera de la URL**, al cuerpo de un POST | V14.2.1, TM-34, R11 residual | Medio |
| G11 | **Límite de tasa en `/forgot-password`** | TM-17, R11 residual | Bajo-medio |
| G12 | ***Deny by default*** en las rutas protegidas, con lista explícita de rutas públicas | TM-21, A01 | Medio |
| G13 | **Límites de recursos**: tamaño máximo de petición y cuotas | TM-18, A06, A10 | Bajo-medio |

**G8 tiene una consecuencia de seguridad que no es obvia.** Hoy, cambiar la contraseña obliga a pasar por el correo de recuperación: el usuario ya autenticado **retrocede a una credencial más débil**, y el sistema emite un token al portador para una operación que no lo necesita. No es solo una funcionalidad que falta.

### Nivel 3 — Infraestructura, fuera del alcance actual del proyecto

Requieren un despliegue real, que el Scope Statement excluye en su Sección 4.

| # | Gap | Cierra |
|---|---|---|
| G14 | **TLS**, servidor WSGI y `debug=False` | TM-06, TM-32, TM-33, V12 completo, A02, A04 |
| G15 | **Permisos restrictivos** sobre `instance/` y `.env`; respaldos de la base | R17 parcial |
| G16 | **Log fuera del alcance de escritura de la aplicación** (*append-only* o destino externo) | R18, TM-26 |
| G17 | **Algo que lea el log**: umbrales y alertas | R18, A09 |
| G18 | **SBOM y `--require-hashes`** | A03, A08, TM parcial |

**G14 es el hallazgo individual que más superficie cierra**: cinco amenazas del threat model y los tres requisitos de V12. Está en el nivel 3 no por poca importancia, sino porque exige salir del alcance del proyecto.

### Nivel 4 — Aceptados, se mantienen

| # | Gap | Riesgo | Por qué se mantiene |
|---|---|---|---|
| G19 | Secreto TOTP sin cifrar | R12 | Cifrarlo exige gestión de llaves. **Releído en 5.2**: la aceptación sigue siendo válida, pero su alcance real está ahora en R17 |
| G20 | Sin códigos de respaldo de MFA | R13 | Decidió el diseño del enrolamiento: MFA opcional y activable desde el dashboard |
| G21 | Una contraseña escrita en el campo "Usuario" queda en el log | R14 residual | Inherente a registrar el nombre de usuario de un intento fallido |
| G22 | Sin límite por IP (*password spraying*) | R10 residual | Fuera del alcance de 4.1; parcialmente atendido por G9 |
| G23 | El canal de entrega no firma sus mensajes | TM-05 | Solo tiene sentido con un canal de entrega real (depende de G14) |

---

## 3. Altas en el Risk Register (WBS 5.4.2)

**Criterio para dar de alta:** solo si el riesgo **no está cubierto por ninguna entrada existente**. Un registro inflado con una entrada por hallazgo pierde la utilidad que tiene un registro corto y verdadero — es el mismo argumento de LL19 sobre el catálogo de eventos, aplicado a los riesgos.

Con ese criterio, de los 23 gaps solo **dos** exigen entrada nueva, y **dos entradas existentes** necesitan actualizarse:

| Acción | Entrada | Motivo |
|---|---|---|
| **Alta** | **R19** — No existe cambio de contraseña autenticado | Ninguna entrada cubre la ausencia de esa funcionalidad ni su consecuencia: obligar a emitir un token al portador para una operación autenticada |
| **Alta** | **R20** — Validación de entrada incompleta en el nombre de usuario | LL20 lo documenta como lección, pero **ninguna entrada del registro lo trata como riesgo**. Dos incumplimientos de nivel 1 apuntan ahí |
| Actualizar | **R9** | La reautenticación sin revocación (V7.2.4) es un caso concreto del riesgo que R9 ya describe: una cookie robada que sigue sirviendo. No es un riesgo nuevo, es una vía de R9 que no se había cerrado |
| Actualizar | **R6** | La ausencia de plazos de remediación (V15.1.1) es un hueco del propio plan de respuesta de R6, que define cuándo revisar pero no en cuánto arreglar |

**Lo que deliberadamente NO se da de alta:** las cabeceras de seguridad, los manejadores de error, la rotación del log y el resto del nivel 1 y 2. Son **trabajo pendiente**, ya inventariado en la deuda de Fase 2 y en este documento, no riesgos sin dueño. El Risk Register registra riesgos; la lista de gaps registra trabajo. Mezclarlos los vuelve inservibles a los dos.

---

## 4. Propuesta de alcance (WBS 5.4.3)

El Charter (Sección 5) coloca **M5 Cierre del proyecto** inmediatamente después de la Fase 3. Abrir una fase de remediación es, por tanto, **un cambio de alcance** y se decide por el Registro de Cambios, no por inercia.

Tres opciones:

### Opción A — Cerrar el proyecto tras la Fase 3

Es lo que dice el Charter hoy. Los 23 gaps quedan documentados como **estado final conocido**, con su priorización, y el proyecto entrega lo que prometió: autenticación endurecida, más una autoevaluación honesta de lo que le falta.

*A favor:* cumple el alcance sin ampliarlo, que es la respuesta a R1. Un proyecto de aprendizaje que sabe exactamente qué le falta y por qué ya demostró lo que tenía que demostrar.
*En contra:* deja sin hacer G2 y G3, que son **dos líneas de código** y cierran un incumplimiento de nivel 1 y un hallazgo nuevo.

### Opción B — Fase 4 acotada al Nivel 1 *(recomendada)*

Solo los siete gaps del Nivel 1. Alcance cerrado y verificable de antemano, sin puerta abierta a "ya que estamos".

*A favor:* cierra **ocho incumplimientos de nivel 1** y sube el resultado de la autoevaluación de 32/44 a 40/44. Todo el nivel es de costo bajo, encaja en la disponibilidad de 4–8 horas semanales, y cada gap tiene un criterio de terminado objetivo — el requisito ASVS que cierra.
*En contra:* es alcance nuevo y exige cambio formal en el Charter, con renumeración del hito de cierre.

### Opción C — Fase 4 con Niveles 1 y 2

Los trece gaps. Dejaría la aplicación sustancialmente completa frente a ASVS Level 1.

*A favor:* G8, G9 y G10 son los que de verdad mejoran la postura de seguridad, no solo el resultado del checklist.
*En contra:* es del tamaño de la Fase 2 entera. Con la disponibilidad actual y sin fecha comprometida, el riesgo no es fallar sino **quedarse a medias**, que es exactamente R16 repitiéndose una fase más tarde.

### Recomendación

**Opción B.** El argumento decisivo no es el conteo de requisitos: es que G2 y G3 cuestan una línea cada uno, y dejar sin hacer un arreglo de una línea que cierra un hallazgo **que este mismo proyecto encontró** es difícil de justificar en un documento que se va a leer como pieza de portafolio (O1).

Si se elige B, el Nivel 2 no se descarta: se propone como alcance de una fase posterior, y el Nivel 3 queda explícitamente fuera mientras no haya despliegue.

### Decisión tomada

**Opción B**, registrada en el Charter (Sección 10, cambio #6) el 25 de septiembre de 2026.

Se abre la **Fase 4 — Remediación acotada**, desglosada en el WBS v1.5 como sección 6.0 (paquetes 6.1 a 6.8), con alcance **cerrado** a los siete gaps de Nivel 1: G1 a G7. Cada paquete lleva su criterio de terminado objetivo — el requisito ASVS o la amenaza del threat model que cierra.

Consecuencias de gobernanza: el cierre del proyecto pasa de la sección 6.0 a la **7.0** del WBS y del hito M5 al **M6**; los paquetes que el cambio #5 asignó como "6.1 y 6.2" —la deuda de Fase 0— son ahora **7.1 y 7.2**. La entrada #5 **no se editó**: reescribir una entrada pasada del registro de cambios destruiría la trazabilidad que justifica tenerlo, así que la renumeración se hace constar en la entrada nueva.

**El Nivel 2 no queda descartado**, queda fuera de *esta* fase. Si se quiere atender, se decide por el mismo camino por el que se decidió esta. El Nivel 3 permanece fuera mientras no haya despliegue (Scope Statement, Sección 4), y el Nivel 4 sigue aceptado.

---

*Los gaps de este documento se revisan en el cierre de la Fase 3 (5.5) y, si se abre remediación, se convierten en su WBS.*
