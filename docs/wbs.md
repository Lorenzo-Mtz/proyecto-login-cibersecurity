# Estructura de Desglose del Trabajo / Work Breakdown Structure (WBS)

**Proyecto:** Sistema de Login Seguro — Proyecto de Aprendizaje en Ciberseguridad
**Enfoque:** Rolling Wave Planning — todas las fases desglosadas a nivel de paquete de trabajo (*work package*).
**v1.5** — se agrega la Fase 4, remediación acotada (ver Charter, Sección 10 — Registro de Cambios, cambio #6). El cierre del proyecto pasa de 6.0 a **7.0**
**v1.4** — desglose de la Fase 3 (ver Charter, Sección 10 — Registro de Cambios, cambio #5)
**v1.3** — se agrega la tarea 4.6.4, suite de pruebas automatizadas (ver Charter, Sección 10 — Registro de Cambios, cambio #3)
**v1.2** — desglose de la Fase 2 (ver Charter, Sección 10 — Registro de Cambios, cambio #2)
**v1.1** — actualizado para incorporar la Fase 0 (ver Charter, Sección 10 — Registro de Cambios, cambio #1)

---

## 1.0 Gestión del Proyecto / Project Management

- 1.1 Project Charter
- 1.2 Scope Statement
- 1.3 Work Breakdown Structure (WBS)
- 1.4 Risk Register
- 1.5 Lessons Learned Log *(actualización continua)*
- 1.6 Glosario bilingüe *(actualización continua)*

---

## 2.0 Fase 0 — Fundamentos Teóricos *(detallado)*

**2.1 Protocolo HTTP/HTTPS**
- 2.1.1 Repasar diferencias HTTP vs HTTPS, y el rol de TLS
- 2.1.2 Nota de estudio + términos nuevos al glosario

**2.2 Criptografía y Hashing**
- 2.2.1 Repasar hashing vs cifrado (encryption), y por qué las contraseñas se hashean y no se cifran
- 2.2.2 Repasar concepto de "salt" y por qué bcrypt lo incorpora
- 2.2.3 Nota de estudio + términos nuevos al glosario

**2.3 Autenticación y Autorización (AuthN / AuthZ)**
- 2.3.1 Repasar la diferencia entre "quién eres" (autenticación) y "qué puedes hacer" (autorización)
- 2.3.2 Nota de estudio + términos nuevos al glosario

**2.4 Gestión de Sesiones**
- 2.4.1 Repasar cookies de sesión, tokens, y riesgos como session fixation / session hijacking
- 2.4.2 Repasar flags `HttpOnly`, `Secure`, `SameSite`
- 2.4.3 Nota de estudio + términos nuevos al glosario

**2.5 Protocolos de Verificación y Recuperación (OTP/TOTP)**
- 2.5.1 Repasar OTP (One-Time Password) y TOTP (Time-based OTP, RFC 6238)
- 2.5.2 Repasar flujo de recuperación de contraseña con token de un solo uso
- 2.5.3 Nota de estudio + términos nuevos al glosario

**2.6 Fundamentos de OWASP**
- 2.6.1 Repasar OWASP Top 10 (visión general)
- 2.6.2 Repasar qué es OWASP ASVS y su estructura por niveles (L1/L2/L3)
- 2.6.3 Nota de estudio + términos nuevos al glosario

**2.7 Cierre de Fase 0**
- 2.7.1 Consolidar todas las notas en `docs/fase0-notas-estudio.md`
- 2.7.2 Commit final de Fase 0
- 2.7.3 Entrada en Lessons Learned Log (parcial)

---

## 3.0 Fase 1 — Autenticación Básica *(detallado)*

**3.1 Configuración del entorno de desarrollo**
- 3.1.1 Setup del esqueleto de la app Flask
- 3.1.2 Diseño del esquema SQLite (tabla `users`)

**3.2 Registro de usuario**
- 3.2.1 Formulario de registro (Jinja2)
- 3.2.2 Validación de inputs (server-side)
- 3.2.3 Política de contraseñas (longitud mínima, complejidad)
- 3.2.4 Hashing de contraseña con bcrypt antes de guardar

**3.3 Login**
- 3.3.1 Formulario de login
- 3.3.2 Verificación de credenciales (bcrypt compare)
- 3.3.3 Mensajes de error genéricos (sin username enumeration)

**3.4 Gestión de sesión**
- 3.4.1 Creación de sesión tras login exitoso
- 3.4.2 Configuración de cookies `HttpOnly`, `Secure`, `SameSite`

**3.5 Logout**
- 3.5.1 Invalidación real de sesión (server-side)

**3.6 Cierre de Fase 1**
- 3.6.1 Pruebas manuales end-to-end
- 3.6.2 Commit final de Fase 1
- 3.6.3 Entrada en Lessons Learned Log (parcial)

---

## 4.0 Fase 2 — Endurecimiento OWASP *(detallado)*

**4.1 Protección contra fuerza bruta (rate limiting / bloqueo temporal)**
- 4.1.1 Definir la política: N intentos fallidos en una ventana de tiempo y duración del bloqueo temporal
- 4.1.2 Esquema para registrar intentos fallidos, contados por el nombre de usuario enviado (exista o no la cuenta)
- 4.1.3 Bloqueo temporal en `login()` con el mismo mensaje genérico de un login fallido (sin revelar si la cuenta existe o está bloqueada)
- 4.1.4 Reinicio del contador tras un login exitoso
- 4.1.5 Prueba: tras N fallos el login se bloquea y se libera al expirar el bloqueo

**4.2 Recuperación de contraseña (token de un solo uso con expiración)**
- 4.2.1 Esquema: tabla `password_reset_tokens` (hash del token, `user_id`, expiración, fecha de uso)
- 4.2.2 Formulario "Olvidé mi contraseña" con mensaje genérico, exista o no el email
- 4.2.3 Generación del token con `secrets.token_urlsafe`; en la BD se guarda solo su hash SHA-256
- 4.2.4 Entrega simulada del enlace (consola en desarrollo, sin servidor SMTP)
- 4.2.5 Formulario de nueva contraseña: valida el token (existe, no expirado, no usado), aplica la política de 3.2.3 y lo marca como usado
- 4.2.6 Tras el cambio: incrementar `session_version` (cierra las sesiones abiertas, R9) y reiniciar el contador de 4.1
- 4.2.7 Prueba: un token expirado y un token ya usado son rechazados

**4.3 Autenticación multifactor (MFA vía TOTP)**
- 4.3.1 Agregar dependencias `pyotp` y `qrcode` a `requirements.txt`
- 4.3.2 Esquema: columnas en `users` para el secreto TOTP, MFA activo y último código usado
- 4.3.3 Enrolamiento: generar el secreto, mostrar el QR de aprovisionamiento y activar MFA solo después de validar un primer código
- 4.3.4 Login en dos pasos: tras la contraseña, la sesión queda "pendiente de MFA" (sin `user_id`) y no da acceso a rutas protegidas
- 4.3.5 Verificación del código: tolerancia de ±1 periodo, rechazo de un código ya usado y límite de intentos (reutiliza 4.1)
- 4.3.6 Prueba con una app autenticadora estándar (Google Authenticator)

**4.4 Registro de auditoría (logging de eventos de seguridad)**
- 4.4.1 Catálogo de eventos: registro, login exitoso y fallido, bloqueo, logout, solicitud y uso de recuperación, cambio de contraseña, activación de MFA y código MFA fallido
- 4.4.2 Implementación con el módulo `logging` de Python: archivo en `instance/` con timestamp, evento, usuario e IP; agregar `*.log` a `.gitignore`
- 4.4.3 Nunca registrar secretos (contraseñas, tokens de recuperación, códigos TOTP, cookie de sesión) y neutralizar saltos de línea en los datos del usuario (*log injection*)
- 4.4.4 Prueba: cada evento del catálogo deja una línea con timestamp

**4.5 Revisión cruzada contra OWASP Top 10**
- 4.5.1 `SECRET_KEY` obligatoria: la app se niega a arrancar sin `.env` (se retira el valor por defecto)
- 4.5.2 Decorador `@login_required` que concentra la validación de `session_version`
- 4.5.3 Tokens CSRF en todos los formularios y `/logout` solo por POST
- 4.5.4 Reducir el riesgo residual de R9 (acortar la vida de la sesión o agregar expiración por inactividad)
- 4.5.5 Auditoría de dependencias con `pip-audit` (R6)
- 4.5.6 Recorrer las 10 categorías del OWASP Top 10 y documentar por cada una: si aplica, control implementado y gaps (`docs/fase2-owasp-top10.md`)

**4.6 Cierre de Fase 2**
- 4.6.1 Pruebas manuales end-to-end contra los criterios de aceptación de Fase 2 (Scope Statement, Sección 3)
- 4.6.2 Commit final de Fase 2
- 4.6.3 Entrada en Lessons Learned Log (parcial) y revisión del Risk Register
- 4.6.4 Suite de pruebas automatizadas (`pytest`) en `tests/`, una por paquete de trabajo *(adelantado a 4.1 — ver Registro de Cambios del Charter, cambio #3)*

*Orden de ejecución sugerido:* el WBS agrupa el trabajo por entregable, no fija el orden. Por dependencias conviene: **4.5.1 – 4.5.3** (base: los formularios y rutas nuevas nacen con CSRF y `@login_required`) → **4.4** (los paquetes siguientes ya emiten eventos) → **4.1** → **4.2** → **4.3** (la más compleja; reutiliza el contador de 4.1) → **4.5.4 – 4.5.6** → **4.6**. Un commit por paquete de trabajo.

---

## 5.0 Fase 3 — Stretch Goal: ASVS Level 1 *(detallado)*

> **Esta fase documenta, no corrige.** El criterio de aceptación del Scope Statement
> (Sección 3) pide un checklist con estatus *pass/fail* por cada control aplicable: un
> `fail` documentado con su evidencia **cumple**. Implementar las correcciones es trabajo
> de otra fase, y se propone como tal en 5.4.3. Es la respuesta directa a R1 (scope creep).

**5.1 Apertura de la fase**
- 5.1.1 Desglose de la sección 5.0 a nivel de paquete de trabajo (WBS v1.4)
- 5.1.2 Registro en el Charter de la versión de ASVS y del orden de ejecución (Sección 10, cambio #5)
- 5.1.3 Revisión del Risk Register al abrir la fase

**5.2 Threat model básico** *(va antes que la autoevaluación)*
- 5.2.1 Inventario de activos: qué se protege y de quién
- 5.2.2 Diagrama de flujo de datos con fronteras de confianza (navegador, Flask, SQLite, consola del mailer)
- 5.2.3 Identificación de amenazas por elemento del diagrama, con STRIDE
- 5.2.4 Mapeo de cada amenaza a los controles ya implementados y a los riesgos del registro (R4, R9 – R14)
- 5.2.5 Amenazas sin control identificado: alta en el Risk Register
- 5.2.6 Documento `docs/fase3-threat-model.md`

**5.3 Autoevaluación contra ASVS Level 1**
- 5.3.1 Obtener el CSV oficial de ASVS 5.0.0 y filtrar los requisitos de nivel 1
- 5.3.2 Triaje por capítulo: *aplica* / *no aplica a esta arquitectura* / *fuera del alcance del proyecto*, cada uno con su argumento
- 5.3.3 **Punto de decisión:** dimensionar el trabajo restante con el número real y acordar el nivel de detalle de 5.3.5
- 5.3.4 Tabla de controles implementados con su evidencia (archivo, o la prueba que lo sostiene), para no repetir la evidencia requisito por requisito
- 5.3.5 Recorrido de los capítulos que aplican, por bloques, con estatus por requisito *(se detalla tras 5.3.3)*
- 5.3.6 Documento `docs/fase3-asvs-l1.md`

**5.4 Consolidación de resultados**
- 5.4.1 Lista priorizada de gaps: los del threat model, los del ASVS y los cinco de 4.5.6
- 5.4.2 Alta en el Risk Register de los gaps que lo ameriten
- 5.4.3 Propuesta de alcance para una fase de remediación, o para el cierre del proyecto

**5.5 Cierre de Fase 3**
- 5.5.1 Entrada en Lessons Learned Log (parcial)
- 5.5.2 Revisión del Risk Register
- 5.5.3 Commit final de Fase 3 y etiqueta `fase-3`

---

## 6.0 Fase 4 — Remediación acotada *(detallado)*

> **Alcance cerrado a los siete gaps de Nivel 1** de `docs/fase3-consolidacion.md`. No se
> amplía sobre la marcha: los gaps de Nivel 2 y 3 quedan fuera, y si se quieren atender
> se decide por el Registro de Cambios como se decidió esta fase. Es R1 y R16 aplicados.
>
> **Criterio de terminado objetivo:** cada paquete cierra un requisito ASVS o una amenaza
> del threat model identificados en la Fase 3. No se da por hecho sin la prueba que lo
> sostenga — los dos controles sin prueba de C24 y C44 ya enseñaron la diferencia.

**6.1 Cabeceras de seguridad (G1)**
- 6.1.1 `after_request` con `Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options` y `Referrer-Policy`
- 6.1.2 Pruebas: cada cabecera presente en toda respuesta, incluidas las de error
- *Cierra:* V3.2.1, parte de TM-34 (por `Referrer-Policy`), gap A02

**6.2 Prefijo de la cookie de sesión (G2)**
- 6.2.1 Renombrar la cookie con el prefijo `__Host-`
- 6.2.2 Prueba sobre el `Set-Cookie` real, y revisar que la suite siga en verde
- *Cierra:* V3.3.1

**6.3 Revocación al reautenticar (G3)**
- 6.3.1 Incrementar `session_version` en `login()` y en `mfa_verify()`
- 6.3.2 Prueba: una cookie copiada antes de volver a autenticarse deja de servir
- 6.3.3 Mutación: quitar el incremento y confirmar que la prueba se pone en rojo
- *Cierra:* V7.2.4, la vía abierta de R9

**6.4 Manejo global de errores (G4)**
- 6.4.1 Manejadores de 404 y 500 que no filtren detalle interno
- 6.4.2 Evento de auditoría para el 500, sin volcar la excepción al log
- 6.4.3 Pruebas: provocar ambos y verificar respuesta y registro
- *Cierra:* TM-14, parte de TM-11, gap A10

**6.5 Rotación del registro de auditoría (G5)**
- 6.5.1 `RotatingFileHandler` con techo de tamaño y número de respaldos
- 6.5.2 Prueba: el archivo rota al superar el techo y no se pierden eventos
- *Cierra:* TM-28, parte de R18, gap A09

**6.6 Validación del nombre de usuario (G6)**
- 6.6.1 Definir la regla: lista blanca de caracteres, longitud mínima y máxima
- 6.6.2 Implementarla en `/register` y documentarla junto a la política de contraseñas
- 6.6.3 Pruebas: se rechazan los caracteres fuera de la lista y la longitud excedida
- *Cierra:* V2.1.1, V2.2.1, R20, LL20

**6.7 Plazos de remediación de dependencias (G7)**
- 6.7.1 Definir plazos basados en riesgo y registrarlos en el plan de respuesta de R6
- *Cierra:* V15.1.1, el hueco del propio plan de R6

**6.8 Cierre de Fase 4**
- 6.8.1 Re-ejecutar la autoevaluación ASVS sobre los requisitos afectados y actualizar `docs/fase3-asvs-l1.md`
- 6.8.2 Revisión del Risk Register (R9, R20 y los que cambien de estado)
- 6.8.3 Entrada en Lessons Learned Log (parcial)
- 6.8.4 Commit final de Fase 4 y etiqueta `fase-4`

---

## 7.0 Cierre del Proyecto

- 7.1 Lessons Learned Log final — **incluye la entrada pendiente del cierre de Fase 0 (tarea 2.7.3)**
- 7.2 Glosario bilingüe finalizado — **incluye los términos pendientes del tema 0.1, HTTP/HTTPS**
- 7.3 Retrospectiva general del proyecto

---

*Nota (Septiembre 2026): la sección 5.0 quedó desglosada al cerrar la Fase 2, como estaba previsto. El rolling wave se aplica ahora **dentro** de la fase: 5.3.5 no se detalla hasta que 5.3.1 y 5.3.2 den el número real de requisitos de nivel 1 aplicables, porque planear ese recorrido sobre una estimación sería planear contra un número inventado.*
