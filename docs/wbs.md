# Estructura de Desglose del Trabajo / Work Breakdown Structure (WBS)

**Proyecto:** Sistema de Login Seguro — Proyecto de Aprendizaje en Ciberseguridad
**Enfoque:** Rolling Wave Planning — Fases 0, 1 y 2 desglosadas a nivel de paquete de trabajo (*work package*); Fase 3 a nivel de entregable, pendiente de desglose detallado.
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

## 5.0 Fase 3 — Stretch Goal: ASVS Level 1 *(alto nivel)*

- 5.1 Autoevaluación contra checklist OWASP ASVS Level 1
- 5.2 Threat model básico del sistema
- 5.3 Documentación de resultados y gaps identificados

---

## 6.0 Cierre del Proyecto

- 6.1 Lessons Learned Log final
- 6.2 Glosario bilingüe finalizado
- 6.3 Retrospectiva general del proyecto

---

*Nota: Los paquetes de trabajo de la sección 5.0 se desglosarán con el mismo nivel de detalle que las secciones 2.0 a 4.0 cuando se cierre la Fase 2, siguiendo el enfoque de rolling wave planning.*
