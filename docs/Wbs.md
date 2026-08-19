# Estructura de Desglose del Trabajo / Work Breakdown Structure (WBS)

x**Proyecto:** Sistema de Login Seguro — Proyecto de Aprendizaje en Ciberseguridad
**Enfoque:** Rolling Wave Planning — Fase 0 y Fase 1 desglosadas a nivel de paquete de trabajo (*work package*); Fases 2 y 3 a nivel de entregable, pendientes de desglose detallado.
**v1.1** — actualizado para incorporar la Fase 0 (ver Charter, Sección 10 — Registro de Cambios)

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

## 4.0 Fase 2 — Endurecimiento OWASP *(alto nivel, pendiente de desglose)*

- 4.1 Protección contra fuerza bruta (rate limiting / bloqueo temporal)
- 4.2 Recuperación de contraseña (token de un solo uso con expiración)
- 4.3 Autenticación multifactor (MFA vía TOTP)
- 4.4 Registro de auditoría (logging de eventos de seguridad)
- 4.5 Revisión cruzada contra OWASP Top 10

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

*Nota: Los paquetes de trabajo de las secciones 4.0 y 5.0 se desglosarán con el mismo nivel de detalle que las secciones 2.0 y 3.0 cuando se cierre la fase anterior, siguiendo el enfoque de rolling wave planning.*
