# Enunciado del Alcance del Proyecto / Project Scope Statement

**Proyecto:** Sistema de Login Seguro — Proyecto de Aprendizaje en Ciberseguridad
**Basado en:** Project Charter (Agosto 2026)
**Fecha de elaboración:** Agosto 2026
**Preparado por:** Lorenzo Mtz

---

## 1. Descripción del Alcance del Producto / Product Scope Description

El producto es una aplicación web de inicio de sesión (login) construida en Python/Flask con SQLite y plantillas Jinja2, que implementa el ciclo de vida completo de autenticación (registro, login, logout, recuperación de contraseña, gestión de sesión) siguiendo los mecanismos de seguridad estándar de la industria, usando **OWASP ASVS Level 1** como marco de referencia objetivo para evaluar el nivel de cumplimiento alcanzado.

El desarrollo se organiza en cuatro fases bajo un enfoque de planeación gradual (**rolling wave planning**) — una fase inicial de fundamentos teóricos seguida de tres fases de construcción — y se documenta en paralelo bajo la metodología PMI/PMBOK.

---

## 2. Entregables del Proyecto / Project Deliverables

### 2.1 Entregables de producto (por fase)

**Fase 0 — Fundamentos teóricos:**
- Notas de estudio bilingües por tema, documentadas en `docs/fase0-notas-estudio.md`
- Ampliación del glosario con una nueva sección de conceptos de ciberseguridad
- Temas cubiertos: protocolo HTTP/HTTPS, criptografía y hashing, autenticación (AuthN) y autorización (AuthZ), gestión de sesiones, protocolos de verificación y recuperación (OTP/TOTP), fundamentos de OWASP (Top 10 y ASVS)

**Fase 1 — Autenticación básica:**
- Registro de usuario con validación de inputs y política de contraseñas
- Login con hashing seguro de contraseñas (bcrypt)
- Mensajes de error que no filtran información (no username enumeration)
- Gestión de sesión segura (cookies `HttpOnly`, `Secure`, `SameSite`)
- Logout con invalidación real de sesión

**Fase 2 — Endurecimiento OWASP (OWASP Hardening):**
- Protección contra fuerza bruta (rate limiting / bloqueo temporal)
- Recuperación de contraseña mediante token de un solo uso con expiración
- Autenticación multifactor (MFA vía TOTP)
- Registro de auditoría (logging de eventos de seguridad)

**Fase 3 — Stretch goal ASVS Level 1:**
- Checklist de autoevaluación contra OWASP ASVS Level 1
- Threat model básico del sistema

### 2.2 Entregables de gestión de proyecto (PM deliverables)

- Project Charter
- Scope Statement (este documento)
- Work Breakdown Structure (WBS)
- Risk Register
- Lessons Learned Log
- Glosario bilingüe (actualización continua)

---

## 3. Criterios de Aceptación / Acceptance Criteria

| Entregable | Criterio de aceptación (verificable) |
|---|---|
| Fase 0 (fundamentos teóricos) | Por cada tema existe una nota de estudio que explica el concepto con palabras propias, su relevancia para el proyecto, y aporta al menos un término nuevo al glosario bilingüe |
| Hashing de contraseñas | Las contraseñas nunca se almacenan en texto plano; verificable inspeccionando la base de datos SQLite |
| Gestión de sesión | Cookies de sesión muestran flags `HttpOnly`, `Secure`, `SameSite` en las herramientas de desarrollador del navegador |
| Rate limiting | Después de N intentos fallidos configurados, el sistema bloquea temporalmente el login |
| Recuperación de contraseña | El token expira después del tiempo definido y no puede reutilizarse una vez consumido |
| MFA | El código TOTP es validado correctamente contra una app autenticadora estándar (ej. Google Authenticator) |
| Logging de auditoría | Eventos de seguridad clave (login fallido, login exitoso, cambio de contraseña) quedan registrados con timestamp |
| ASVS Level 1 | Checklist documentado con estatus pass/fail por cada control aplicable de nivel 1 |

---

## 4. Exclusiones del Proyecto / Project Exclusions

- Infraestructura de producción real (despliegue en la nube, balanceo de carga, alta disponibilidad)
- Detección de fraude basada en Machine Learning
- Motor de base de datos productivo (PostgreSQL u otro) — se usa SQLite por simplicidad de aprendizaje
- Aplicación móvil nativa
- Certificación formal (SOC 2, ISO 27001, etc.) — solo se usan como referencia conceptual

---

## 5. Restricciones y Supuestos / Constraints & Assumptions

**Restricciones:**
- Tiempo disponible: ~4-8 horas por semana
- Sin presupuesto — solo herramientas gratuitas/open source
- Nivel de experiencia principiante en desarrollo práctico

**Supuestos:**
- Entorno de aprendizaje individual, no organizacional
- Acceso continuo a Git/GitHub y stack Python/Flask

---

## 6. Enfoque de Planeación / Planning Approach

Se usa **rolling wave planning**: la Fase 0 y la Fase 1 se desglosan a nivel de paquete de trabajo (*work package*) en el WBS, mientras que las Fases 2 y 3 permanecen a nivel de entregable general hasta que se cierre la fase anterior. El WBS se actualizará con más detalle conforme avance el proyecto. *(Septiembre 2026: la Fase 2 ya está desglosada en el WBS v1.2; la Fase 3 sigue a nivel de entregable.)*

> Nota: la incorporación de la Fase 0 (ver Charter, Sección 10 — Registro de Cambios) es un ejemplo práctico de cómo el rolling wave planning convive con el control de cambios: se ajusta el plan sin perder la trazabilidad de por qué cambió.
