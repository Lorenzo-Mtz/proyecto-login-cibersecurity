# Project Charter / Acta de Constitución del Proyecto

**Proyecto:** Sistema de Login Seguro — Proyecto de Aprendizaje en Ciberseguridad
**Repositorio:** https://github.com/Lorenzo-Mtz/proyecto-login-cibersecurity
**Fecha de elaboración:** Agosto 2026
**Preparado por:** Lorenzo Mtz

---

## 1. Propósito y Justificación / Purpose & Justification

Este proyecto tiene un doble propósito de aprendizaje autodirigido:

1. **Ciberseguridad aplicada:** aprender los conceptos más importantes de ciberseguridad de forma práctica, construyendo un sistema de inicio de sesión (login) que implemente los mecanismos de seguridad estándar de la industria.
2. **Gestión de proyectos y Arquitectura Empresarial:** practicar la metodología PMI/PMBOK como forma de aprendizaje pasivo, generando los artefactos de planeación y documentación reales de un proyecto, en línea con los estudios de Ingeniería en Transformación Digital y Negocios del responsable.

Como criterio transversal, la documentación clave se produce en **español con terminología técnica introducida también en inglés**, dado que gran parte del trabajo profesional y de referencia técnica en ciberseguridad ocurre en inglés.

---

## 2. Objetivos del Proyecto / Project Objectives

| Objetivo | Descripción |
|---|---|
| O1 | Construir un sistema de login funcional con calidad de UX/UI de nivel comercial |
| O2 | Implementar los mecanismos de seguridad estándar de autenticación y gestión de sesión (OWASP Top 10 / ASVS Level 1 como referencia) |
| O3 | Documentar el proyecto completo bajo el marco de PMBOK, con artefactos reales (Charter, Scope Statement, WBS, Risk Register, Lessons Learned) |
| O4 | Generar un glosario bilingüe (ES/EN) de los términos técnicos aprendidos, actualizado de forma continua |

---

## 3. Criterios de Éxito / Success Criteria (Definition of Done)

El proyecto se considera exitoso cuando el sistema de login permite, de forma segura:

- Registro de usuario con validación de inputs y política de contraseñas
- Login con hashing seguro de contraseñas (bcrypt) y mensajes de error que no filtran información
- Logout con invalidación real de sesión
- Recuperación de contraseña mediante token de un solo uso con expiración
- Gestión de sesión segura (cookies `HttpOnly`, `Secure`, `SameSite`)
- Protección contra fuerza bruta (rate limiting / bloqueo temporal)
- Autenticación multifactor (MFA vía TOTP)
- Registro de auditoría (logging de eventos de seguridad)

Y cuando, de forma adicional, se documenta una autoevaluación del sistema contra el checklist de **OWASP ASVS Level 1**.

---

## 4. Alcance de Alto Nivel / High-Level Scope

**Incluido (in scope):**
- Aplicación web de login (backend Python/Flask, SQLite, plantillas Jinja2)
- Mecanismos de seguridad definidos en la sección 3, distribuidos en fases (ver Fase 1 y 2 en el WBS)
- Documentación PMBOK completa del proyecto
- Glosario bilingüe

**Excluido (out of scope) — para esta iteración:**
- Infraestructura de producción real (despliegue en la nube, balanceo de carga, alta disponibilidad)
- Detección de fraude basada en Machine Learning
- Base de datos productiva (PostgreSQL u otro motor) — se usa SQLite por simplicidad de aprendizaje
- Aplicación móvil nativa
- Cumplimiento formal de certificaciones (SOC 2, ISO 27001, etc.) — solo se usan sus estándares como referencia conceptual

---

## 5. Hitos de Alto Nivel / High-Level Milestones

Dado que es un proyecto de aprendizaje sin fecha límite fija, los hitos se organizan por **fases funcionales** (rolling wave planning) en vez de fechas exactas:

| Hito | Entregable |
|---|---|
| M0 | Entorno configurado: Git/GitHub, estructura de repo, Charter aprobado |
| M1 | Fase 0 completa: fundamentos teóricos repasados y documentados (HTTP/HTTPS, criptografía y hashing, AuthN/AuthZ, gestión de sesiones, TOTP/OTP, OWASP) |
| M2 | Fase 1 completa: autenticación básica robusta funcional |
| M3 | Fase 2 completa: endurecimiento (MFA, prevención OWASP Top 10, logging) |
| M4 | Fase 3 (stretch): checklist ASVS Level 1 documentado + threat model básico |
| M5 | Cierre del proyecto: Lessons Learned Log completo, glosario finalizado |

---

## 6. Riesgos de Alto Nivel / High-Level Risks

(Se detallan a fondo en el Risk Register — aquí solo los más relevantes a nivel charter)

- Alcance ambiguo ("calidad de mercado") puede generar scope creep si no se controla contra los criterios de la sección 3
- Al ser primer proyecto de seguridad práctica, riesgo de subestimar el tiempo de las fases de endurecimiento (Fase 2)
- Disponibilidad de tiempo variable (4-8 hrs/semana) puede alargar los tiempos entre hitos

---

## 7. Interesados / Stakeholders

| Rol | Persona |
|---|---|
| Patrocinador / Sponsor | Lorenzo Mtz (autoasignado, proyecto de aprendizaje individual) |
| Responsable del proyecto / Project Lead | Lorenzo Mtz |
| Equipo de ejecución / Execution team | Lorenzo Mtz + Claude (asistente de planeación y desarrollo) |
---

## 8. Supuestos y Restricciones / Assumptions & Constraints

**Supuestos (Assumptions):**
- El proyecto se desarrolla en un entorno de aprendizaje individual, no organizacional
- Se cuenta con acceso continuo a Git/GitHub y Python/Flask como stack

- Tiempo disponible: aproximadamente 4-8 horas por semana
- Sin presupuesto asignado — todas las herramientas usadas son gratuitas/open source
- Nivel de experiencia: principiante en desarrollo práctico, lo que puede afectar la velocidad de las fases iniciales

---

## 9. Aprobación / Approval
Al ser un proyecto individual de aprendizaje, este Charter se considera aprobado por el propio Sponsor/Project Lead al momento de iniciar la Fase 1.

**Aprobado por:** Lorenzo Mtz
**Fecha:** Agosto 2026

---

## 10. Registro de Cambios / Change Log


| # | Fecha | Descripción del cambio | Justificación |
|---|---|---|---|
| 1 | Agosto 2026 | Se añade **Fase 0 — Fundamentos Teóricos** antes de Fase 1: repaso de HTTP/HTTPS, criptografía y hashing, autenticación y autorización, gestión de sesiones, protocolos de verificación/recuperación (OTP/TOTP) y conceptos de OWASP. Se renumeran los hitos M1-M4 a M2-M5. | Antes de escribir código de seguridad conviene dominar los conceptos teóricos subyacentes; refuerza el propósito de aprendizaje del proyecto (Sección 1) |Los cambios al alcance base (Charter, Scope Statement, WBS) se registran aquí en vez de sobreescribirse sin dejar rastro, siguiendo el principio de **control de cambios (change control)** de PMBOK, adaptado a la escala de un proyecto individual.

**Restricciones (Constraints):**

