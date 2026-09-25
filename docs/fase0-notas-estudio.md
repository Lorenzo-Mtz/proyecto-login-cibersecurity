# Notas de Estudio — Fase 0: Fundamentos Teóricos

Plantilla de trabajo para la Fase 0. La idea es llenarla conforme estudias cada tema — las respuestas son tuyas, no pre-llenadas, para que el repaso realmente sirva. Cuando termines un tema, añade los términos nuevos a `docs/glossary.md` (nueva sección "Conceptos de Ciberseguridad").

Guía de preguntas por tema (repetir el formato en cada uno):
- **¿Qué es?** (definición en tus propias palabras)
- **¿Por qué es relevante para este proyecto?** (conexión directa con el login seguro)
- **Términos clave (ES/EN)** a agregar al glosario
- **Fuentes consultadas**

---

## 0.1 Protocolo HTTP / HTTPS

- ¿Qué es?
- ¿Por qué es relevante para este proyecto?
- Términos clave (ES/EN):
- Fuentes consultadas:

---

## 0.2 Criptografía y Hashing

- ¿Qué es? (diferencia entre hashing y cifrado/encryption)
- ¿Por qué es relevante para este proyecto? (¿por qué bcrypt y no solo SHA-256, por ejemplo?)
- Términos clave (ES/EN):
- Fuentes consultadas:

---

## 0.3 Autenticación y Autorización (AuthN / AuthZ)

- ¿Qué es? (diferencia entre autenticación y autorización)
- ¿Por qué es relevante para este proyecto?
- Términos clave (ES/EN):
- Fuentes consultadas:

---

## 0.4 Gestión de Sesiones

- ¿Qué es? (cookies de sesión, tokens, riesgos como session hijacking/fixation)
- ¿Por qué es relevante para este proyecto? (conexión con flags `HttpOnly`/`Secure`/`SameSite` del Charter)
- Términos clave (ES/EN):
- Fuentes consultadas:

---

## 0.5 Protocolos de Verificación y Recuperación (OTP / TOTP)

- ¿Qué es? (OTP vs TOTP, RFC 6238)
- ¿Por qué es relevante para este proyecto? (conexión con MFA de Fase 2 y recuperación de contraseña)
- Términos clave (ES/EN):
- Fuentes consultadas:

---

## 0.6 Fundamentos de OWASP

- ¿Qué es? (OWASP Top 10, y qué es OWASP ASVS y sus niveles L1/L2/L3)
- ¿Por qué es relevante para este proyecto? (conexión con el criterio de éxito del Charter)
- Términos clave (ES/EN):
- Fuentes consultadas:

---

## Resumen de cierre de Fase 0

- Temas cubiertos:
- Principales aprendizajes:
- Dudas pendientes o temas a revisar más adelante:

---

## Anexo — Resumen de lo realizado en Fase 0

**Periodo:** 18 de agosto – 3 de septiembre de 2026

### Gestión del proyecto (WBS 1.0)
- Artefactos PMBOK *tailored*: Project Charter, Scope Statement, WBS (v1.1, con la Fase 0 agregada vía Registro de Cambios del Charter), Risk Register (R1–R8 y O1) y Lessons Learned Log (LL1–LL3).
- Glosario bilingüe iniciado con conceptos de Git, Bash y PMBOK.

### Estudio teórico (WBS 2.1 – 2.6)
El aprendizaje se documentó directamente en `docs/glossary.md`, sección 4, en lugar de esta plantilla:

| Tema | Resultado |
|---|---|
| 0.1 HTTP / HTTPS | **Glosario 4.1** (agregado en el cierre del proyecto, WBS 7.2): HTTP y HTTPS, TLS, sin estado, métodos y códigos de estado, cabeceras, *query string* frente a cuerpo, origen, contexto seguro, intermediario, HSTS, certificados y CA |
| 0.2 Criptografía y Hashing | Glosario 4.2: hash vs cifrado, salt, work factor, bcrypt, rainbow tables, fuerza bruta |
| 0.3 AuthN / AuthZ | Glosario 4.3: autenticación vs autorización, RBAC, IDOR, username enumeration, mínimo privilegio |
| 0.4 Gestión de Sesiones | Glosario 4.4: cookies y tokens de sesión, hijacking, fixation, flags `HttpOnly`/`Secure`/`SameSite`, expiración, invalidación |
| 0.5 OTP / TOTP | Glosario 4.5: OTP, HOTP, TOTP (RFC 6238), MFA, secreto compartido, QR de aprovisionamiento |
| 0.6 OWASP | Glosario 4.6: Top 10, ASVS y sus niveles L1/L2/L3, inyección, broken access control, fallas criptográficas |

### Laboratorios prácticos (`docs/fase0-lab-hashing/`)
- **`md5_lab.py`** — MD5 implementado desde cero (padding little-endian, funciones F/G/H/I, tabla K derivada de `sin`), verificado contra `hashlib.md5`.
- **`sha256_lab.py`** — SHA-256 desde cero (padding big-endian, tabla K generada a partir de raíces cúbicas de los primeros 64 primos, message schedule de 64 words, compresión de 64 rondas), verificado contra `hashlib.sha256`, incluyendo entradas de más de un bloque.
- **`prueba.py`** — experimentos previos de conversión de texto a bits y codificación de la longitud.

**Aprendizaje clave:** MD5 y SHA-256 son rápidos por diseño, y eso es justo lo que los hace inadecuados para contraseñas. Por eso el proyecto usa bcrypt, que es lento a propósito y trae el salt incorporado.

### Pendientes de cierre de Fase 0 (WBS 2.7) — **cerrados**

Los tres quedaron abiertos al cerrar la Fase 0 en agosto de 2026 y se saldaron en el cierre del proyecto, más de un mes después. Que tardaran tanto es en sí mismo la lección de **LL31**.

- [x] ~~Tema 0.1 HTTP/HTTPS: notas y términos al glosario.~~ Resuelto en **WBS 7.2**: sección 4.1 del glosario, con 14 términos. El aprendizaje se documentó ahí y no en esta plantilla, igual que en los otros cinco temas.
- [x] ~~2.7.3 Entrada de Lessons Learned de Fase 0.~~ Resuelta en **WBS 7.1**: entrada **LL31**.
- [x] ~~Quitar la línea duplicada de "Última actualización" al final del glosario.~~ Ya estaba resuelto cuando se revisó; esta lista llevaba tiempo diciendo lo contrario.
