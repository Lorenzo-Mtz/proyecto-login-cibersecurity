# Notas — Fase 1: Autenticación Básica

**Periodo:** 1 – 13 de septiembre de 2026
**Estado:** Cerrada (commit `11e2f13`)

---

## Resumen de lo realizado

### Stack
Flask 3.1 · SQLite · bcrypt 5.0 · email-validator 2.3 · python-dotenv · plantillas Jinja2.

### 3.1 Entorno y esquema
- App Flask con *application factory* (`src/app.py`) y blueprint de autenticación (`src/routes/auth.py`).
- Tabla `users`: `id`, `username` (único), `email` (único), `password_hash`, `created_at` y `session_version`.
- `SECRET_KEY` cargada desde `.env` (fuera del repo, ver `.env.example`).

### 3.2 Registro
- Validación en el servidor: campos obligatorios, formato de email con `email-validator` (normalizado a minúsculas).
- Política de contraseña: 12 a 64 caracteres y máximo 72 bytes, que es el límite real de bcrypt. Se sigue el criterio de NIST/ASVS de priorizar longitud sobre reglas de complejidad.
- Hash con bcrypt, *cost factor* 12. La contraseña nunca se guarda en texto plano.
- Consultas parametrizadas (`?`) contra inyección SQL.
- Si el usuario o email ya existe, el mensaje es genérico, para no confirmar qué cuentas existen.

### 3.3 Login
- Verificación con `bcrypt.checkpw`.
- Mismo mensaje de error ("Usuario o contraseña incorrectos") para usuario inexistente y contraseña incorrecta.
- Cuando el usuario no existe se compara contra un `DUMMY_HASH`, para que el tiempo de respuesta no revele si existe (mitiga la enumeración por *timing*).

### 3.4 Sesión
- `session.clear()` antes de crear la sesión nueva (mitiga *session fixation*).
- Cookie con `HttpOnly` (default de Flask), `Secure` y `SameSite=Strict`.
- Sesión permanente de 14 días (`PERMANENT_SESSION_LIFETIME` + `session.permanent = True`).

### 3.5 Logout e invalidación server-side
- **Problema detectado (R9):** Flask guarda la sesión en una cookie firmada del lado del cliente, así que `session.clear()` no invalida una cookie que alguien ya copió.
- **Solución:** columna `session_version`.
  - El login guarda la versión en la sesión.
  - `/dashboard` la compara contra la BD en cada request.
  - El logout la incrementa. Toda cookie emitida antes deja de ser válida.
- El dashboard saluda al usuario ("Hola, {usuario}"); Jinja2 escapa el nombre automáticamente, lo que evita XSS.

### 3.6 Cierre
- **Prueba manual end-to-end aprobada:** validaciones de registro, login con mensaje genérico, flags y expiración de la cookie, logout, y rechazo de una cookie copiada antes del logout.
- Lessons Learned LL4 – LL7 y riesgo R9 (mitigado) documentados.

---

## Decisiones de diseño

| Decisión | Alternativa descartada | Motivo |
|---|---|---|
| `session_version` en BD | Flask-Session / aceptar el riesgo | Cumple WBS 3.5.1 sin dependencias nuevas y se reusa en Fase 2 (cambio de contraseña) |
| `SameSite=Strict` | `Lax` | La app no necesita recibir la cookie en navegación desde otros sitios; mitiga CSRF de forma más estricta |
| Longitud mínima de 12, sin reglas de complejidad | Mayúsculas/números/símbolos obligatorios | Recomendación NIST SP 800-63B / ASVS: la longitud aporta más que la complejidad forzada |

---

## Deuda técnica para Fase 2 (revisión OWASP, WBS 4.5)

- [x] Formularios sin token CSRF (mitigado parcialmente por `SameSite=Strict`). *(Resuelto en WBS 4.5.3 con `CSRFProtect` de Flask-WTF.)*
- [x] `/logout` acepta GET: un enlace externo podría cerrar la sesión del usuario. *(Resuelto en WBS 4.5.3: solo POST con token CSRF.)*
- [x] `SECRET_KEY` tiene un valor por defecto si falta `.env`; la app debería negarse a arrancar sin él. *(Resuelto en WBS 4.5.1; ver LL8.)*
- [x] La validación de sesión vive dentro de `dashboard()`; con más rutas protegidas conviene un decorador `@login_required`. *(Resuelto en WBS 4.5.2; además, el logout ya no permite que una cookie invalidada cierre las sesiones vigentes.)*
- [ ] Riesgo residual de R9: una cookie robada sigue válida hasta 14 días si el usuario nunca hace logout.
- [ ] Sin límite de intentos de login (WBS 4.1).
