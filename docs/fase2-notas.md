# Notas — Fase 2: Endurecimiento OWASP

**Periodo:** desde el 14 de septiembre de 2026
**Estado:** en curso
**Plan:** WBS v1.2, paquetes 4.1 – 4.6 (ver `docs/wbs.md`)

> Documento vivo: se actualiza al cerrar cada paquete de trabajo. El orden de
> ejecución no sigue la numeración, sino las dependencias acordadas en el WBS:
> 4.5.1 – 4.5.3 → 4.4 → 4.1 → 4.2 → 4.3 → 4.5.4 – 4.5.6 → 4.6.

---

## Paquetes cerrados

### 4.5.1 `SECRET_KEY` obligatoria (commit `3efa2e4`)

- `create_app()` se niega a arrancar si la clave falta, si es el valor de ejemplo de `.env.example` o si tiene menos de 32 caracteres.
- **Hallazgo:** durante toda la Fase 1 las cookies se firmaron con el valor por defecto, porque `app.py` importaba `Config` antes de llamar a `load_dotenv()` (ver LL8). El `.env` real se creó en este paquete.

### 4.5.2 Decorador `@login_required` (commit `faadb59`)

- `src/routes/decorators.py`: centraliza la validación de sesión (`user_id` + `session_version` contra la BD) y deja la fila del usuario en `g.user`.
- El logout ahora solo incrementa `session_version` si la cookie trae la versión vigente (`WHERE id = ? AND session_version = ?`), de modo que una cookie ya invalidada no puede cerrar las sesiones activas del usuario.
- **Detalle de seguridad:** el orden de los decoradores importa. Con `@login_required` arriba de `@route`, la ruta queda abierta sin ningún error visible.

### 4.5.3 Tokens CSRF y logout por POST (commit `7e2556b`)

- `CSRFProtect` de Flask-WTF protege todos los POST; los formularios llevan el campo `csrf_token`.
- `/logout` acepta solo POST, y en el dashboard el enlace se reemplazó por un formulario.
- Un token ausente, alterado o de otra sesión se maneja con un mensaje flash y una redirección a una ruta fija (no al `Referer`, para no abrir una *open redirect*).
- `SameSite=Strict` no bastaba: no cubre *login CSRF* ni los subdominios del mismo sitio.

### 4.4 Registro de auditoría

- `src/audit.py`: módulo `logging` de Python escribiendo **una línea JSON por evento** en `instance/audit.log` (ignorado por git vía `*.log`).
- Campos por evento: `ts` (UTC), `event`, `user_id`, `username`, `ip` y `path`.

**Catálogo de eventos (WBS 4.4.1).** Un evento fuera del catálogo lanza `ValueError`:

| Evento | Cuándo se registra |
|---|---|
| `register_success` | Cuenta creada |
| `register_failure` | Registro rechazado porque el usuario o el email ya existen |
| `login_success` | Login correcto |
| `login_failure` | Credenciales incorrectas, usuario inexistente o contraseña de más de 72 bytes |
| `logout` | Cierre de sesión con una cookie vigente |
| `session_rejected` | Cookie con `session_version` vieja o de un usuario inexistente (posible cookie robada) |
| `csrf_failure` | POST con token CSRF ausente o inválido |

Los eventos de bloqueo (4.1), recuperación de contraseña (4.2) y MFA (4.3) se agregarán al catálogo cuando se implemente cada paquete.

**Controles contra R14:**
- La firma `audit(event, user_id, username)` no acepta campos libres, así que no se le puede pasar una contraseña o un token por accidente.
- `json.dumps` escapa saltos de línea y comillas: un `username` malicioso no puede fabricar una segunda línea (*log injection*).
- El `username` se recorta a 64 caracteres.
- La IP sale de `request.remote_addr`, nunca del encabezado `X-Forwarded-For`, que lo escribe el cliente.

---

## Deuda y pendientes de Fase 2

- [ ] 4.5.4: riesgo residual de R9 (sesión de 14 días sin expiración por inactividad).
- [ ] 4.5.5: `pip-audit` sobre las dependencias (R6).
- [ ] 4.5.6: recorrido documentado del OWASP Top 10.
- [ ] Sin pruebas automatizadas en el repo: la verificación de cada paquete se hizo con scripts temporales fuera del proyecto. Decidir en el cierre de fase si se incorpora `pytest`.
- [ ] Riesgo residual de R14: una contraseña escrita por error en el campo "Usuario" queda en el log.
