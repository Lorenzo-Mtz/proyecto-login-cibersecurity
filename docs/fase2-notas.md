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
| `login_blocked` | Login rechazado por el límite de intentos (agregado en 4.1) |

Los eventos de recuperación de contraseña (4.2) y MFA (4.3) se agregarán al catálogo cuando se implemente cada paquete.

`login_blocked` es un evento distinto de `login_failure` a propósito: es la señal de que una cuenta está bajo ataque (o de que un usuario legítimo quedó atorado). Mezclarlo con los fallos normales borraría esa señal en el log.

**Controles contra R14:**
- La firma `audit(event, user_id, username)` no acepta campos libres, así que no se le puede pasar una contraseña o un token por accidente.
- `json.dumps` escapa saltos de línea y comillas: un `username` malicioso no puede fabricar una segunda línea (*log injection*).
- El `username` se recorta a 64 caracteres.
- La IP sale de `request.remote_addr`, nunca del encabezado `X-Forwarded-For`, que lo escribe el cliente.

### 4.1 Protección contra fuerza bruta

**Política (WBS 4.1.1).** **5 intentos fallidos** contra el mismo nombre de usuario enviado dentro de una **ventana de 15 minutos** activan el bloqueo. El bloqueo no tiene duración propia: dura mientras sigan contando 5 o más fallos, es decir hasta 15 minutos desde el más antiguo. **Nunca es permanente** (R10). Los números viven en `src/config.py` (`LOGIN_MAX_ATTEMPTS`, `LOGIN_WINDOW_SECONDS`), no incrustados en `auth.py`, para que una prueba pueda acortar la ventana a segundos y ver expirar el bloqueo de verdad.

**Se cuenta por el nombre de usuario *enviado*, exista o no la cuenta.** Si sólo se contaran cuentas reales, el bloqueo sería un oráculo de existencia: `admin` se bloquearía y `xyz123` nunca. De ahí se deriva el diseño del esquema:

- Tabla propia `login_attempts` y no columnas en `users`, porque hay que registrar intentos contra usuarios que no existen.
- **Sin `FOREIGN KEY` a `users`**, por la misma razón. No es un olvido.
- Índice `(username, attempted_at)`, que es exactamente el patrón de la consulta. `EXPLAIN QUERY PLAN` confirma `SEARCH ... USING COVERING INDEX`.

**Implementación.** `src/throttle.py` con tres funciones (`is_blocked`, `record_failed_attempt`, `reset_attempts`). Módulo aparte y no dentro de `login()` porque 4.2.6 y 4.3.5 reutilizan el mismo contador. Reciben la conexión `db` como parámetro en vez de llamar a `get_db()`, para poder probarse con una conexión propia.

El tiempo lo pone **siempre SQLite** (`DEFAULT CURRENT_TIMESTAMP` al insertar, `datetime('now', ?)` al consultar), ambos en UTC. Mezclar un `datetime.now()` de Python (hora local, UTC−6) con el UTC de SQLite daría una ventana desfasada seis horas.

**Tres decisiones en `login()` que no son evidentes:**

| Decisión | Riesgo que cierra |
|---|---|
| El guard va **antes** de buscar en `users` y de validar la contraseña | Una contraseña correcta no vence al bloqueo, y no se gasta CPU en una decisión ya tomada |
| Se ejecuta `bcrypt.checkpw` contra `DUMMY_HASH` aunque el resultado se ignore | Sin él la respuesta bloqueada vuelve en ~2 ms y un fallo normal en ~340 ms: la **latencia** delata que la cuenta existe y está bajo ataque |
| El camino bloqueado **no registra el intento** | R10: un atacante no puede renovar indefinidamente el bloqueo de una víctima golpeando cada minuto |

**Verificación (WBS 4.1.5).** 13 pruebas sobre el flujo HTTP completo: el umbral en 5 y no en 6; la contraseña correcta rechazada durante el bloqueo; `MAX(id)` sin cambios tras tres intentos bloqueados; latencia 371 ms vs 340 ms (ratio 1.09); una cuenta inexistente bloqueada igual; liberación automática al vencer la ventana; y `login_blocked: 4` separado de `login_failure: 14` en el log.

**Riesgo residual.** Contar por usuario **no detecta *password spraying***: una contraseña común probada contra mil usuarios distintos nunca acumula fallos en ninguna cuenta. Mitigarlo requiere un límite por IP, fuera del alcance de 4.1.

---

## Deuda y pendientes de Fase 2

- [ ] 4.5.4: riesgo residual de R9 (sesión de 14 días sin expiración por inactividad).
- [ ] 4.5.5: `pip-audit` sobre las dependencias (R6).
- [ ] 4.5.6: recorrido documentado del OWASP Top 10.
- [ ] Sin pruebas automatizadas en el repo: la verificación de cada paquete se hizo con scripts temporales fuera del proyecto. Decidir en el cierre de fase si se incorpora `pytest`.
- [ ] Riesgo residual de R14: una contraseña escrita por error en el campo "Usuario" queda en el log.
- [ ] Riesgo residual de R10: no hay límite por IP, así que el *password spraying* pasa sin tocar ningún contador.
