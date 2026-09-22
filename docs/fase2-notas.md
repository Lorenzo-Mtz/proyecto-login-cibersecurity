# Notas — Fase 2: Endurecimiento OWASP

**Periodo:** desde el 14 de septiembre de 2026
**Estado:** completa — cerrada el 22 de septiembre de 2026 (WBS 4.6)
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
| `password_reset_requested` | Solicitud de recuperación de contraseña (agregado en 4.2) |
| `password_reset_failure` | Token de recuperación inválido, expirado o ya usado (agregado en 4.2) |
| `password_reset_success` | Contraseña cambiada por recuperación (agregado en 4.2) |
| `mfa_activated` | Segundo factor activado tras validar el primer código (agregado en 4.3) |
| `mfa_required` | Contraseña correcta; sesión pendiente del segundo factor (agregado en 4.3) |
| `mfa_failure` | Código TOTP incorrecto, reutilizado o fuera de la ventana (agregado en 4.3) |

El catálogo quedó en **14 eventos**. `mfa_required` no estaba previsto en el WBS 4.4.1 y se agregó al implementar 4.3: es la señal de que **alguien ya tiene la contraseña** de una cuenta y solo le falta el segundo factor. Una ráfaga de estos *sin* un `login_success` detrás es justo el ataque que MFA está deteniendo; sin el evento, ese ataque no deja huella.

El éxito del segundo factor se registra como **`login_success`**, el mismo evento que el camino sin MFA, no como uno propio. En los dos significa exactamente lo mismo —se creó una sesión— y separarlos obligaría a sumar dos claves distintas para contar cuántas veces entró alguien.

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

### 4.2 Recuperación de contraseña

El flujo son tres rutas y dos módulos nuevos:

| Ruta | Método | Qué hace |
|---|---|---|
| `/forgot-password` | GET, POST | Normaliza el email igual que `register()`. Si el usuario existe, emite un token y lo entrega; si no, no hace nada. El `flash` y el `redirect` están **fuera** del `if`, así que la respuesta es la misma en los dos casos |
| `/reset-password/<token>` | GET | Solo pinta el formulario con el token en un campo oculto. No consulta la BD y **no audita nada** |
| `/reset-password` | POST | Valida el token, aplica la política de contraseñas y hace el cambio completo en un solo commit |

`src/reset_tokens.py` (`issue_token`, `find_valid_token`) y `src/mailer.py` (`send_password_reset`) van aparte de `auth.py` por la misma razón que `throttle.py`: reciben la conexión `db` o cadenas ya armadas, así que se pueden probar solos.

**El token (WBS 4.2.3).** `secrets.token_urlsafe(32)` — 256 bits de un CSPRNG, no de `random`. En la BD se guarda **solo su SHA-256**: quien lea `app.db` (un backup filtrado, una inyección SQL, un disco robado) encuentra hashes, no enlaces utilizables. El token en claro solo existe en memoria y en la consola.

**SHA-256 y no bcrypt, a propósito.** Parece un paso atrás frente a las contraseñas, pero es la decisión correcta: bcrypt es lento para encarecer el diccionario contra un secreto de **baja entropía**. Un token de 256 bits aleatorios no tiene diccionario que probar, así que la lentitud no compraría nada y sí costaría ~330 ms por validación.

**La expiración la calcula SQLite, nunca Python.** `created_at` lo pone `CURRENT_TIMESTAMP` (UTC, `YYYY-MM-DD HH:MM:SS`) y `expires_at` sale de `datetime('now', ?)`. Mezclar el reloj de Python (hora local, UTC−6) con el de SQLite dejaría las dos columnas de tiempo en formatos distintos y comparaciones que fallan en los bordes — el mismo error que se evitó en 4.1.

**Un token nuevo invalida los anteriores** del mismo usuario (`DELETE ... WHERE user_id = ?`): no hay varias credenciales vivas a la vez. La traza de que existieron queda en el log de auditoría, no en la tabla.

**Esta tabla sí lleva `FOREIGN KEY` a `users`**, al revés que `login_attempts`. Allá se cuentan intentos contra cuentas inexistentes (si no, el bloqueo revelaría cuáles existen); aquí un token solo tiene sentido para un usuario real. Hizo falta agregar `PRAGMA foreign_keys = ON` por conexión en `database.py`: **SQLite trae la verificación apagada por default**, y sin ella la restricción es decorativa (verificado: sin el pragma se inserta un token con un `user_id` que no existe).

**Dos rutas y no una, por el log.** `audit()` guarda `request.path`, y en el GET el token viaja justo ahí. Si el formulario y el envío compartieran ruta, cualquier evento escrito en esa vista dejaría el token en claro en `audit.log` — exactamente el secreto que 4.4.3 prohíbe registrar. Por eso el GET no audita nada y el POST recibe el token en el cuerpo.

**El enlace nunca sale por la respuesta HTTP**: ni por `flash`, ni por la plantilla, ni por `audit()`. Solo por consola, y con `print` y no con `current_app.logger`, porque el logger es un sistema de handlers que alguien puede reconfigurar hacia un archivo. `mailer.py` es el punto de costura: el día que haya SMTP real se reemplaza el cuerpo de esa función y ningún otro archivo cambia.

**Tres motivos de rechazo, una sola salida.** Inexistente, expirado y ya usado caen los tres en el mismo `if reset is None`, con el mismo mensaje y el mismo destino. Distinguirlos convertiría el formulario en un verificador de qué enlaces se emitieron.

**El cambio es una sola transacción (WBS 4.2.6).** La contraseña y `session_version + 1` van en la **misma sentencia**: cambiar la credencial e invalidar las sesiones abiertas son una sola decisión, y juntas no puede ocurrir una sin la otra. Quien recupera su cuenta suele hacerlo porque alguien más tiene la cookie. A diferencia de `logout()`, aquí no se exige `AND session_version = ?`: quien probó control del correo puede invalidar todo sin presentar ninguna cookie. Después se marca `used_at` y se llama a `reset_attempts`, con un solo `commit` al final: si la contraseña cambiara y el token quedara sin marcar, el enlace del correo seguiría abriendo la cuenta.

**Verificación (WBS 4.2.7).** 14 pruebas en `tests/test_password_reset.py`, sobre el flujo HTTP completo. Cada control se verificó además **rompiéndolo a propósito** y confirmando que la prueba correspondiente se pone en rojo (diez mutaciones: quitar el marcado de `used_at`, marcar la fila por `user_id`, quitar el `WHERE user_id` del `DELETE`, quitar `session_version + 1`, quitar `reset_attempts`, quitar la comparación de `expires_at`, quitar el filtro `used_at IS NULL`, hacer que el email inexistente responda distinto, auditar en el GET y guardar el token en claro). Una prueba que nunca se ha visto fallar no prueba nada: la primera versión de `test_se_marca_la_fila_del_token_usado_y_no_otra` pasaba con el bug puesto, porque los ids volvían a coincidir (ver LL14).

**Riesgos residuales.**
- **`/forgot-password` no tiene límite de tasa.** Como un token nuevo invalida los anteriores, alguien que conozca un email puede pedir tokens en serie y mantener invalidado el que la víctima está por usar: un DoS de recuperación. Con SMTP real sería además un vector de envío masivo desde el dominio del proyecto.
- **El token viaja en la URL**, así que queda en el historial del navegador y podría filtrarse por el encabezado `Referer` si la página cargara un recurso externo. Está mitigado solo del lado del log (el POST no lleva el token en el path). La alternativa —pedirlo en un formulario aparte— se descartó por ser el flujo que ningún usuario real sigue desde un correo.

### 4.3 Segundo factor por TOTP

**El encuadre.** `pyotp` implementa el RFC 6238 y eso está resuelto (R4 lo pide explícitamente: no programar el algoritmo a mano). **Todo lo que puede salir mal en un MFA está alrededor del algoritmo, no dentro**, y eso es lo que vive en `src/mfa.py`.

TOTP en una frase: el servidor y el teléfono comparten un secreto, los dos calculan `HMAC(secreto, tiempo/30)` y truncan a 6 dígitos. **No hay red entre el teléfono y el servidor** — por eso funciona en modo avión. De esa única frase caen los cuatro problemas del paquete:

| De la frase | Sale el problema |
|---|---|
| El servidor necesita **el secreto** para calcular el código | No se puede hashear como una contraseña: se guarda recuperable (**R12**) |
| Los dos dependen de **su propio reloj** | Hace falta una ventana de tolerancia |
| Un código vive **30 segundos** | Hay que rechazar la reutilización |
| Son **6 dígitos** | 10⁶ combinaciones: hace falta límite de intentos |

**Dependencias (4.3.1).** `pyotp` por R4. `qrcode` con su factory **SVG**, no PNG: el PNG exige **Pillow**, una librería de procesamiento de imágenes completa (decodificadores de JPEG, TIFF, WebP y más, buena parte en C) para dibujar cuadritos negros en una retícula. Una dependencia no se paga una vez, se paga siempre: aparecería en cada revisión de **R6** y en cada corrida de `pip-audit` de 4.5.5. Nota: `qrcode` arrastra `colorama` en cualquier caso.

**Esquema (4.3.2).** Tres columnas en `users`:

| Columna | Por qué |
|---|---|
| `totp_secret` | En claro. En 4.2 el servidor solo **comparaba** (hasheaba el token recibido y veía si coincidía), así que bastaba el hash. Aquí tiene que **recalcular** un HMAC, y no se puede calcular un HMAC con el hash de la llave. Es **R12**, aceptado |
| `mfa_enabled` | Columna propia y no `totp_secret IS NOT NULL`, porque el enrolamiento tiene **tres** estados: sin secreto → con secreto sin confirmar → confirmado. Inferir el estado de un `NULL` colapsa los dos últimos, y el que se pierde es el intermedio: quien abre el QR y cierra la pestaña quedaría marcado como protegido y el siguiente login le pediría un código que no puede generar. `DEFAULT 0` por lo mismo: una cuenta que ya existía nace fuera de MFA |
| `last_mfa_timecode` | El **número de periodo** del último código aceptado, **no el código** |

**Guardar el periodo y no el código** es la decisión central, y gana por dos razones a la vez:

- **Sensibilidad.** El periodo no es secreto: es el reloj dividido entre 30. Un código en cambio es una credencial viva hasta 90 segundos por la ventana, y acabaría guardada en la misma tabla que el secreto — justo lo que 4.4.3 prohíbe registrar en cualquier otro lado. Hashearlo no ayudaría: seis dígitos son un millón de posibilidades y el hash se revierte al instante. **Hashear solo protege lo que ya tiene entropía**, que es la lección de 4.2 vista al revés.
- **Protección.** Exigir que el periodo nuevo sea **estrictamente mayor** que el guardado rechaza el código repetido **y además invalida los anteriores de la ventana**. Guardar el código solo tapa lo primero: el del periodo anterior seguiría sirviendo, y quien lo vio por encima del hombro entraría.

`CREATE TABLE IF NOT EXISTS` no agrega columnas a una tabla existente (**LL4**, ya pasó con `session_version`). Se resolvió recreando la base de desarrollo, que es una de las dos salidas que LL4 prescribe. Es válido porque los datos eran desechables; **el día que haya datos que importen, la respuesta tiene que ser una migración** — está aplazado, no resuelto.

**Enrolamiento (4.3.3).** `GET /mfa/setup` genera el secreto, lo guarda con `mfa_enabled = 0` y muestra el QR; el `POST` valida un primer código y **solo entonces** activa MFA. Tres detalles:

- **El secreto va a la BD, no a la sesión.** La cookie de Flask va **firmada, no cifrada**: la firma impide *modificarla*, no *leerla*. Guardar ahí el secreto mientras no está confirmado —que es la opción cómoda— publicaría el segundo factor completo.
- **El secreto pendiente se reutiliza entre recargas.** Si cambiara en cada `GET`, el QR recién escaneado dejaría de coincidir con el teléfono.
- **El código que confirma el enrolamiento queda consumido.** Es un código válido que acaba de usarse; sin registrar su periodo, serviría otra vez para el primer login treinta segundos después.

**El QR va embebido como `data:` URI**, no servido desde una ruta propia. Una ruta `/mfa/qr.svg` sería una URL que entrega el secreto compartido: necesitaría su propio control de acceso, y bastaría olvidarlo una vez. Va en base64 dentro del atributo `src` en vez de inyectarse con `|safe`: marcar contenido como seguro es un hábito que no conviene normalizar.

**MFA es opcional y se enrola desde el dashboard**, no obligatorio durante el registro. Obligatorio sería más seguro, y aun así se descartó: con **R13** aceptado (sin códigos de respaldo, recuperación manual en la BD), hacerlo obligatorio dejaría **cada cuenta nueva** a un teléfono perdido de distancia de necesitar SQLite. Además habría sido un cambio de alcance —el WBS no lo pide— y habría obligado a tocar `register()`, un flujo cerrado y con pruebas encima (**LL12**). Enrolar después del login además hereda `@login_required`: cero código de autorización nuevo.

**Login en dos pasos (4.3.4).** Con MFA activo la contraseña correcta **no abre sesión**: deja una sesión *pendiente* con `pending_mfa_user_id` y **sin `user_id`**. Como `@login_required` solo mira `user_id`, el guard que ya existía rechaza esa sesión sin una línea nueva.

Esa decisión se verificó por el lado equivocado primero, y vale la pena: con `user_id` en la sesión pendiente **y** `session_version`, `/dashboard` responde **200** y MFA queda saltado por completo. Con `user_id` solo, el decorador rechaza — pero por la validación de R9, no por MFA, y escribe un `session_rejected` que en el catálogo significa *"posible cookie robada"*. Cada login legítimo fabricaría una alerta falsa.

La sesión pendiente va en la cookie y no en la BD: es estado de **esta conversación con este navegador**, no de la cuenta. Una fila en la BD no distingue dos navegadores del mismo usuario, y haría falta algo en la cookie de todos modos para ligar la petición a la fila. La regla que queda: **la BD guarda el estado de la cuenta, la cookie el de la conversación.**

Esa cookie **caduca a los 5 minutos** (`MFA_PENDING_LIFETIME_SECONDS`). No basta con omitir `session.permanent`: mucha gente no cierra nunca el navegador. El cliente no puede retrasar la marca de tiempo porque la cookie va firmada — el mismo hecho que la descartaba para el secreto la hace válida para esto.

**La decisión menos evidente:** con MFA, la contraseña correcta **no reinicia el contador de 4.1**. Si lo reiniciara, quien tenga la contraseña probaría códigos de cinco en cinco volviendo a loguearse entre tandas, y el límite del segundo factor sería decorativo. `reset_attempts` se movió a `mfa_verify()`, al punto en que el usuario demostró **las dos** cosas.

**Verificación del código (4.3.5).** `verificar_codigo()` devuelve el **número de periodo aceptado**, no un booleano: con un `bool`, quien llama no tendría qué guardar y el control de reutilización no podría existir. `pyotp.verify()` no alcanza por eso mismo.

| Control | Riesgo que cierra |
|---|---|
| Tolerancia de **exactamente ±1 periodo** | Absorbe el reloj desfasado del teléfono. Cada periodo extra **triplica** los códigos válidos en un instante |
| Periodo nuevo **>** periodo guardado | Reutilización, y códigos vistos por encima del hombro |
| `hmac.compare_digest` y no `==` | `==` corta en el primer carácter distinto: el tiempo de respuesta diría cuántos dígitos se acertaron, y adivinar seis dígitos pasaría de un millón de intentos a sesenta |
| Filtro de formato **antes** de comparar | `compare_digest` lanza `TypeError` con lo que no sea ASCII → 500 → oráculo (**LL15**). `isdigit()` no basta: es `True` para los dígitos arábigo-índicos (`١٢٣`), que no son ASCII |
| Límite de intentos reutilizando `throttle.py` | 10⁶ combinaciones son un millón de intentos gratis por periodo |

El descarte por periodo va **antes** del `compare_digest`, no después: así un código ya usado se rechaza sin llegar a confirmar que era correcto.

**El contador es compartido** con el de la contraseña (misma clave). La alternativa —contador propio para los códigos— es mejor de usabilidad e igual de segura, pero exige tocar el esquema de 4.1 y `throttle.py`; queda como deuda. Se descartó la vía barata de prefijar la clave (`f"mfa:{username}"`) porque **colisiona**: `register()` no restringe caracteres y alguien puede registrarse literalmente como `mfa:ana` (comprobado).

Y el intento bloqueado **se audita pero no se cuenta**: contarlo permitiría mantener una cuenta bloqueada para siempre con una petición cada quince minutos (**R10**), mientras que en el log es de las líneas más valiosas que hay. La regla: **el contador decide, el log narra.**

**Verificación (4.3.6).** 28 pruebas automatizadas en `tests/test_mfa.py` y **dieciséis mutaciones** —una a la vez— para confirmar que cada control tiene una prueba que se pone en rojo cuando el control desaparece (**LL14**). Y la prueba manual con **Google Authenticator** sobre un teléfono real, que es la única que confirma que el URI `otpauth://` y el QR son los que las apps estándar esperan. El log de esa sesión:

```
02:31:06  mfa_activated   /mfa/setup   <- enrolamiento con el telefono
02:31:23  mfa_required    /login       <- paso 1: contrasena
02:31:37  login_success   /mfa         <- paso 2: codigo aceptado
02:31:53  mfa_required    /login       <- segundo login
02:32:00  mfa_failure     /mfa         <- CODIGO REUTILIZADO, rechazado
02:32:06  login_success   /mfa         <- codigo nuevo, seis segundos despues
```

El rechazo del código reutilizado contra un teléfono real es lo que confirma que el periodo que calcula la app y el que guarda el servidor son el mismo número. La app muestra el issuer **"Login Seguro"** con el nombre de la cuenta.

**Hueco conocido de cobertura, medido y no supuesto:** sustituir `hmac.compare_digest` por `==` **pasa las 28 pruebas**. Medir microsegundos sobre seis dígitos dentro del mismo proceso no da señal estable, a diferencia de los ~330 ms de bcrypt que sí sostienen `test_sin_oraculo_por_latencia` en 4.1. **Ese control se sostiene por revisión de código, no por prueba** (ver LL22).

### 4.5.4 Caducidad de la sesión

**El punto de partida estaba mal entendido.** La deuda decía "una cookie robada vive hasta 14 días si el usuario nunca hace logout". Al leer el código de Flask instalado resultó ser peor: no vivía 14 días, vivía **indefinidamente**.

`PERMANENT_SESSION_LIFETIME` **no es una vida máxima**. Son dos piezas:

```python
# flask/sessions.py -- open_session
max_age = int(app.permanent_session_lifetime.total_seconds())
data = s.loads(val, max_age=max_age)          # valida el timestamp FIRMADO

# flask/sessions.py -- should_set_cookie
return session.modified or (
    session.permanent and app.config["SESSION_REFRESH_EACH_REQUEST"]   # default: True
)
```

Lo bueno: el límite **se hace cumplir del lado del servidor**, contra el timestamp que va dentro de la firma, no contra el `Expires` de la cookie —que el cliente puede ignorar—. Lo malo: como la sesión se marca `permanent` y `SESSION_REFRESH_EACH_REQUEST` viene en `True`, la cookie se vuelve a firmar en cada petición con un timestamp nuevo. **La ventana se desliza.** Quien usa la cookie la renueva al usarla.

**Son dos controles distintos, no dos formas de configurar el mismo:**

| | Vida máxima | Expiración por inactividad |
|---|---|---|
| Se mide desde | el **login** | la **última petición** |
| Mata la sesión de | todo el mundo, cada N tiempo | quien dejó de usar la app |
| ¿Flask lo trae? | **No** | Sí, es `PERMANENT_SESSION_LIFETIME` |
| ¿La actividad lo renueva? | **No** | Sí |

Se implementaron los dos: **60 minutos de inactividad** y **12 horas de vida máxima**. El segundo es el que cierra el riesgo residual de R9, porque es el único que una cookie robada no puede estirar usándola; el primero solo, que era la lectura intuitiva del problema, no lo habría cerrado.

**Un camino descartado.** Poner `SESSION_REFRESH_EACH_REQUEST = False` parece el arreglo obvio —deja de deslizar la ventana— y es una trampa: la cookie solo se re-emite cuando la sesión se **modifica**, así que el timestamp queda congelado en un instante arbitrario y el usuario activo se ve expulsado a media tarea sin que nada lo explique. Da un límite absoluto, pero medido desde un evento que nadie controla.

**Implementación.** `SESSION_ABSOLUTE_LIFETIME_SECONDS` en `config.py` —en segundos, como los otros tres umbrales del proyecto, para que una prueba pueda bajarlo— y la comprobación en `@login_required`, **antes** del `SELECT`: una cookie vencida no tiene por qué costar una consulta. La marca es `session["login_at"]`, escrita en los **dos** puntos que abren sesión (`login()` y `mfa_verify()`); olvidar el segundo habría dejado sin tope justo a las cuentas con MFA.

**Tres decisiones que no son evidentes:**

| Decisión | Por qué |
|---|---|
| `login_at` va en la **cookie firmada**, no en la BD | Es estado de la conversación con este navegador, no de la cuenta. La firma da la integridad que aquí sí hace falta: el cliente no puede retrasar la marca. Es el mismo argumento que `pending_mfa_at` en 4.3 |
| La **ausencia** de `login_at` se trata como vencida (*fail-closed*) | Cubre las cookies emitidas antes de este cambio y cualquier punto futuro que abra sesión y olvide la marca. Sale gratis con `session.get("login_at", 0)`, sin una rama aparte |
| Evento propio `session_expired`, no `session_rejected` | Caducar y ser revocada son hechos distintos. Mezclarlos pierde la señal al leer el log, que es justo para lo que se construyó (LL16, LL19). El catálogo pasa a **15** |

**El aviso al usuario es genérico a propósito.** Decir "tu sesión caducó" le confirmaría a quien usa una cookie robada que la cookie era buena y solo llegó tarde. El mensaje es el mismo que en `/mfa`: *vuelve a iniciar sesión*.

**Verificación (6 pruebas, `tests/test_session_expiry.py`).** La central es `test_la_actividad_no_renueva_el_tope`: golpea `/dashboard` sin parar mientras el tope corre y exige además que la sesión se haya usado al menos tres veces, porque una sesión que muriera al primer intento pasaría la prueba midiendo otra cosa. Es la única que distingue el control absoluto del de inactividad; sin ella, las demás pasarían igual aunque el tope se renovara en cada petición —que era el defecto original—.

Las aserciones son sobre el **evento del log** y no solo sobre el redirect, con un `assert "session_rejected" not in nombres` explícito: una sesión rechazada por `session_version` también redirige al login, y sin ese guard la prueba habría estado verificando 4.5.2 en lugar de 4.5.4.

**Mutaciones (LL14): cuatro, las cuatro atrapadas.** Comparación invertida (5 de 6 en rojo); `login()` sin la marca (4 en rojo); `mfa_verify()` sin la marca (1 en rojo); evento de auditoría equivocado (2 en rojo, gracias al guard de arriba). **Sin huecos que documentar bajo LL22 esta vez.**

Un detalle de la tercera: no la atrapa el archivo nuevo sino `test_mfa.py::test_el_login_completo_con_mfa_abre_sesion`, que asevera un 200 en `/dashboard`. La cobertura del camino con MFA es real pero **incidental**, no de diseño: si alguien reorganiza `test_mfa.py` se pierde sin que nada lo señale.

**Limitación conocida.** La expiración por inactividad **no puede auditarse**: Flask descarta la cookie vencida en `open_session` y la sesión llega vacía a la vista, indistinguible de un visitante que nunca inició sesión. No hay `user_id` a quien atribuir el evento. Queda fijado con una prueba que afirma esa ausencia, para que salte si algún día cambia.

**Efecto colateral del despliegue.** Ninguna cookie anterior a este cambio trae `login_at`, así que todas las sesiones abiertas —incluida la de `prueb1`— rebotan al login la primera vez. Es el *fail-closed* funcionando, y es el aspecto que tendría una migración de este control.

### 4.5.5 Auditoría de dependencias

**Resultado: 0 vulnerabilidades conocidas.** `pip-audit 2.10.1` contra la PyPI Advisory Database, 22 de septiembre de 2026.

**Qué hace la herramienta, y qué no.** Compara **nombre + versión** de cada paquete contra avisos publicados (OSV / GHSA / CVE). No analiza el código ni cómo se usa cada librería. Un resultado limpio significa *nada conocido hoy*, no *sin vulnerabilidades*: por eso R6 pide re-correrlo en cada cierre de fase y no una sola vez.

**Lo que se auditó no fue `requirements.txt`.** El archivo declara **8 paquetes**; el entorno tiene **22**. Los 14 restantes son transitivos:

| Declarado | Arrastra |
|---|---|
| Flask | Werkzeug, Jinja2, itsdangerous, MarkupSafe, click, blinker |
| email-validator | dnspython, idna |
| qrcode | colorama |
| pytest | pluggy, iniconfig, packaging, Pygments |

Es el punto entero de R6: **en una app Flask los avisos caen históricamente en Werkzeug y en Jinja2**, que nadie escribió en el archivo. Auditar solo lo declarado habría sido auditar la lista corta, no la superficie real. Se auditó además `pip` (26.2.1) por separado, porque `pip freeze` lo omite de su salida.

**El auditor no se instaló en el entorno que audita.** `pip-audit` arrastra su propia cadena —`requests`, `cyclonedx-python-lib`, `pip-api` y otros ~10—. Instalado en `.venv`, esos paquetes pasarían a formar parte de lo auditado, y los hallazgos del auditor quedarían mezclados con los del proyecto. El procedimiento:

```powershell
# 1. Congelar el entorno REAL antes de tocar nada
.\.venv\Scripts\python.exe -m pip freeze > entorno-real.txt

# 2. Auditor en un venv desechable, fuera del proyecto
python -m venv auditor
.\auditor\Scripts\python.exe -m pip install pip-audit

# 3. Auditar el archivo congelado, sin resolver nada
.\auditor\Scripts\pip-audit.exe -r entorno-real.txt --no-deps
```

`--no-deps` porque el archivo congelado ya trae **todo** fijado con `==`: no hay nada que resolver, y resolverlo abriría la puerta a auditar versiones distintas de las instaladas. Como contraste se corrió también `pip-audit -r requirements.txt` con resolución de transitivas; mismo resultado, cero hallazgos.

**Separación de `requirements-dev.txt`.** Aprovechando el paquete se pagó la deuda de que `requirements.txt` mezclaba producción y desarrollo. Ahora `requirements.txt` es lo que la aplicación necesita para **correr** —y lo único que instalaría un despliegue— y `requirements-dev.txt` tiene `pytest` y `pip-audit`. No es cosmético: cada paquete instalado es superficie de cadena de suministro aunque el código nunca lo importe, y una herramienta de desarrollo en un servidor es exactamente eso.

`pip-audit` queda fijado ahí con su versión aunque **no** se instale en `.venv`, para que la próxima revisión de R6 sepa con qué se auditó y pueda reproducir el resultado. El comentario del archivo lo dice explícitamente, porque de otro modo la línea invita a instalarlo donde no debe ir.

**Nota que ya estaba escrita.** El comentario de `qrcode` en `requirements.txt` anticipaba esta corrida: *"si `colorama` aparece en `pip-audit`, de ahí viene"*. Apareció en la lista auditada, sin hallazgos, y confirma la decisión de usar la factory SVG en lugar de la PNG — que habría metido Pillow entero, con sus decodificadores en C, a esta auditoría y a todas las siguientes.

### 4.5.6 Recorrido del OWASP Top 10

Documento propio: **`docs/fase2-owasp-top10.md`**. Aquí solo lo que hay que saber para no tener que abrirlo.

**Se recorrió la edición 2025, no la 2021.** Las notas de Fase 0 y el glosario usan los nombres de 2021 —por eso ahí *Cryptographic Failures* es A02 y en el recorrido es A04—, y el Charter, el Scope y el WBS dicen "OWASP Top 10" sin fijar edición. Se eligió la vigente por dos razones concretas: **A03 Software Supply Chain Failures** es literalmente el paquete 4.5.5, y **A10 Mishandling of Exceptional Conditions** es LL15 —el 500 en `/forgot-password` que delataba qué emails existían—. Con la lista de 2021, dos piezas de trabajo ya hecho no habrían tenido dónde aparecer.

**Pendiente de gobernanza:** fijar la edición en el Charter (Sección 10, Registro de Cambios). Un artefacto que dice "OWASP Top 10" a secas envejece sin avisar, que es justo lo que R8 pide evitar.

**El formato es tres preguntas por categoría** —¿aplica?, ¿qué control hay?, ¿qué falta?— y la que importa es la tercera. Un recorrido que solo lista lo que sí se hizo es autofelicitación; el valor está en que la autoevaluación ASVS de Fase 3 empiece con un inventario honesto y no con una hoja en blanco (R5).

**Los tres huecos más grandes que salieron:**

1. **Sin cabeceras de seguridad** (A02). Ninguna: ni CSP, ni HSTS, ni `X-Content-Type-Options`, ni `Referrer-Policy`. La última no es teórica — acota el riesgo residual de R11, el token que viaja en la URL, con una línea de configuración.
2. **Sin alerting** (A09). El log se escribe con disciplina y **nadie lo lee**: sin umbrales, sin notificaciones, sin rotación, sin protección de integridad. El cambio de nombre de la categoría en 2025 —de *Monitoring* a *Alerting*— señala exactamente esto, y el proyecto lo falla entero.
3. **Configuración de desarrollo como única configuración** (A02, A04). `debug=True`, sin servidor WSGI y sin TLS. Eso deja tres controles en estado declarativo: `SESSION_COOKIE_SECURE` funciona en local solo porque el navegador trata `localhost` como contexto seguro.

**Lo que el recorrido añadió al inventario y no estaba registrado en ninguna parte:** las cabeceras ausentes; la falta de alerting, rotación e integridad del log; la ausencia de manejadores globales de error —el único `errorhandler` es el de `CSRFError`, así que un 500 imprevisto ni se maneja ni se audita—; la falta de verificación por hash de las dependencias (`--require-hashes`); y que `@login_required` **depende de que alguien se acuerde de escribirlo**: no hay *deny by default*, así que una ruta nueva sin el decorador queda abierta y nada avisa.

**Lo que confirmó sin cambios:** los riesgos residuales ya registrados de R10, R11, R12, R13 y R14.

**Una afirmación se corrigió al verificarla contra el código** en lugar de darla por buena: el recorrido decía "sin rollback explícito", y `register()` sí hace `db.rollback()` ante un `IntegrityError`. Lo que falta es manejo de las excepciones **no** previstas, donde la consistencia la salva el cierre de la conexión y no una decisión.

## Cierre de Fase 2 (WBS 4.6)

### 4.6.1 Pruebas end-to-end contra los criterios de aceptación

Se recorrieron los criterios del Scope Statement (Sección 3) sobre la **aplicación real corriendo en HTTP**, no con el test client de pytest: servidor levantado en el puerto 5099 con `debug=False`, contra una base y un log temporales —la BD de desarrollo no se tocó— y conducido con `curl`, cookies y token CSRF incluidos.

Eso es lo que distingue 4.6.1 de la suite de 4.6.4. Las pruebas automatizadas llaman a la aplicación por dentro; aquí se comprobó lo que viaja **por el cable**: cabeceras `Set-Cookie` reales, redirecciones reales, el enlace saliendo por la consola del servidor.

| Criterio (Scope, Sección 3) | Cómo se verificó | Resultado |
|---|---|---|
| Las contraseñas nunca se almacenan en texto plano | `SELECT password_hash` sobre el SQLite recién creado | `$2b$12$…`, cost 12; la contraseña en claro no aparece |
| Cookies con `HttpOnly`, `Secure`, `SameSite` | Cabecera `Set-Cookie` cruda de un login real | `Secure; HttpOnly; Path=/; SameSite=Strict` |
| Rate limiting tras N intentos | 5 fallos y un sexto intento **con la contraseña correcta** | Rechazado. Otro usuario entró sin problema en el mismo momento: el bloqueo es por cuenta, no global |
| El token de recuperación expira y no se reutiliza | Flujo completo con el enlace tomado de la consola | 1.er uso cambia la contraseña (la nueva entra, la vieja no); 2.º uso del mismo token rechazado, sin cambiar nada |
| MFA validado contra una app autenticadora estándar | **4.3.6**, con Google Authenticator en un teléfono real | Ya verificado al cerrar 4.3 |
| MFA, resto del flujo sobre HTTP | Enrolamiento, login en dos pasos y repetición | Activación con el primer código; la sesión pendiente **no** abre `/dashboard`; segundo paso correcto; código repetido rechazado |
| Eventos de seguridad con timestamp | Lectura del log de la corrida | 15 eventos, todos con `ts`; `login_blocked` separado de `login_failure`; una línea JSON por evento; ningún secreto presente |

**Como efecto secundario se vio en vivo el control de 4.5.4:** el `Expires` de la cookie llegó a exactamente 60 minutos del login, que es la expiración por inactividad recién configurada.

**Dos "fallos" durante la corrida, y los dos eran del guion, no de la aplicación:**

1. `GET /reset-password?token=…` devolvió **405**. La ruta real es `/reset-password/<token>`, con el token en el *path* — que es justo la razón por la que ese GET no audita, para no escribir el token en el log. El guion estaba mal escrito.
2. El segundo paso del login con MFA falló la primera vez. El guion hizo en dos segundos lo que una persona hace en veinte, así que reutilizó **el mismo código** con el que acababa de activar el enrolamiento, que queda consumido a propósito. Era la protección contra repetición haciendo su trabajo.

El segundo merece quedar escrito (**LL25**): en una corrida automatizada, un rechazo puede ser el control funcionando y no un defecto. Diagnosticar antes de "arreglar".

### 4.6.3 Revisión del Risk Register y del Lessons Learned

**Risk Register al cierre de la fase:**

| Estado | Riesgos |
|---|---|
| Mitigado | R1, R4 (MFA), R6 (dependencias), R9 (sesión, con su residual **cerrado** en 4.5.4), R10 (fuerza bruta), R11 (recuperación), R14 (auditoría) |
| Aceptado | R3 (disponibilidad), R12 (secreto TOTP sin cifrar), R13 (sin códigos de respaldo) |
| En seguimiento | R2 (cronograma), R5 (falsa sensación de seguridad → Fase 3), R7, R8 |

Ningún riesgo se cierra: siguiendo la Sección 5 del registro, los cerrados se marcan pero no se borran, y aquí ninguno dejó de aplicar.

**Residuales que quedan abiertos y conocidos:** sin límite por IP (R10, *password spraying*); sin límite de tasa en `/forgot-password` y token en la URL (R11); secreto TOTP en claro (R12); sin códigos de respaldo (R13); contraseña escrita en el campo "Usuario" (R14). Más los **cinco huecos nuevos** que destapó 4.5.6, ya en la lista de deuda.

**Lessons Learned:** se agregan LL24 y LL25. La revisión formal completa del log corresponde al cierre del proyecto (M5).

### 4.6.2 y 4.6.4

4.6.4 se ejecutó anticipadamente durante 4.1 y quedó registrado en el Charter (cambio #3). 4.6.2 es el commit de cierre.

---

## Deuda y pendientes de Fase 2

- [x] ~~4.5.4: riesgo residual de R9~~: cerrado. El enunciado estaba **de menos** —la cookie robada no vivía 14 días, vivía indefinidamente porque el uso la renovaba—. Resuelto con 60 min de inactividad + 12 h de vida máxima. Ver 4.5.4 y LL23.
- [x] ~~4.5.5: `pip-audit` sobre las dependencias (R6)~~: hecho. 0 vulnerabilidades conocidas sobre los 22 paquetes del entorno (no solo los 8 declarados) más `pip`. De paso se separó `requirements-dev.txt`. Ver 4.5.5.
- [x] ~~4.5.6: recorrido documentado del OWASP Top 10~~: hecho, contra la edición **2025**. Ver `docs/fase2-owasp-top10.md` y la sección 4.5.6.
- [ ] **Gobernanza:** fijar la edición del OWASP Top 10 en el Charter (Sección 10). Los artefactos dicen "OWASP Top 10" sin edición, y eso envejece sin avisar (R8).
- [ ] **A02 — sin cabeceras de seguridad.** Ni CSP, ni HSTS, ni `X-Content-Type-Options`, ni `X-Frame-Options`, ni `Referrer-Policy`. Esta última acota el riesgo residual de R11 con una línea.
- [ ] **A09 — sin alerting.** El log se escribe y nadie lo lee: sin umbrales, sin rotación, sin protección de integridad del archivo.
- [ ] **A10 — sin manejadores globales de error.** El único `errorhandler` es el de `CSRFError`; un 500 imprevisto ni se maneja ni se audita, y con `debug=True` devolvería el traceback.
- [ ] **A03/A08 — sin `--require-hashes` ni SBOM.** Se fija la versión, no el artefacto.
- [ ] **A01 — `@login_required` no es *deny by default*.** Una ruta nueva sin el decorador queda abierta y nada avisa.
- [ ] **A07 — sin comprobación contra contraseñas filtradas.** Lo pide ASVS Level 1; candidato claro para Fase 3.
- [x] ~~Sin pruebas automatizadas en el repo~~: resuelto durante 4.1. Se incorporó `pytest` y la carpeta `tests/` (56 pruebas sobre los paquetes 4.1, 4.2, 4.4, 4.5.2 y 4.5.3). Ver `tests/README.md`. **Pendiente formal:** registrar el cambio de alcance en el Charter y agregar el paquete al WBS.
- [ ] `tests/`: falta cubrir 4.5.1 (`validate_secret_key`) y el resto de las validaciones propias de `/register` (formato del email, límite de 72 bytes). La política de longitud ya quedó cubierta en 4.2.7.
- [ ] Riesgo residual de R14: una contraseña escrita por error en el campo "Usuario" queda en el log.
- [ ] Riesgo residual de R10: no hay límite por IP, así que el *password spraying* pasa sin tocar ningún contador.
- [ ] Riesgo residual de R11: `/forgot-password` no tiene límite de tasa (DoS de recuperación por invalidación en serie de tokens).
- [ ] Riesgo residual de R11: el token viaja en la URL (historial del navegador, posible fuga por `Referer`).
- [ ] **4.3: contador de intentos compartido** entre contraseña y códigos TOTP. Un contador propio para los códigos es mejor de usabilidad (quien falló la contraseña llega a `/mfa` con el presupuesto ya gastado) e igual de seguro; exige una columna `kind` en `login_attempts` y un parámetro más en `throttle.py`.
- [ ] **4.3: migración de esquema aplazada.** Las columnas de MFA se resolvieron recreando la BD de desarrollo. Con datos que importen hace falta un script de migración (LL4).
- [ ] `tests/`: sustituir `compare_digest` por `==` en `mfa.py` no lo atrapa ninguna prueba (medido; ver 4.3 y LL22).
- [ ] Riesgo aceptado R12: el secreto TOTP se guarda sin cifrar. Se documenta como *gap* en la autoevaluación ASVS de Fase 3.
- [ ] Riesgo aceptado R13: sin códigos de respaldo. Perder el teléfono exige desactivar MFA a mano en la BD.
