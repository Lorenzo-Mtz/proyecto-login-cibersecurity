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

---

## Deuda y pendientes de Fase 2

- [ ] 4.5.4: riesgo residual de R9 (sesión de 14 días sin expiración por inactividad).
- [ ] 4.5.5: `pip-audit` sobre las dependencias (R6).
- [ ] 4.5.6: recorrido documentado del OWASP Top 10.
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
