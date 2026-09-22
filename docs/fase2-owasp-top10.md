# Recorrido del OWASP Top 10 — Fase 2

**Edición:** OWASP Top 10:**2025** (`https://top10.owasp.org/2025/`)
**Fecha:** 22 de septiembre de 2026
**Paquete:** WBS 4.5.6
**Preparado por:** Lorenzo Mtz

> **Nota sobre la edición.** Las notas de estudio de Fase 0 (tema 0.6) y el glosario se
> escribieron contra la edición **2021**: por eso ahí *Cryptographic Failures* aparece
> como A02 y aquí es A04. El Charter, el Scope Statement y el WBS dicen "OWASP Top 10"
> sin fijar edición. Se recorre la **vigente**, porque es lo que haría una revisión real
> y porque dos de sus categorías —A03 *Software Supply Chain Failures* y A10
> *Mishandling of Exceptional Conditions*— cubren trabajo que este proyecto ya hizo y
> que la lista de 2021 no reconocía como categoría propia. **Pendiente de gobernanza:**
> fijar la edición en el Charter (Sección 10, Registro de Cambios), que es justo lo que
> R8 pide evitar — artefactos que se desactualizan en silencio.

---

## 1. Para qué sirve este documento

Recorrer las diez categorías y contestar tres preguntas por cada una: **¿aplica a este
proyecto?**, **¿qué control está implementado?** y **¿qué falta?**.

Lo importante es la tercera columna. Un recorrido que solo lista lo que sí se hizo es un
ejercicio de autofelicitación; el valor está en dejar por escrito lo que **no** está
cubierto, para que la autoevaluación ASVS Level 1 de Fase 3 empiece con un inventario
honesto y no con una hoja en blanco (R5: no asumir que "funciona" = "seguro").

El Top 10 es una lista de **categorías de riesgo**, no un checklist de cumplimiento. Que
las diez tengan algo escrito no significa que el proyecto esté seguro: significa que se
miró cada una a propósito.

---

## 2. Resumen

| # | Categoría | ¿Aplica? | Estado |
|---|---|---|---|
| A01 | Broken Access Control | Sí, de forma acotada | Cubierto para la superficie que existe |
| A02 | Security Misconfiguration | Sí | **Parcial** — faltan cabeceras de seguridad y configuración de producción |
| A03 | Software Supply Chain Failures | Sí | Cubierto en 4.5.5; falta SBOM y verificación por hash |
| A04 | Cryptographic Failures | Sí | Cubierto, con R12 aceptado y sin TLS real |
| A05 | Injection | Sí | Cubierto; validación de entrada incompleta |
| A06 | Insecure Design | Sí | Es la fortaleza del proyecto; falta el threat model (Fase 3) |
| A07 | Authentication Failures | Sí, es el núcleo | Cubierto; cuatro riesgos residuales conocidos |
| A08 | Software or Data Integrity Failures | Parcialmente | No hay CI/CD que proteger; falta `--require-hashes` |
| A09 | Security Logging and Alerting Failures | Sí | Logging sólido, **alerting inexistente** |
| A10 | Mishandling of Exceptional Conditions | Sí | Tratado caso por caso; falta manejo global de errores |

**Los tres huecos más grandes,** por si alguien lee solo esta sección: no hay **cabeceras
de seguridad** (A02), no hay **nada que lea el log** (A09) y la app corre con
`debug=True` sin servidor WSGI ni TLS reales (A02, A04).

---

## 3. Recorrido

### A01:2025 — Broken Access Control

**¿Aplica?** Sí, pero sobre una superficie pequeña. La aplicación tiene **una sola ruta
protegida** (`/dashboard`) y **no hay roles, ni recursos de un usuario que otro pueda
pedir, ni rutas con el identificador de un objeto en la URL**. Eso elimina por
construcción la forma más común de esta categoría (IDOR), y conviene decirlo así: es un
hecho del alcance, **no un control**. El día que exista `/perfil/<id>` habrá que diseñar
la autorización, no heredarla.

**Controles implementados**

| Control | Dónde | Paquete |
|---|---|---|
| Decorador `@login_required` en toda ruta protegida | `src/routes/decorators.py` | 4.5.2 |
| La sesión pendiente de MFA **no lleva `user_id`**, así que el guard la rechaza igual que a un visitante | `src/routes/auth.py` | 4.3.4 |
| Revocación server-side con `session_version`: una cookie emitida antes del logout o del cambio de contraseña deja de servir | `users.session_version` | 4.5.2, 4.2.6 |
| Caducidad de la sesión: 60 min de inactividad y 12 h de vida máxima | `@login_required`, `config.py` | 4.5.4 |
| `/logout` solo por POST, con token CSRF | `src/routes/auth.py` | 4.5.3 |
| El `SELECT` del decorador lista columnas explícitas y no `*`, para que `totp_secret` no quede en `g.user` | `src/routes/decorators.py` | 4.3 |

**Gaps**

- No hay control de acceso **a nivel de objeto**, porque no hay objetos. Es deuda latente,
  no deuda actual.
- El control vive en un decorador que hay que **acordarse de poner**. No hay un
  *deny by default* a nivel de blueprint: una ruta nueva sin el decorador queda abierta y
  nada avisa. Es un fallo abierto en potencia (LL12).

---

### A02:2025 — Security Misconfiguration

**¿Aplica?** Sí, y es donde el proyecto tiene más pendientes.

**Controles implementados**

| Control | Detalle |
|---|---|
| `SECRET_KEY` obligatoria | `create_app()` **se niega a arrancar** si falta, es la de `.env.example` o mide menos de 32 caracteres. Sin valor por defecto a propósito: un *fallback* de desarrollo ocultó durante toda la Fase 1 que las cookies se firmaban con una clave pública (LL8) |
| Cookie endurecida | `HttpOnly` (default de Flask), `Secure` y `SameSite=Strict` |
| CSRF global | `CSRFProtect` sobre toda la app, no formulario por formulario |
| Secretos fuera del repo | `.env`, `*.key`, `*.pem`, `*.db` en `.gitignore` (R7); `instance/` y `*.log` también |
| Dependencias de desarrollo separadas | `requirements-dev.txt`, para que un despliegue no instale `pytest` ni `pip-audit` (4.5.5) |

**Gaps**

- **Sin cabeceras de seguridad.** No se emiten `Content-Security-Policy`,
  `X-Content-Type-Options`, `X-Frame-Options`, `Strict-Transport-Security` ni
  **`Referrer-Policy`**. La última no es teórica aquí: el riesgo residual de R11 es
  justamente que el token de recuperación viaja en la URL y podría filtrarse por
  `Referer`. Una `Referrer-Policy` restrictiva lo acotaría sin rediseñar el flujo.
- **`run.py` usa `app.run(debug=True)`** (S7). En desarrollo es cómodo; expuesto sería un
  intérprete de Python remoto vía el depurador de Werkzeug. No hay separación
  desarrollo/producción más allá de esa línea.
- **Sin servidor WSGI ni TLS reales.** `SESSION_COOKIE_SECURE = True` funciona en local
  solo porque los navegadores tratan `localhost` como contexto seguro; en cualquier otro
  despliegue por HTTP la cookie sencillamente no viajaría. Es un control que hoy no se
  ejerce de verdad.
- **Sin cabecera de errores propia:** con `debug=True`, un 500 devuelve el traceback.
  Ver A10.

---

### A03:2025 — Software Supply Chain Failures

**¿Aplica?** Sí. Es la categoría que más subió en 2025 (venía de *Vulnerable and Outdated
Components*) y ahora cubre **todo el proceso de construir, distribuir y actualizar**, no
solo las versiones con avisos conocidos. Es exactamente el paquete 4.5.5.

**Controles implementados**

- **Versiones fijadas con `==`** en `requirements.txt` y `requirements-dev.txt`. Nada de
  rangos: el entorno es reproducible.
- **Auditoría con `pip-audit` 2.10.1**: 0 vulnerabilidades conocidas sobre los **22
  paquetes del entorno** —no solo los 8 declarados— más `pip`, que `pip freeze` omite.
- **El auditor no se instala en el entorno auditado**, para no mezclar su propia cadena
  (~10 paquetes) con la del proyecto.
- **Decisión deliberada de no ampliar la cadena:** se usa la factory **SVG** de `qrcode` y
  no la PNG, que habría metido Pillow entero —con sus decodificadores en C— a esta
  auditoría y a todas las siguientes. Está escrito en `requirements.txt` para que nadie lo
  "mejore" sin ver el costo.
- **Separación producción / desarrollo**, para que un despliegue no instale herramientas
  que nunca va a usar.

**Gaps**

- **Sin SBOM.** `pip-audit` puede emitir CycloneDX; no se generó. La categoría lo pide
  explícitamente como inventario central de dependencias directas y transitivas.
- **Sin verificación por hash.** `pip-audit` lo advirtió en la corrida: *"users are
  encouraged to fully hash their pinned dependencies"*. Hoy se fija la **versión**, pero no
  el **artefacto**: nada comprueba que el `.whl` descargado sea el mismo que se auditó.
  Requiere `pip-compile --generate-hashes` e instalar con `--require-hashes`.
- **Auditoría manual y puntual.** No hay CI que la corra: el control depende de que alguien
  se acuerde al cerrar la fase. Un aviso publicado mañana no lo detecta nadie.
- **Sin firma ni verificación de procedencia** de los paquetes más allá de la confianza en
  PyPI.
- El resto de la categoría —seguridad de los servidores de build, separación de
  responsabilidades, despliegues escalonados— **no aplica**: no hay pipeline, ni build, ni
  despliegue. Que no aplique hoy no significa que esté resuelto; significa que no existe.

---

### A04:2025 — Cryptographic Failures

**¿Aplica?** Sí.

**Controles implementados**

| Uso | Primitiva | Por qué esa |
|---|---|---|
| Contraseñas | **bcrypt**, cost 12 | Lento a propósito. Los ~330 ms por verificación son el control, no un defecto de rendimiento |
| Token de recuperación | **SHA-256** del token, solo el hash en la BD | Y no bcrypt: el token trae 256 bits de un CSPRNG, así que no hay diccionario que probar y encarecer cada intento no compra nada |
| Generación de tokens | `secrets.token_urlsafe(32)` | CSPRNG. `random` es determinista a partir de su semilla y no sirve para secretos |
| Códigos TOTP | `hmac.compare_digest` | Comparación en tiempo constante: `==` cortaría en el primer dígito distinto y su duración revelaría cuántos se acertaron |
| Sesión | Cookie **firmada** con `SECRET_KEY` validada al arrancar | Firmada, no cifrada: sirve para impedir que el cliente la modifique, no para guardar secretos en ella |

**Gaps**

- **R12, aceptado a conciencia:** `users.totp_secret` se guarda **en claro**. No es un
  descuido: validar un código TOTP exige **recalcular** un HMAC, y no se puede calcular un
  HMAC con el hash de la llave. Cifrarlo requiere gestión de llaves, fuera del alcance. La
  exposición está acotada (no entra a `g.user`, ni a la cookie, ni al log) y queda como
  *gap* explícito para la autoevaluación ASVS de Fase 3.
- **Sin TLS.** Todo lo anterior protege datos en reposo y en la cookie; **en tránsito no
  hay nada**. Es el hueco más grande de esta categoría y el que hace que `Secure` y
  `HSTS` sean hoy declaraciones de intención.
- **Sin cifrado en reposo de la base de datos.** El archivo SQLite está fuera del repo
  (R7), pero quien lea el disco lo lee entero.

---

### A05:2025 — Injection

**¿Aplica?** Sí.

**Controles implementados**

- **Consultas parametrizadas en todo el código.** No hay una sola concatenación de SQL:
  los valores viajan como parámetros (`?`), nunca como texto de la sentencia.
- **Autoescape de Jinja2** en las plantillas, que cubre el XSS reflejado por defecto.
- **Log injection cerrada** (4.4.3, R14): cada evento se escribe con `json.dumps`, que
  escapa saltos de línea y comillas, y el `username` se recorta a 64 caracteres. Se
  verificó con un usuario que contenía un salto de línea y un `login_success` falso: quedó
  en una sola línea, escapado, como `login_failure`.
- **`PRAGMA foreign_keys = ON`** en cada conexión (SQLite las ignora por defecto).

**Gaps**

- **La validación de entrada es parcial.** El email pasa por `email-validator` y la
  contraseña por la política de longitud, pero **el nombre de usuario solo se comprueba
  que no esté vacío**. LL20 mostró la consecuencia concreta: alguien puede registrarse
  literalmente como `mfa:ana`. No es inyección SQL —las consultas están parametrizadas—
  pero sí es la misma raíz: **mezclar control y datos en una cadena sin restringir el
  espacio de nombres**.
- **Sin Content-Security-Policy** como segunda línea frente al XSS (ver A02). El autoescape
  de Jinja2 es bueno, pero es el único control.

---

### A06:2025 — Insecure Design

**¿Aplica?** Sí, y es donde el proyecto está mejor: casi todas las decisiones no evidentes
están escritas junto al código que las implementa.

**Controles implementados** — muestra de decisiones de diseño, no de código:

| Decisión | Riesgo que cierra |
|---|---|
| `login_attempts` **sin `FOREIGN KEY`** a `users` | Si solo se contaran cuentas reales, el bloqueo sería un oráculo de existencia: `admin` se bloquearía y `xyz123` nunca |
| El intento bloqueado **se audita pero no se cuenta** | Contarlo permitiría mantener bloqueada una cuenta ajena para siempre con una petición cada quince minutos |
| `verificar_codigo()` devuelve **el periodo aceptado**, no un booleano | Con un booleano, quien llama no tendría qué guardar y el control de reutilización sería imposible |
| MFA **opcional** y activable desde el dashboard, no obligatorio al registrarse | Con R13 aceptado (sin códigos de respaldo), obligarlo dejaría cada cuenta nueva a un teléfono perdido de necesitar acceso a SQLite |
| La contraseña correcta **no reinicia** el contador cuando hay MFA | Si lo hiciera, quien tenga la contraseña probaría códigos de cinco en cinco volviendo a loguearse |
| `session_expired` como evento propio y no `session_rejected` | Caducar y ser revocada son hechos distintos; mezclarlos pierde la señal al leer el log |
| **Fail-closed por defecto** | Un control que rechaza de más se reporta en cinco minutos; uno que deja pasar no se nota nunca (LL12) |
| **Mutation testing** al cerrar cada paquete (LL14) | Una prueba que nunca se ha visto fallar no prueba nada |

**Gaps**

- **Sin threat model formal.** Está planificado para Fase 3 (Charter, M4). Hoy las
  amenazas se razonaron control por control, que es mejor que nada pero no es un
  recorrido sistemático: nada garantiza que no falte una rama entera.
- **El espacio de nombres de los usuarios no está restringido** (LL20). La decisión de
  diseño quedó identificada pero no tomada.
- **Contador de intentos compartido** entre contraseña y códigos TOTP. Un contador propio
  sería mejor de usabilidad e igual de seguro; exige una columna `kind` en
  `login_attempts`.
- **Sin límites de recursos** de ningún tipo: ni tamaño máximo de petición, ni límite de
  cuentas por origen, ni rate limiting general.

---

### A07:2025 — Authentication Failures

**¿Aplica?** Es el núcleo del proyecto. Prácticamente toda la Fase 2 vive aquí.

**Controles implementados**

| Control | Paquete |
|---|---|
| Hash con bcrypt cost 12, nunca la contraseña en claro | 3.2.4 |
| Política de longitud 12–64 caracteres, máximo 72 bytes (límite real de bcrypt), **sin reglas de complejidad** — criterio NIST SP 800-63B / ASVS | Fase 1 |
| Anti fuerza bruta: 5 fallos / 15 min, ventana deslizante, nunca permanente | 4.1 |
| Sin enumeración de usuarios: mensaje genérico y `bcrypt.checkpw` contra `DUMMY_HASH` para igualar también la **latencia** | 4.1, 4.2 |
| Segundo factor TOTP: ventana de ±1 periodo, rechazo de reutilización por número de periodo, límite de intentos | 4.3 |
| Recuperación con token de un solo uso, 30 min, solo su SHA-256 en la BD, que cierra sesiones al consumirse | 4.2 |
| Gestión de sesión: revocación server-side, 60 min de inactividad, 12 h de vida máxima | 4.5.2, 4.5.4 |

**Gaps** — los cuatro son riesgos residuales ya registrados:

- **Sin comprobación contra listas de contraseñas filtradas.** ASVS Level 1 lo pide, y es
  el hueco más relevante de esta categoría: una contraseña de 12 caracteres puede ser
  perfectamente `Password1234`. Candidato claro para Fase 3.
- **Sin límite por IP** (R10 residual): contar por usuario no detecta *password spraying*,
  porque ninguna cuenta acumula fallos.
- **Sin límite de tasa en `/forgot-password`** (R11 residual): como un token nuevo invalida
  los anteriores, quien conozca un email puede mantener invalidado el que la víctima está
  por usar.
- **Sin códigos de respaldo** (R13, aceptado): perder el teléfono exige desactivar MFA a
  mano en la BD.

---

### A08:2025 — Software or Data Integrity Failures

**¿Aplica?** Parcialmente. La mitad de la categoría —integridad del pipeline de CI/CD,
actualizaciones automáticas sin verificar, deserialización insegura— **no tiene dónde
ocurrir aquí**: no hay CI, ni despliegue automático, ni se deserializa nada que venga del
cliente más allá de la cookie de sesión.

**Controles implementados**

- **La cookie de sesión va firmada.** Un cliente no puede fabricarse un `user_id`, ni
  retrasar `login_at`, ni marcarse como "ya puse la contraseña". La integridad de todo el
  estado de sesión descansa en la `SECRET_KEY`, que por eso se valida al arrancar.
- **Integridad de las escrituras críticas.** Al consumir un token de recuperación, la
  contraseña nueva y `session_version + 1` se escriben en la **misma sentencia**: no existe
  un estado intermedio donde la contraseña cambió pero las sesiones viejas siguen abiertas.
- **`session_version` con `AND` en el `UPDATE`** del logout: una cookie vieja no puede
  cerrar las sesiones nuevas del usuario legítimo.

**Gaps**

- **Sin `--require-hashes`** (mismo hueco que A03): se fija la versión, no el artefacto.
- **Sin integridad del log** — ver A09.
- El resto de la categoría no aplica **por ausencia de infraestructura**, no por estar
  resuelto. Si algún día hay pipeline, esta sección se reescribe entera.

---

### A09:2025 — Security Logging and Alerting Failures

**¿Aplica?** Sí. El paquete 4.4 la atiende, y el **cambio de nombre de 2025** —de
*Monitoring* a ***Alerting***— señala justo lo que aquí falta.

**Controles implementados**

- **Catálogo cerrado de 15 eventos.** `audit()` lanza `ValueError` ante un evento no
  catalogado.
- **Imposible filtrar un secreto por accidente:** la firma de `audit()` no acepta campos
  libres, solo `event`, `user_id` y `username`. No hay por dónde pasarle una contraseña, un
  token o un código TOTP.
- **Una línea JSON por evento**, con escape de saltos de línea y comillas (ver A05).
- **Los eventos distinguen señales, no solo resultados.** Es la parte de diseño:
  `mfa_required` existe porque una ráfaga de esos *sin* un `login_success` detrás significa
  que la contraseña ya está comprometida; `login_blocked` es distinto de `login_failure`; y
  `session_expired` es distinto de `session_rejected`. Un catálogo que colapsara estos
  pares sería contable pero no diría nada (LL19).
- **El log está fuera del repo** y cada prueba escribe en el suyo, temporal.

**Gaps**

- **No hay alerting. Nada lee el archivo.** Se escribe con disciplina y ahí se queda: sin
  umbrales, sin notificaciones, sin nadie mirando. Es literalmente el punto que el nombre
  de la categoría 2025 subraya, y hoy el proyecto lo falla entero.
- **Sin rotación ni límite de tamaño.** El archivo crece sin techo.
- **Sin protección de integridad.** Quien pueda escribir en `instance/` puede editar o
  borrar el log. No es *append-only* ni está firmado.
- **R14 residual:** una contraseña escrita por error en el campo "Usuario" queda en el log
  como `username` de un `login_failure`.
- **El GET de `/reset-password` no audita a propósito**, porque el token viaja en
  `request.path` y registrarlo sería filtrarlo. Es una decisión correcta, pero deja un
  hueco de trazabilidad: ese acceso no queda registrado en ninguna parte.

---

### A10:2025 — Mishandling of Exceptional Conditions

**¿Aplica?** Sí, y el proyecto tiene una historia concreta en esta categoría — que en 2021
no existía como tal.

La categoría cubre tres fallos: que la aplicación **no prevenga** la situación anómala,
que **no la detecte**, o que **responda mal** ante ella. Los tres ejemplos canónicos son
agotamiento de recursos, **errores que exponen información** y transacciones a medias sin
rollback.

**Controles implementados**

| Situación anómala | Cómo se maneja |
|---|---|
| Email inexistente en `/forgot-password` | **LL15**, el caso más claro: el código desempacaba un `fetchone()` que devolvía `None`, así que respondía **302 si el email existía y 500 si no**. Un 500 es tan buen oráculo como un mensaje distinto. Corregido y con prueba que compara la respuesta completa —código, destino y HTML— entre las dos ramas |
| La cuenta desactiva MFA entre los dos pasos del login | `mfa_verify()` comprueba `mfa_enabled` antes de usar `totp_secret`; sin eso, un `NULL` reventaría en un 500 a media autenticación |
| Código TOTP no ASCII | Filtro de formato **antes** de `compare_digest`, que con una entrada no ASCII lanzaría `TypeError` → 500 |
| Token CSRF ausente o vencido | Manejador de `CSRFError` que audita, avisa y redirige, en lugar de devolver un 400 crudo |
| Sesión sin `login_at` | **Fail-closed**: se trata como vencida. Lo anómalo se rechaza, no se interpreta (4.5.4) |
| Contraseña correcta durante un bloqueo | El guard va **antes** de validar credenciales: la condición excepcional se resuelve primero y no se le puede ganar acertando |

El principio está escrito en el glosario y en LL12: **todo control debe fallar cerrado**,
porque un fallo abierto no se nota nunca.

**Gaps**

- **Sin manejadores globales de 404 y 500.** El único `errorhandler` registrado es el de
  `CSRFError`. Con `debug=True` (S7), una excepción no prevista devuelve el traceback de
  Werkzeug —código fuente, variables locales y consola interactiva—, que es el ejemplo de
  "errores que exponen información" del propio OWASP.
- **El rollback es puntual, no general.** `register()` sí hace `db.rollback()` explícito
  ante un `IntegrityError`, que es el único fallo previsto. Para cualquier excepción **no**
  prevista a media escritura, lo que salva la consistencia es que la conexión se cierra en
  `teardown_appcontext` y SQLite descarta lo no confirmado. En la práctica no queda
  escritura a medias, pero es un efecto secundario del cierre y no un manejo deliberado, y
  ninguna prueba recorre ese camino.
- **Sin límites de recursos** (ver A06): nada impide peticiones desmesuradas ni agota
  presupuesto antes de que el servidor lo haga.
- **Ningún 500 se audita.** Si una excepción no prevista ocurriera, el log de auditoría no
  lo registraría: `audit()` solo se llama en caminos que el código previó.

---

## 4. Qué sale de aquí

**Candidatos para Fase 3 (autoevaluación ASVS Level 1), por orden de valor:**

1. **Cabeceras de seguridad**, empezando por `Referrer-Policy`, que acota un riesgo
   residual ya registrado (R11) con una línea de configuración.
2. **Comprobación contra contraseñas filtradas** (A07). Es lo que ASVS L1 pide y hoy no
   está.
3. **Configuración de producción**: sin `debug=True`, con servidor WSGI y TLS. Convierte
   en reales tres controles que hoy son declarativos.
4. **Manejadores globales de error** que no filtren y que **auditen** (A10, A09).
5. **SBOM y `--require-hashes`** (A03, A08).
6. **Algo que lea el log** (A09), aunque sea un script con umbrales. Hoy el registro no
   tiene lector.
7. **Threat model** formal (A06), ya comprometido en el Charter.

**Riesgos del registro que este recorrido confirma sin cambios:** R10 residual (sin límite
por IP), R11 residuales (sin límite de tasa, token en URL), R12 (secreto TOTP sin cifrar),
R13 (sin códigos de respaldo), R14 residual (contraseña en el campo "Usuario").

**Lo que este recorrido añade al inventario y no estaba en ningún lado:** la ausencia de
cabeceras de seguridad, la ausencia de alerting y de rotación del log, la falta de
manejadores globales de error, la falta de verificación por hash de las dependencias, y
que `@login_required` depende de que alguien se acuerde de escribirlo.

---

*Documento de la Fase 2, WBS 4.5.6. Se revisa en el cierre de fase (4.6) y alimenta la
autoevaluación ASVS Level 1 de la Fase 3.*
