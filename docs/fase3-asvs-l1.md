# Autoevaluación contra OWASP ASVS Level 1

**Fase:** 3 — Stretch Goal ASVS Level 1
**Paquete:** WBS 5.3
**Fecha:** 25 de septiembre de 2026
**Preparado por:** Lorenzo Mtz

> **Estado:** completo. **Re-evaluado tras la Fase 4** (WBS 6.8.1): seis requisitos
> pasaron de `fail` a `pass`. El recorrido de la sección 6 conserva la evaluación
> **original de la Fase 3** y cada requisito afectado lleva su nota de re-evaluación;
> el resultado actualizado está en la sección 8. No se reescribe la evaluación
> inicial: un documento de auditoría que se sobrescribe deja de poder mostrar qué
> se corrigió.

> **Esta fase documenta, no corrige** (Charter, cambio #5). Un requisito en `fail`
> documentado con su evidencia **cumple** el criterio de aceptación del Scope Statement.
> Las correcciones se proponen como fase aparte en 5.4.3.

---

## 1. Origen del estándar y reproducibilidad (WBS 5.3.1)

No se trabajó sobre listas de terceros ni de memoria. El estándar se obtuvo de su repositorio oficial:

| | |
|---|---|
| **Versión** | OWASP ASVS **5.0.0** (Charter, Sección 10, cambio #5) |
| **Archivo** | `OWASP_Application_Security_Verification_Standard_5.0.0_en.csv` |
| **Origen** | `https://raw.githubusercontent.com/OWASP/ASVS/master/5.0/docs_en/OWASP_Application_Security_Verification_Standard_5.0.0_en.csv` |
| **SHA-256** | `98c8fe911b9edb403af8ee05d3ce8201ecac2659e313b053890a62847cdcf680` |
| **Obtenido** | 25 de septiembre de 2026 |

El CSV **no se versiona en este repositorio**: es contenido de OWASP con su propia licencia. Se registran la URL y el hash para que cualquiera pueda reproducir exactamente el mismo punto de partida y comprobar que evaluó contra el mismo texto.

Columnas del archivo: `chapter_id`, `chapter_name`, `section_id`, `section_name`, `req_id`, `req_description`, `L`. El filtrado es `L == "1"`.

### El número

| | Requisitos |
|---|---|
| ASVS 5.0.0 completo | **345** |
| Nivel 1 | **70** |
| Nivel 2 | 183 |
| Nivel 3 | 92 |

Reparto de los 70 de nivel 1 por capítulo:

| Capítulo | L1 | Total del capítulo |
|---|---|---|
| V1 Encoding and Sanitization | 8 | 30 |
| V2 Validation and Business Logic | 4 | 13 |
| V3 Web Frontend Security | 8 | 31 |
| V4 API and Web Service | 2 | 16 |
| V5 File Handling | 4 | 13 |
| V6 Authentication | 13 | 47 |
| V7 Session Management | 6 | 19 |
| V8 Authorization | 4 | 13 |
| V9 Self-contained Tokens | 4 | 7 |
| V10 OAuth and OIDC | 5 | 36 |
| V11 Cryptography | 3 | 24 |
| V12 Secure Communication | 3 | 12 |
| V13 Configuration | 1 | 21 |
| V14 Data Protection | 2 | 13 |
| V15 Secure Coding and Architecture | 3 | 21 |
| **V16 Security Logging and Error Handling** | **0** | 17 |
| V17 WebRTC | 0 | 12 |

### V16 no tiene ni un requisito de nivel 1

Merece señalarse porque **valida el orden de ejecución de la fase**. El capítulo de registro y manejo de errores no aporta nada a Level 1: el estándar no pregunta a este nivel por integridad del log, ni por rotación, ni por trazabilidad de acciones.

Si esta autoevaluación se hubiera hecho **antes** del threat model, **R18 no habría aparecido nunca** — el riesgo de que el registro de auditoría no sostenga no repudio. Invertir el orden (Charter, cambio #5) no fue una preferencia de estilo: fue lo que hizo visible un riesgo que este checklist, por diseño, no ve.

---

## 2. Triaje por capítulo (WBS 5.3.2)

**Tres estatus, no dos.** *No aplica* significa que el requisito no tiene dónde ocurrir en esta arquitectura. *Fuera del alcance* significa que sí aplicaría y **no está cubierto**: es un gap real, no una exención. Colapsar los dos convertiría una carencia en una dispensa, que es justamente el riesgo R15.

| Cap | L1 | Estatus | Argumento |
|---|---|---|---|
| V1 | 8 | **Aplica** | Hay salida HTML dinámica y consultas a base de datos |
| V2 | 4 | **Aplica** | Hay validación de entrada y un flujo multipaso (login → MFA) |
| V3 | 8 | **Aplica** | Es una aplicación servida a navegadores, con cookies |
| V4 | 2 | **Aplica en parte** | `V4.1.1` (`Content-Type` correcto con charset) aplica a **toda** respuesta con cuerpo, no solo a APIs. `V4.4.1` no: no hay WebSockets |
| V5 | 4 | **No aplica** | La aplicación no acepta, genera ni sirve archivos. Los cuatro requisitos hablan de subida y de rutas construidas con nombres de archivo |
| V6 | 13 | **Aplica** | Es el núcleo del producto |
| V7 | 6 | **Aplica** | Gestión de sesión propia |
| V8 | 4 | **Aplica** | Hay rutas protegidas y un decorador de autorización |
| V9 | 4 | **Aplica** | **La cookie de sesión de Flask es un token autocontenido**: va firmada, lleva su propio estado y el servidor la valida sin consultar nada. Que no sea un JWT no la excluye |
| V10 | 5 | **No aplica** | Los cinco describen el comportamiento de un *authorization server* OAuth. No hay proveedor de identidad externo ni flujos delegados |
| V11 | 3 | **Aplica en parte** | `V11.4.1` (funciones hash aprobadas) aplica. `V11.3.1` y `V11.3.2` son de cifrado simétrico por bloques: la aplicación **no cifra nada** — hashea, firma y compara |
| V12 | 3 | **Fuera del alcance** | Los tres son de TLS. No son inaplicables a una aplicación web: es que **no hay despliegue** (Scope Statement, Sección 4). Es la Raíz 1 del threat model, con cinco amenazas colgando |
| V13 | 1 | **Fuera del alcance** | `V13.4.1` exige desplegar sin metadatos de control de versiones accesibles. Sin despliegue no se puede verificar, y con despliegue sería obligatorio |
| V14 | 2 | **Aplica** | Hay datos sensibles en tránsito y estado en el cliente |
| V15 | 3 | **Aplica** | Hay dependencias de terceros y respuestas que devuelven datos de objetos |
| V16 | 0 | — | Sin requisitos de nivel 1 |
| V17 | 0 | — | Sin requisitos de nivel 1 |

### Resultado del triaje

| | Requisitos |
|---|---|
| **A evaluar con evidencia** | **54** |
| No aplican a esta arquitectura | 12 |
| Fuera del alcance del proyecto | 4 |
| **Total nivel 1** | **70** |

Los 12 que no aplican: V5 completo (4), V10 completo (5), `V4.4.1` (1), `V11.3.1` y `V11.3.2` (2).
Los 4 fuera del alcance: V12 completo (3) y `V13.4.1` (1).

---

## 3. Punto de decisión: nivel de detalle (WBS 5.3.3)

El WBS dejó este paquete sin detallar a propósito, porque planear el recorrido sobre una estimación habría sido planear contra un número inventado. La estimación previa era "del orden de cientos"; **el número real es 70, y 54 después del triaje**.

**Decisión: evaluación completa, con evidencia por requisito, sin recortes de alcance.**

No hacen falta las palancas de reducción que se habían considerado. Se conserva una sola por eficiencia, no por necesidad: **la evidencia se agrupa por control** en la tabla de 5.3.4, y cada requisito apunta a ella en vez de repetir archivo y línea. Muchos requisitos de sesión se satisfacen con el mismo `session_version` más los dos timeouts, y muchos de contraseña con bcrypt más la política de longitud.

El recorrido de 5.3.5 se organiza en **cuatro bloques con un commit cada uno**, que es el patrón que funcionó en la Fase 2:

| Bloque | Capítulos | Requisitos |
|---|---|---|
| 1 | V6, V7 — autenticación y sesión | 19 |
| 2 | V8, V9, V14 — autorización, tokens y datos | 10 |
| 3 | V1, V2, V3 — codificación, validación y frontend | 20 |
| 4 | V4, V11, V15 — el resto | 5 |

---

## 4. Lo que el triaje ya dejó ver

Leer los 70 requisitos para clasificarlos adelantó tres hallazgos. Se confirmarán con evidencia en 5.3.5; se anotan aquí porque dos de ellos **no los había detectado ningún ejercicio anterior**.

**`V6.2.2` — "Verify that users can change their password". Falla.** La aplicación **no tiene cambio de contraseña autenticado**. Las rutas son `register`, `login`, `logout`, `dashboard`, `forgot-password`, `reset-password` y las dos de MFA: un usuario con sesión abierta que quiera cambiar su contraseña tiene que pasar por el flujo de recuperación por correo. Arrastra a `V6.2.3`, que exige pedir la contraseña actual además de la nueva.

Es el hallazgo más interesante del triaje porque **no es un control ausente, es una funcionalidad ausente**. Ni el recorrido del Top 10 ni el threat model podían verlo: ambos evalúan lo que existe, y ninguno pregunta qué falta.

**`V3.3.1` — prefijo de cookie. Falla.** Exige que la cookie lleve el atributo `Secure` —que sí está— **y** que su nombre use el prefijo `__Host-` o `__Secure-`. La cookie se llama `session`, sin prefijo. Es una línea de configuración.

**`V14.2.1` — "sensitive data ... the URL and query string do not contain sensitive data". Falla.** Confirma como incumplimiento explícito de nivel 1 lo que hasta ahora era un riesgo residual de R11 y la amenaza TM-34: el token de recuperación viaja en el path.

---

## 5. Controles implementados y su evidencia (WBS 5.3.4)

Esta tabla existe para **no repetir la evidencia requisito por requisito**. Cada control tiene un identificador `Cnn`; el recorrido de 5.3.5 cita esos identificadores en lugar de volver a escribir archivo, línea y prueba.

La columna **Evidencia** distingue dos cosas que no valen lo mismo:

- **Prueba** — hay una prueba automatizada que se pone en rojo si el control se rompe. Verificado con *mutation testing* al cerrar cada paquete (LL14).
- **Revisión** — el control está en el código y se leyó, pero **ninguna prueba lo atrapa**. No es lo mismo, y mezclarlos sería justo el autoengaño que R15 previene.

La suite son **90 pruebas**: `test_audit.py` 13, `test_bruteforce.py` 8, `test_csrf.py` 12, `test_mfa.py` 28, `test_password_reset.py` 14, `test_session.py` 9, `test_session_expiry.py` 6.

### Contraseñas

| ID | Control | Dónde | Evidencia |
|---|---|---|---|
| C01 | Hash con **bcrypt cost 12** (`SALT = 12`); nunca se guarda la contraseña | `auth.py:18`, `register()` | Prueba + comprobación directa en SQLite (4.6.1) |
| C02 | Política de longitud **12–64 caracteres, máximo 72 bytes** (límite real de bcrypt), sin reglas de composición | `validar_password()`, `auth.py:23` | Prueba (`test_password_reset.py`, función compartida) |
| C03 | `bcrypt.checkpw` contra `DUMMY_HASH` cuando no hay usuario o la cuenta está bloqueada, para igualar la **latencia** | `auth.py:19`, `login()` | Prueba — medido 371 ms vs 340 ms, ratio 1.09 |
| C04 | La contraseña se verifica **tal como llega**: la política rechaza más de 72 bytes en vez de truncar | `validar_password()` | Revisión |

### Protección contra fuerza bruta

| ID | Control | Dónde | Evidencia |
|---|---|---|---|
| C05 | **5 fallos / 15 minutos** por nombre de usuario enviado, ventana deslizante, nunca permanente | `throttle.py`, `config.py` | Prueba (8 en `test_bruteforce.py`) |
| C06 | El guard va **antes** de buscar el usuario y de validar la contraseña: la contraseña correcta no vence el bloqueo | `login()` | Prueba + 4.6.1 sobre HTTP real |
| C07 | El intento bloqueado **se audita pero no se cuenta**, para que nadie prolongue el bloqueo de otro | `login()` | Prueba — `MAX(id)` sin cambios tras tres intentos bloqueados |
| C08 | `login_attempts` **sin `FOREIGN KEY`** a `users`, para contar también cuentas inexistentes | `schema.sql` | Prueba |

### Gestión de sesión

| ID | Control | Dónde | Evidencia |
|---|---|---|---|
| C09 | Cookie de sesión **firmada** con `SECRET_KEY`; el cliente no puede alterar su contenido | Flask + `config.py` | Prueba (mutación de `login_at` en 4.5.4) |
| C10 | `HttpOnly`, `Secure`, `SameSite=Strict` | `config.py` | Prueba + cabecera `Set-Cookie` cruda en 4.6.1 |
| C11 | **Revocación server-side** con `session_version`: se valida en cada petición protegida y sube en logout y en cambio de contraseña | `schema.sql`, `decorators.py`, `auth.py` | Prueba (cookie copiada antes del logout deja de servir) |
| C12 | El `UPDATE` del logout lleva `AND session_version = ?`: una cookie vieja no cierra sesiones nuevas | `logout()` | Prueba |
| C13 | **Expiración por inactividad**: 60 minutos | `PERMANENT_SESSION_LIFETIME` | Prueba + `Expires` observado en 4.6.1 |
| C14 | **Vida máxima**: 12 horas desde el login, que la actividad **no** renueva | `SESSION_ABSOLUTE_LIFETIME_SECONDS`, `decorators.py` | Prueba (`test_la_actividad_no_renueva_el_tope`) |
| C15 | Ausencia de `login_at` tratada como sesión vencida (*fail-closed*) | `decorators.py` | Prueba |
| C16 | `session.clear()` antes de escribir la sesión nueva, contra *session fixation* | `login()`, `mfa_verify()` | Prueba |

### Autorización

| ID | Control | Dónde | Evidencia |
|---|---|---|---|
| C17 | `@login_required` en toda ruta protegida | `decorators.py` | Prueba |
| C18 | El `SELECT` del decorador lista **columnas explícitas y no `*`**, para que `totp_secret` no quede en `g.user` | `decorators.py` | Revisión |
| C19 | La **sesión pendiente de MFA no lleva `user_id`**, así que el guard la rechaza igual que a un visitante | `login()`, `mfa_verify()` | Prueba + 4.6.1 sobre HTTP real |
| C20 | La sesión pendiente **caduca a los 5 minutos** | `MFA_PENDING_LIFETIME_SECONDS` | Prueba |

### Segundo factor (TOTP)

| ID | Control | Dónde | Evidencia |
|---|---|---|---|
| C21 | Algoritmo de `pyotp` (RFC 6238), no implementación propia | `mfa.py` | Prueba |
| C22 | Tolerancia de **±1 periodo** de 30 segundos | `TOTP_VALID_WINDOW`, `mfa.py:82` | Prueba (reloj inyectado con `ahora=`) |
| C23 | **Rechazo de reutilización**: `verificar_codigo()` devuelve el periodo aceptado y se exige que sea estrictamente mayor que `last_mfa_timecode` | `mfa.py:82`, `schema.sql` | Prueba + 4.6.1 + prueba manual 4.3.6 con Google Authenticator |
| C24 | **`hmac.compare_digest`** para comparar el código, con filtro de formato previo | `mfa.py` | **Revisión** — ninguna prueba lo atrapa (medido, LL22) |
| C25 | MFA se activa **solo tras validar un primer código**; el código de activación queda consumido | `mfa_setup()` | Prueba |
| C26 | La contraseña correcta **no reinicia** el contador de intentos cuando hay MFA | `login()` | Prueba |
| C27 | El QR se embebe como **`data:` URI**, no se sirve desde una ruta propia | `qr_data_uri()`, `mfa.py:64` | Revisión |

### Recuperación de contraseña

| ID | Control | Dónde | Evidencia |
|---|---|---|---|
| C28 | Token de `secrets.token_urlsafe(32)` — 256 bits de un CSPRNG | `reset_tokens.py:17` | Prueba |
| C29 | En la base solo el **SHA-256** del token; un token nuevo borra los anteriores del usuario | `reset_tokens.py` | Prueba |
| C30 | **Un solo uso** (`used_at`) y vigencia de **30 minutos**, calculada por SQLite | `reset_tokens.py`, `config.py` | Prueba + 4.6.1 sobre HTTP real |
| C31 | Respuesta **idéntica** exista o no el email: mismo código, mismo destino, mismo HTML | `forgot_password()` | Prueba (LL15) |
| C32 | Al consumirse, contraseña y `session_version + 1` en la **misma sentencia**; se reinicia el contador de intentos | `reset_password_submit()` | Prueba |
| C33 | El enlace **no sale** por la respuesta HTTP ni por `audit.log`: solo por consola. El GET del token no audita | `mailer.py`, `auth.py:251` | Prueba |

### Entrada y salida

| ID | Control | Dónde | Evidencia |
|---|---|---|---|
| C34 | **Consultas parametrizadas** en todo el código; ni una concatenación de SQL | Todo `src/` | Revisión (verificada por búsqueda) + prueba indirecta |
| C35 | **Autoescape de Jinja2** en todas las plantillas | `src/templates/` | Revisión |
| C36 | Validación de formato de email con `email-validator`, normalizado a minúsculas | `register()` | Revisión |
| C37 | Campos de contraseña con `type="password"` en las cuatro plantillas que los usan | `src/templates/` | Revisión |
| C38 | **CSRF global** con `CSRFProtect`, y `/logout` solo por `POST` | `app.py`, `auth.py:184` | Prueba (12 en `test_csrf.py`) |
| C39 | `PRAGMA foreign_keys = ON` en cada conexión | `database.py` | Revisión |

### Auditoría

| ID | Control | Dónde | Evidencia |
|---|---|---|---|
| C40 | **Catálogo cerrado de 15 eventos**; `audit()` lanza `ValueError` ante uno no catalogado | `audit.py` | Prueba |
| C41 | La firma de `audit()` **no acepta campos libres**: no hay por dónde pasarle un secreto | `audit.py` | Revisión — es una propiedad de la firma, no del flujo |
| C42 | Una línea JSON por evento, con `json.dumps` escapando saltos y comillas, y `username` recortado a 64 | `audit.py` | Prueba (*log injection* con un `login_success` falso) |
| C43 | Eventos que distinguen señales, no solo resultados: `login_blocked` ≠ `login_failure`, `session_expired` ≠ `session_rejected`, `mfa_required` propio | `audit.py` | Prueba (conteos por evento) |

### Configuración y cadena de suministro

| ID | Control | Dónde | Evidencia |
|---|---|---|---|
| C44 | **`SECRET_KEY` obligatoria**: la app se niega a arrancar si falta, es la de ejemplo o mide menos de 32 caracteres | `validate_secret_key()`, `app.py` | **Revisión** — sin prueba (deuda anotada en `tests/README.md`) |
| C45 | Versiones fijadas con `==`; herramientas de desarrollo en `requirements-dev.txt` | `requirements*.txt` | Revisión |
| C46 | **`pip-audit` 2.10.1: 0 vulnerabilidades** sobre los 22 paquetes del entorno, más `pip` | WBS 4.5.5 | Auditoría reproducible (hash y URL registrados) |
| C47 | `.env`, `*.db`, `*.key`, `*.pem` y `*.log` fuera del repositorio | `.gitignore` | Revisión |

### Los dos controles sin prueba

Se señalan aparte porque son los que este documento **no puede respaldar con evidencia automatizada**, y decirlo es parte del ejercicio:

- **C24** (`hmac.compare_digest` en la comparación de códigos TOTP). Medido con una mutación: sustituirlo por `==` **pasa las 28 pruebas de MFA**. Medir microsegundos sobre seis dígitos dentro del mismo proceso no da señal estable, a diferencia de los ~330 ms de bcrypt que sí sostienen C03. Documentado en el código, en `tests/README.md` y en el Risk Register (LL22).
- **C44** (`validate_secret_key`). Es una función pura y serían cuatro asertos; simplemente no se escribieron. Es deuda de cobertura, no una limitación.

---

## 6. Recorrido por requisito (WBS 5.3.5)

**Estatus: `pass` o `fail`**, como pide el criterio de aceptación del Scope Statement. No hay estatus intermedio: un control que cubre parte del requisito y deja el resto **es un `fail`**, con la nota explicando qué sí está. Suavizarlo a "parcial" convertiría el documento en el ejercicio de auto-aprobación que R15 previene.

Los identificadores `Cnn` remiten a la tabla de controles de la sección 5.

### Bloque 1 — V6 Authentication y V7 Session Management (19 requisitos)

#### V6 Authentication (13)

| Req | Qué exige | Estatus | Evidencia / argumento |
|---|---|---|---|
| V6.1.1 | Que la documentación defina cómo se usan el límite de tasa y la anti-automatización, cómo se configuran y cómo evitan el bloqueo malicioso de cuentas | **pass** | `docs/fase2-notas.md` §4.1 define la política (5 fallos / 15 min, ventana deslizante) y **por qué nunca es permanente**; R10 en el Risk Register cubre el bloqueo malicioso, y C07 lo implementa: el intento bloqueado se audita pero no se cuenta |
| V6.2.1 | Contraseñas de al menos 8 caracteres; 15 muy recomendado | **pass** | C02: mínimo de 12. Cumple el requisito, **por debajo de la recomendación fuerte de 15** |
| V6.2.2 | Que los usuarios puedan cambiar su contraseña | **fail** | **No existe la funcionalidad.** No hay ruta de cambio de contraseña autenticado: las rutas son `register`, `login`, `logout`, `dashboard`, `forgot-password`, `reset-password` y las dos de MFA |
| V6.2.3 | Que el cambio de contraseña pida la actual además de la nueva | **fail** | Consecuencia de V6.2.2: sin funcionalidad, no hay dónde pedirla. El flujo de recuperación sí exige poseer el token, pero eso no es *la contraseña actual* |
| V6.2.4 | Que las contraseñas se comprueben contra al menos las 3000 más filtradas que cumplan la política | **fail** | No hay ninguna comprobación contra listas de contraseñas filtradas. Una contraseña de 12 caracteres puede ser `Password1234` y el registro la acepta |
| V6.2.5 | Que se acepte cualquier composición, sin exigir mayúsculas, números ni símbolos | **pass** | C02: la política es **solo de longitud**, siguiendo NIST SP 800-63B. Decisión de Fase 1, documentada en `docs/fase1-notas.md` |
| V6.2.6 | Que los campos de contraseña usen `type=password` | **pass** | C37: en las cuatro plantillas que los usan |
| V6.2.7 | Que se permitan pegar, los ayudantes del navegador y los gestores externos | **pass** | Nada lo impide: no hay `onpaste`, ni `autocomplete="off"`, ni JavaScript en los formularios de contraseña |
| V6.2.8 | Que la contraseña se verifique **tal como llega**, sin truncar ni transformar | **pass** | C04: la política **rechaza** más de 72 bytes en lugar de truncar al límite de bcrypt, y no hay cambios de caja |
| V6.3.1 | Que existan controles contra *credential stuffing* **y** fuerza bruta, según la documentación | **fail** | C05–C08 cubren la fuerza bruta con evidencia sólida. **El *credential stuffing* no está cubierto**: sin comprobación de contraseñas filtradas (V6.2.4) y sin límite por IP, un atacante con pares usuario/contraseña de otra filtración no acumula fallos en ninguna cuenta. Es el residual de R10 |
| V6.3.2 | Que no haya cuentas por defecto (`root`, `admin`, `sa`) activas | **pass** | El esquema no crea ninguna cuenta: `users` nace vacía y toda cuenta sale de `/register` |
| V6.4.1 | Que los códigos de activación generados por el sistema sean aleatorios seguros, sigan la política y expiren pronto o al usarse | **pass** | C28 (`secrets.token_urlsafe(32)`, 256 bits de un CSPRNG), C30 (30 minutos **y** un solo uso). Y no puede convertirse en contraseña de largo plazo: no es una contraseña, es un token para fijar una |
| V6.4.2 | Que no haya pistas de contraseña ni preguntas secretas | **pass** | No existen; la recuperación es exclusivamente por token al correo |

#### V7 Session Management (6)

| Req | Qué exige | Estatus | Evidencia / argumento |
|---|---|---|---|
| V7.2.1 | Que la verificación del token de sesión la haga un servicio backend de confianza | **pass** | C09: la firma se valida **en el servidor** en cada petición (`open_session` de Flask); el cliente nunca decide si su cookie es válida |
| V7.2.2 | Tokens autocontenidos o de referencia **generados dinámicamente**, no claves estáticas | **pass** | C09: la cookie se genera por sesión con su propio contenido y timestamp. No hay API keys ni secretos estáticos por usuario |
| V7.2.3 | Que los tokens **de referencia**, si se usan, tengan 128 bits de un CSPRNG | **N/A** | Condicional no cumplida: la sesión usa un token **autocontenido** (cookie firmada), no de referencia. El requisito no llega a activarse |
| V7.2.4 | Generar un token nuevo al autenticar, **incluida la reautenticación**, y **terminar el token actual** | **fail** → **pass** *(Fase 4, G3)* | **Se cumple la primera mitad y no la segunda.** `login()` hace `session.clear()` y escribe una sesión nueva (C16), pero **no incrementa `session_version`**. Una cookie capturada antes de volver a autenticarse conserva la misma versión y una firma válida, así que **sigue sirviendo**. `session_version` solo sube en el logout y en el cambio de contraseña por recuperación |
| V7.4.1 | Que al terminar la sesión no se pueda seguir usándola; para tokens autocontenidos, una lista de revocados, rechazar los emitidos antes de cierta fecha por usuario, o rotar la clave por usuario | **pass** | C11: `session_version` es exactamente la variante por usuario que el requisito describe. Verificado con la prueba de la cookie copiada antes del logout (LL5). C13 y C14 cubren además la terminación por expiración |
| V7.4.2 | Terminar todas las sesiones activas cuando una cuenta se deshabilita o se borra | **N/A** | Condicional no cumplida: **no existe funcionalidad** de deshabilitar ni borrar cuentas. Si una fila se borra directamente en la base, `@login_required` rechaza la sesión porque el `SELECT` no devuelve usuario (C17), pero eso es una consecuencia del guard, no una implementación de este requisito |

#### Resultado del bloque 1

| Estatus | Requisitos |
|---|---|
| `pass` | **12** |
| `fail` | **5** |
| N/A por condicional no cumplida | 2 |
| **Total** | **19** |

**Los cinco `fail` son tres problemas, no cinco.**

**1. No hay cambio de contraseña autenticado** (V6.2.2, V6.2.3). Es una **funcionalidad ausente**, no un control débil, y por eso ningún ejercicio anterior podía verla: el recorrido del Top 10 y el threat model evalúan lo que existe. Hoy un usuario con sesión abierta que quiera cambiar su contraseña tiene que pasar por el correo de recuperación, lo que además obliga a exponer un token al portador para una operación que no lo necesita.

**2. Nada frena el *credential stuffing*** (V6.2.4, V6.3.1). El contador de 4.1 detiene la fuerza bruta contra *una* cuenta, pero no ayuda contra un atacante que prueba una contraseña filtrada en muchas cuentas: ninguna acumula fallos. La comprobación contra las 3000 peores contraseñas es la mitad barata del arreglo; el límite por IP es la otra.

**3. La reautenticación no invalida la sesión anterior** (V7.2.4). **Hallazgo nuevo de este recorrido.** El proyecto construyó `session_version` precisamente para poder revocar (LL5, R9) y lo aplica en el logout y en el cambio de contraseña, pero **no al volver a autenticarse**. El escenario concreto: alguien copia la cookie de un usuario; el usuario vuelve a iniciar sesión —incluso por sospechar algo— y la cookie robada **sigue funcionando**, porque la versión no cambió. Es una línea en `login()`, y el mecanismo para arreglarlo ya existe.

Ese tercero es el tipo de hallazgo que justifica hacer el checklist además del threat model: el modelo dio por cubierta la revocación porque el mecanismo existe, y el estándar pregunta por el **momento** en que se aplica.

### Bloque 2 — V8 Authorization, V9 Self-contained Tokens y V14 Data Protection (10 requisitos)

#### V8 Authorization (4)

| Req | Qué exige | Estatus | Evidencia / argumento |
|---|---|---|---|
| V8.1.1 | Que la documentación de autorización defina las reglas de acceso a nivel de función y de dato, según permisos del consumidor y atributos del recurso | **pass** | El modelo es binario —anónimo o autenticado— y está **enunciado explícitamente**, no supuesto: `docs/fase2-owasp-top10.md` §A01 declara que hay una sola ruta protegida, que no hay roles ni recursos direccionables, y que eso es *un hecho del alcance y no un control*. El threat model lo repite en F1 y F4. Pasa **porque el modelo es trivial y está escrito**; en cuanto aparezca un segundo rol o un recurso por usuario, este requisito exige un documento de verdad |
| V8.2.1 | Que el acceso a nivel de función esté restringido a consumidores con permiso explícito | **pass** | C17: `@login_required` sobre la única ruta protegida, con validación de `session_version` (C11) y de caducidad (C13, C14). **Nota de robustez:** el control depende de recordar el decorador —no hay *deny by default*—, que es la amenaza TM-21. El requisito pregunta si el acceso *está* restringido, y lo está; TM-21 sigue abierto como riesgo de futuro |
| V8.2.2 | Que el acceso a datos concretos esté restringido, para mitigar IDOR y BOLA | **N/A** | Condicional no cumplida: **no hay acceso a datos direccionables**. Ninguna ruta recibe el identificador de un recurso; `/dashboard` solo muestra datos del propio `g.user`. No hay objeto sobre el que verificar autorización, así que el requisito no llega a activarse |
| V8.3.1 | Que las reglas se apliquen en una capa de servicio de confianza, sin depender de controles que el consumidor pueda manipular | **pass** | C17 y C09: la decisión se toma en el servidor, sobre una cookie firmada que el cliente no puede alterar. **No hay JavaScript en la aplicación**, así que no existe siquiera la tentación de un control de cliente |

#### V9 Self-contained Tokens (4)

La cookie de sesión de Flask **es** un token autocontenido: va firmada, lleva su propio estado y el servidor la valida sin consultar nada externo. Que no sea un JWT no la excluye de este capítulo — y de hecho es donde el proyecto sale mejor parado de toda la autoevaluación.

| Req | Qué exige | Estatus | Evidencia / argumento |
|---|---|---|---|
| V9.1.1 | Validar el token por su firma o MAC **antes** de aceptar su contenido | **pass** | C09: `open_session` de Flask verifica la firma y, si falla, devuelve una sesión vacía; el contenido nunca se lee sin validar. Se comprobó por mutación en 4.5.4 al manipular `login_at` |
| V9.1.2 | Que solo se usen algoritmos de una lista blanca, **sin `None`**, evitando la confusión de claves | **pass** | El algoritmo lo fija el servidor (HMAC con SHA-1, `key_derivation = "hmac"` en `SecureCookieSessionInterface`) y **el token no lleva campo de algoritmo**: no hay negociación que envenenar. El ataque clásico de `alg: none` de JWT **no tiene superficie aquí**, y al ser solo simétrico tampoco hay confusión simétrico/asimétrico. *Ver V11.4.1 en el bloque 4 para la valoración de SHA-1 como función hash* |
| V9.1.3 | Que el material de clave venga de fuentes preconfiguradas de confianza, sin que el atacante pueda indicar otras | **pass** | La clave es `SECRET_KEY`, leída de `.env` al arrancar. El token **no lleva cabeceras que apunten a una fuente de clave** —el equivalente a `jku`, `x5u` o `jwk` de JWS no existe—, así que no hay nada que un atacante pueda señalar. C44 además obliga a que la clave exista y sea fuerte, o la aplicación no arranca |
| V9.2.1 | Que, si el token lleva una ventana de validez, se acepte solo dentro de ella | **pass** | C13: `open_session` valida `max_age` contra el timestamp **que va dentro de la firma**, no contra el `Expires` de la cookie —que el cliente puede ignorar—. Este es exactamente el mecanismo que se investigó en 4.5.4, y de paso el que reveló que `SESSION_REFRESH_EACH_REQUEST` lo convertía en inactividad y no en vida máxima (LL23). C14 añade el tope absoluto que el estándar no exige aquí |

#### V14 Data Protection (2)

| Req | Qué exige | Estatus | Evidencia / argumento |
|---|---|---|---|
| V14.2.1 | Que los datos sensibles viajen solo en el cuerpo o en cabeceras, y que **la URL no contenga información sensible** como una clave o un token de sesión | **fail** | **El token de recuperación viaja en el path**: `/reset-password/<token>`. Es un token al portador de 256 bits que queda en el historial del navegador, en los registros de cualquier proxy y expuesto a filtrarse por `Referer`. Ya estaba registrado como riesgo residual de R11 y como amenaza TM-34; aquí es un incumplimiento explícito de nivel 1. Mitigación conocida: mover el token al cuerpo de un POST, o al menos emitir `Referrer-Policy` |
| V14.3.1 | Que los datos autenticados se borren del almacenamiento del cliente al terminar la sesión | **pass** | No hay dónde acumularlos: la aplicación **no usa JavaScript**, así que no hay `localStorage`, `sessionStorage` ni estado en el DOM. El único almacén en el cliente es la cookie, y al hacer logout `session.clear()` la deja vacía, con lo que Flask emite un `delete_cookie` en lugar de renovarla (verificado en `save_session`). No se envía `Clear-Site-Data`, pero el requisito la ofrece como ayuda opcional, no como obligación |

#### Resultado del bloque 2

| Estatus | Requisitos |
|---|---|
| `pass` | **8** |
| `fail` | **1** |
| N/A por condicional no cumplida | 1 |
| **Total** | **10** |

**V9 pasa entero, y no por casualidad.** Los cuatro requisitos describen las formas clásicas de romper un token autocontenido —aceptar el contenido sin validar la firma, dejar que el token elija el algoritmo, dejar que señale la clave, ignorar la ventana de validez— y ninguna tiene superficie aquí. Dos de los cuatro se pueden sostener con evidencia propia del proyecto y no solo con "lo hace Flask": la validación de la firma y la de `max_age` se verificaron por mutación en 4.5.4.

Conviene decir de dónde viene ese resultado: **el proyecto no eligió este diseño, lo heredó de Flask**. Lo que sí es mérito propio es haber ido a leer `open_session` y `should_set_cookie` en lugar de confiar en el nombre de la configuración, que es lo que hizo que `max_age` se entendiera de verdad.

**El único `fail` ya se conocía por tres caminos distintos** —R11, TM-34 y ahora V14.2.1—, lo que refuerza su prioridad en 5.4.1: es el hallazgo que más veces ha aparecido y sigue sin atenderse.

**Un N/A que conviene releer más adelante.** V8.2.2 no aplica porque no hay recursos direccionables. El día que exista `/perfil/<id>`, este requisito pasa a ser el más importante del capítulo y no habrá nada construido para cumplirlo.

### Bloque 3 — V1 Encoding, V2 Validation y V3 Web Frontend (20 requisitos)

#### V1 Encoding and Sanitization (8)

| Req | Qué exige | Estatus | Evidencia / argumento |
|---|---|---|---|
| V1.2.1 | Codificación de salida adecuada al contexto (elemento HTML, atributo, comentario, CSS, cabecera) para no alterar la estructura del documento | **pass** | C35: autoescape de Jinja2 en todas las plantillas, que escapa según contexto HTML. No se construyen cabeceras HTTP con datos del usuario |
| V1.2.2 | Codificar datos no confiables al construir URLs, y permitir solo protocolos seguros (nada de `javascript:` ni `data:`) | **pass** | Las URLs se construyen con `url_for()`, que codifica los parámetros de ruta. **Matiz que conviene declarar:** la aplicación **sí** usa un `data:` URI —el QR del enrolamiento— pero lo **genera el servidor** a partir de un secreto propio, no de entrada del usuario. El requisito habla de datos no confiables; aquí no los hay |
| V1.2.3 | Codificar al construir contenido JavaScript o JSON, para evitar inyección | **N/A** | Condicional no cumplida: **no hay JavaScript en la aplicación** ni se sirve JSON a ningún cliente. El único JSON que se construye es el registro de auditoría, y ahí el escapado sí existe (C42) — pero es un archivo, no una respuesta |
| V1.2.4 | Consultas parametrizadas, ORM o equivalente frente a inyección SQL | **pass** | C34: consultas parametrizadas en todo el código, sin una sola concatenación. Verificado por búsqueda sobre `src/` |
| V1.2.5 | Protección frente a inyección de comandos del sistema operativo | **N/A** | Condicional no cumplida: la aplicación **no hace ninguna llamada al sistema**. Verificado: no hay `os.system`, `subprocess`, `eval`, `exec` ni `__import__` |
| V1.3.1 | Sanear HTML no confiable procedente de editores WYSIWYG o similares | **N/A** | Condicional no cumplida: no se acepta HTML en ningún campo |
| V1.3.2 | Evitar `eval()` y otras formas de ejecución dinámica de código | **pass** | No existe ninguna: verificado por búsqueda en todo `src/` |
| V1.5.1 | Configurar los parsers XML de forma restrictiva, con entidades externas deshabilitadas (XXE) | **N/A** | Condicional no cumplida: la aplicación **no parsea XML**. El único XML que aparece es el SVG del QR, que el servidor **genera** y nunca lee |

#### V2 Validation and Business Logic (4)

| Req | Qué exige | Estatus | Evidencia / argumento |
|---|---|---|---|
| V2.1.1 | Que la documentación defina reglas de validación de entrada: cómo comprobar cada dato contra una estructura esperada | **fail** → **pass** *(Fase 4, G6)* | Hay reglas documentadas para **dos** de los tres datos de entrada: la política de contraseñas (`docs/fase1-notas.md`) y el formato de email (C36, vía `email-validator`). **Del nombre de usuario no hay regla escrita porque no hay regla**: el único control es que no esté vacío |
| V2.2.1 | Validar la entrada contra expectativas de negocio, con lista blanca de valores, patrones y rangos | **fail** → **pass** *(Fase 4, G6)* | El `username` se acepta tal cual, sin lista blanca, sin patrón y sin longitud máxima. Es la raíz de **LL20**: se comprobó que alguien puede registrarse literalmente como `mfa:ana`, que fue lo que descartó usar prefijos como espacio de nombres en el contador de intentos. La contraseña y el email sí cumplen |
| V2.2.2 | Que la validación se aplique en una capa de servicio de confianza, sin depender de la del cliente | **pass** | Toda la validación ocurre en el servidor. **No hay JavaScript**, así que no existe validación de cliente en la que apoyarse ni siquiera por accidente |
| V2.3.1 | Procesar los flujos de negocio en el orden esperado, sin saltarse pasos | **pass** | El login en dos pasos lo impone la **sesión pendiente**: sin el paso 1 no hay `pending_mfa_user_id` y `/mfa` rechaza; sin el paso 2 no hay `user_id` y `@login_required` rechaza (C19, C20). Verificado sobre HTTP real en 4.6.1. El flujo de recuperación exige un token válido y no reutilizable (C30) |

#### V3 Web Frontend Security (8)

| Req | Qué exige | Estatus | Evidencia / argumento |
|---|---|---|---|
| V3.2.1 | Controles que impidan al navegador interpretar una respuesta en el contexto equivocado (`Sec-Fetch-*`, `sandbox` de CSP, `Content-Disposition`) | **fail** → **pass** *(Fase 4, G1)* | No se emite **ninguno** de los tres mecanismos, ni `X-Content-Type-Options: nosniff`. Es el gap A02 del recorrido del Top 10 |
| V3.2.2 | Que el contenido destinado a mostrarse como texto use funciones de render seguras (`textContent`, `createTextNode`) | **N/A** | Condicional no cumplida: no hay render del lado del cliente. El equivalente en servidor es el autoescape de V1.2.1 |
| V3.3.1 | Cookies con atributo `Secure` **y**, si no se usa el prefijo `__Host-`, el prefijo `__Secure-` en el nombre | **fail** → **pass, con reserva** *(Fase 4, G2)* | **Se cumple la mitad.** C10 pone `Secure`, pero la cookie se llama `session`, sin prefijo. El prefijo es lo que impide que un subdominio —o un atacante en HTTP plano— sobrescriba la cookie: sin él, `Secure` protege la lectura pero no la **escritura** |
| V3.4.1 | Cabecera `Strict-Transport-Security` en todas las respuestas, con `max-age` de al menos un año | **fail** | No se emite. Es el gap A02, y sin TLS tampoco tendría efecto: pertenece a la Raíz 1 del threat model |
| V3.4.2 | Que `Access-Control-Allow-Origin` sea un valor fijo o se valide contra una lista blanca | **N/A** | Condicional no cumplida: la aplicación **no configura CORS** y no emite esa cabecera, así que rige la política de mismo origen del navegador sin modificaciones. La ausencia es el estado seguro |
| V3.5.1 | Que, si **no** se depende del preflight de CORS, las peticiones a funcionalidad sensible se validen como originadas en la propia aplicación (tokens anti-falsificación o cabeceras no incluidas en la lista segura de CORS) | **pass** | Es exactamente el caso: no se depende del preflight, y C38 aplica **tokens CSRF en todos los POST** mediante `CSRFProtect` global, con 12 pruebas propias. `SameSite=Strict` (C10) refuerza |
| V3.5.2 | Que, si **sí** se depende del preflight, no se pueda invocar la funcionalidad con una petición que no lo dispare | **N/A** | Condicional no cumplida: no se depende del preflight (ver V3.5.1) |
| V3.5.3 | Que la funcionalidad sensible use métodos como `POST`, y no métodos "seguros" como `GET` | **pass** | Registro, login, recuperación, cambio de contraseña, enrolamiento y verificación de MFA son `POST`. **`/logout` se convirtió a `POST` en 4.5.3** precisamente por esto. El único `GET` del flujo de recuperación solo muestra el formulario; el cambio va por `POST` |

#### Resultado del bloque 3

| Estatus | Requisitos |
|---|---|
| `pass` | **8** |
| `fail` | **5** |
| N/A por condicional no cumplida | **7** |
| **Total** | **20** |

**Siete N/A de veinte, y la razón es una sola: la aplicación es deliberadamente mínima.** Sin JavaScript, sin XML, sin llamadas al sistema, sin subida de archivos, sin CORS. Cada una de esas ausencias hace evaporarse un requisito entero. Es un resultado honesto —la superficie de ataque es pequeña **por construcción**— pero conviene no leerlo como mérito de seguridad: no se defendió nada, sencillamente no hay nada que defender. El día que entre una sola línea de JavaScript, tres de estos N/A se reactivan.

También muestra que el **triaje por capítulo es forzosamente grueso**. V1 y V3 se marcaron "aplica" y, a nivel de requisito, la mitad de V1 no aplica. El triaje sirvió para no perder tiempo en V5, V10 y V17; el detalle real solo aparece requisito por requisito.

**Los cinco `fail` son dos problemas.**

**1. No se emite ninguna cabecera de seguridad** (V3.2.1, V3.3.1, V3.4.1). Tres incumplimientos de nivel 1 con la misma causa y el mismo arreglo: un `after_request` que añada las cabeceras. `V3.3.1` es el más barato de todos —renombrar la cookie a `__Host-session`— y el más fácil de pasar por alto, porque `Secure` ya está puesto y parece que el requisito está cubierto. No lo está: el prefijo protege contra **escritura** desde un subdominio, que es un ataque distinto del que cubre `Secure`.

**2. El nombre de usuario no se valida** (V2.1.1, V2.2.1). Esto sube de categoría. Hasta ahora era una nota de **LL20** —se descubrió al ver que `mfa:ana` es registrable, lo que descartó usar prefijos en el contador de intentos— y un gap anotado en A05. Aquí son **dos incumplimientos explícitos de nivel 1**: uno por no tener la regla y otro por no aplicarla. Es el mismo hallazgo contado dos veces por el estándar, lo que indica cuánto le importa.

**Y una confirmación que vale la pena:** `V3.5.1` describe casi literalmente la decisión de 4.5.3 —tokens anti-falsificación para toda funcionalidad sensible cuando no se depende del preflight de CORS— y `V3.5.3` justifica haber movido `/logout` a `POST`. Dos decisiones tomadas por razonamiento propio que coinciden con el estándar.

### Bloque 4 — V4 API, V11 Cryptography y V15 Secure Coding (5 requisitos)

Los tres requisitos descartados en el triaje no se repiten aquí: `V4.4.1` (WebSockets), `V11.3.1` y `V11.3.2` (cifrado simétrico por bloques, que la aplicación no usa porque **no cifra nada**: hashea, firma y compara).

| Req | Qué exige | Estatus | Evidencia / argumento |
|---|---|---|---|
| V4.1.1 | Que toda respuesta con cuerpo lleve `Content-Type` acorde al contenido, **con el parámetro `charset`** | **pass** | Verificado sobre el servidor real, no supuesto: `/login`, `/register` y `/forgot-password` devuelven `text/html; charset=utf-8`, y también lo llevan el **302** de una redirección y el **404** de una ruta inexistente. Es el comportamiento por defecto de Flask, pero se comprobó en la respuesta HTTP |
| V11.4.1 | Que solo se usen funciones hash aprobadas para usos criptográficos —firmas, HMAC, KDF, generación de bits aleatorios— y que **las prohibidas, como MD5, no se usen para ningún propósito criptográfico** | **pass** | Inventario completo de funciones hash en la aplicación: **SHA-256** para el hash del token de recuperación (C29); **bcrypt** para contraseñas (C01); **HMAC-SHA-1** en dos sitios que no elige el proyecto — la firma de la cookie de Flask (`digest_method = sha1`, `key_derivation = "hmac"`) y el TOTP, cuyo algoritmo por defecto fija el RFC 6238. **SHA-1 sigue siendo aceptable dentro de HMAC**: sus debilidades son de colisión y no afectan a la construcción HMAC, que es por lo que NIST lo mantiene permitido para HMAC, KDF y generación de bits aleatorios, y lo prohíbe solo para firma digital. Ninguno de los dos usos aquí es una firma digital. **MD5 aparece en el repositorio** —`docs/fase0-lab-hashing/md5_lab.py`, implementado desde cero como ejercicio de Fase 0— pero **no se importa ni se usa en `src/`**: no tiene ningún propósito criptográfico en la aplicación |
| V15.1.1 | Que la documentación defina **plazos de remediación basados en riesgo** para componentes de terceros con vulnerabilidades, y para actualizar librerías en general | **fail** → **pass** *(Fase 4, G7)* | R6 define **cuándo mirar** —`pip-audit` antes del cierre de cada fase— pero no **en cuánto tiempo arreglar**. No hay nada que diga, por ejemplo, "una vulnerabilidad crítica se atiende en 7 días". Es una cadencia de revisión, no un plazo de remediación, y el requisito pide lo segundo |
| V15.2.1 | Que la aplicación solo contenga componentes que **no hayan incumplido** esos plazos | **pass** | C46: `pip-audit` 2.10.1 sobre los 22 paquetes del entorno más `pip`, **0 vulnerabilidades conocidas**, con URL y hash del estándar registrados para reproducir. Pasa **sobre los hechos**: con cero componentes vulnerables, ninguno puede haber incumplido plazo alguno. La carencia está en V15.1.1, no aquí |
| V15.3.1 | Que la aplicación devuelva solo el subconjunto de campos necesario de un objeto de datos, y no el objeto entero | **pass** | C18: el `SELECT` de `@login_required` lista **columnas explícitas y no `*`**, con el motivo escrito en el código — con un asterisco, `totp_secret` quedaría en `g.user` en cada petición protegida, al alcance de cualquier plantilla futura. Es exactamente el escenario que este requisito describe, y la decisión se tomó por razonamiento propio en 4.3, antes de conocer el requisito |

#### Resultado del bloque 4

| Estatus | Requisitos |
|---|---|
| `pass` | **4** |
| `fail` | **1** |
| **Total** | **5** |

**El caso de SHA-1 merecía argumento y no un veredicto rápido.** Un lector apresurado ve "SHA-1" y marca `fail`; un lector complaciente lo pasa por alto. Lo correcto es más aburrido: SHA-1 es inseguro frente a colisiones, HMAC no depende de la resistencia a colisiones de su hash, y ninguno de los dos usos del proyecto es una firma digital. Además, **ninguno de los dos lo eligió el proyecto**: uno es el default de Flask y el otro lo fija el RFC 6238, que es lo que asumen Google Authenticator y todas las aplicaciones estándar. Cambiar el del TOTP rompería la compatibilidad; el de Flask se puede subir a SHA-256 configurando `digest_method`, y vale la pena anotarlo como mejora sin urgencia.

**Y el MD5 del repositorio es justo el tipo de cosa que hay que declarar.** Una auditoría externa que busque `md5` encuentra un archivo y levanta la ceja. Está en `docs/fase0-lab-hashing/`, es una implementación desde cero hecha para entender el algoritmo, y no lo importa nadie. Decirlo cuesta una línea; que lo descubra otro cuesta la credibilidad del documento entero.

---

## 7. Resultado de la autoevaluación

| Estatus | Requisitos | Sobre los 70 de nivel 1 |
|---|---|---|
| `pass` | **32** | 46 % |
| `fail` | **12** | 17 % |
| N/A por condicional no cumplida | 10 | 14 % |
| No aplican a esta arquitectura (triaje) | 12 | 17 % |
| Fuera del alcance del proyecto (triaje) | 4 | 6 % |
| **Total** | **70** | 100 % |

Sobre los **54 efectivamente evaluados**: **32 `pass` y 12 `fail`**, con 10 que no llegaron a activarse. Dicho de la forma que menos favorece: de los 44 requisitos con veredicto, **se cumplen 32, el 73 %**.

### Los 12 `fail`, agrupados por problema

| # | Problema | Requisitos | Ya conocido |
|---|---|---|---|
| 1 | **No hay cambio de contraseña autenticado** | V6.2.2, V6.2.3 | No — hallazgo de esta autoevaluación |
| 2 | **Nada frena el *credential stuffing*** | V6.2.4, V6.3.1 | Sí — residual de R10 y gap de A07 |
| 3 | **La reautenticación no invalida la sesión anterior** | V7.2.4 | No — hallazgo de esta autoevaluación |
| 4 | **El token de recuperación viaja en la URL** | V14.2.1 | Sí — residual de R11, amenaza TM-34 |
| 5 | **No se emite ninguna cabecera de seguridad** | V3.2.1, V3.3.1, V3.4.1 | Sí — gap A02; el prefijo de cookie es nuevo |
| 6 | **El nombre de usuario no se valida** | V2.1.1, V2.2.1 | Parcialmente — LL20 y gap A05, ahora como incumplimiento |
| 7 | **Sin plazos de remediación documentados** | V15.1.1 | No — hallazgo de esta autoevaluación |

**Doce incumplimientos son siete problemas, y tres de los siete no los había visto ningún ejercicio anterior.** Los tres nuevos tienen algo en común: **ninguno es un control débil**. Dos son funcionalidad ausente —cambiar la contraseña, y el momento en que se revoca la sesión— y el tercero es documentación ausente. El recorrido del Top 10 y el threat model evalúan lo que existe; solo un checklist pregunta por lo que falta.

### Lo que la autoevaluación confirma

El proyecto cumple **V9 entero** (tokens autocontenidos) y la mayor parte de V6, V7 y V8. Varios `pass` corresponden a decisiones tomadas por razonamiento propio, antes de conocer el requisito que las exige: `session_version` es la solución que `V7.4.1` describe para tokens autocontenidos; el `SELECT` con columnas explícitas es literalmente `V15.3.1`; mover `/logout` a `POST` es `V3.5.3`; los tokens CSRF son `V3.5.1`; y rechazar contraseñas de más de 72 bytes en lugar de truncarlas es `V6.2.8`.

### Y lo que no cubre

**Nivel 1 no pregunta por el registro de auditoría.** V16 no aporta ni un requisito a este nivel, así que **R18 —el hallazgo de que el log no sostiene no repudio— no aparece en ninguna parte de estos 70**. Un proyecto que solo hiciera esta autoevaluación no tendría forma de encontrarlo. Es el argumento más claro a favor de haber hecho los dos ejercicios, y en ese orden.

---

## 8. Re-evaluación tras la Fase 4 (WBS 6.8.1)

La Fase 4 remedió los siete gaps de Nivel 1. Esta sección recalcula el resultado **sin reescribir** la evaluación original: el recorrido de la sección 6 sigue mostrando lo que se encontró en la Fase 3, con una marca `fail → pass` en los requisitos que cambiaron. Un documento de auditoría que se sobrescribe deja de poder demostrar qué se corrigió.

### Requisitos que cambiaron de estatus

| Req | Gap | Qué lo cierra |
|---|---|---|
| V2.1.1 | G6 | La política del nombre de usuario existe y está escrita: `USERNAME_MIN_LENGTH`, `USERNAME_MAX_LENGTH` y `USERNAME_PATTERN` en `config.py`, aplicadas por `validar_username()` |
| V2.2.1 | G6 | **Lista blanca**, no lista negra: se enumera lo permitido. 18 pruebas, incluida la que fija que los dos puntos se rechazan — el caso concreto de LL20 |
| V3.2.1 | G1 | `X-Content-Type-Options: nosniff` más una CSP estricta. La aplicación no sirve archivos subidos ni respuestas de API, así que el escenario que el requisito persigue queda cubierto |
| V3.3.1 | G2 | Cookie renombrada a `__Host-session`, con `Secure`, `Path=/` y sin `Domain`. **Con reserva: ver abajo** |
| V7.2.4 | G3 | `abrir_sesion()` incrementa `session_version` antes de escribir la cookie, en los dos caminos de autenticación. Verificado con la prueba de la cookie copiada y con su mutación |
| V15.1.1 | G7 | Plazos de remediación basados en riesgo, incorporados al plan de respuesta de R6 |

### La reserva de V3.3.1

El control está implementado y su nombre es correcto, pero **no está verificado en un navegador**, y no puede estarlo con la suite: el test client de Werkzeug **no implementa las reglas de prefijo**, así que aceptaría una cookie `__Host-` que un navegador rechazaría. Sobre HTTP plano el comportamiento **varía entre navegadores**.

Si el navegador la rechaza, no se trata de un incumplimiento: **la aplicación no permitiría iniciar sesión en absoluto**. Queda como comprobación manual pendiente, del mismo tipo que la de 4.3.6 con la app autenticadora. Hasta hacerla, este `pass` es provisional.

### Lo que la Fase 4 cerró y ASVS Level 1 no mide

Dos de los siete gaps **no cambian ningún requisito de nivel 1**:

- **G4** (manejadores globales de error) cierra la amenaza TM-14 y el gap A10 del Top 10.
- **G5** (rotación del registro) cierra TM-28.

Los dos pertenecen a **V16 Security Logging and Error Handling**, que no aporta **ni un requisito de nivel 1**. Es la misma asimetría que se documentó al bajar el estándar, ahora vista desde el otro lado: se puede mejorar la postura de seguridad de forma medible sin que el checklist se mueva un punto. Un proyecto que solo persiguiera el número no habría hecho ninguno de los dos.

### Resultado actualizado

| Estatus | Fase 3 | **Tras la Fase 4** |
|---|---|---|
| `pass` | 32 | **38** |
| `fail` | 12 | **6** |
| N/A por condicional no cumplida | 10 | 10 |
| No aplican a esta arquitectura | 12 | 12 |
| Fuera del alcance del proyecto | 4 | 4 |
| **Total** | **70** | **70** |

Sobre los 44 requisitos con veredicto: **38 de 44, el 86 %** — frente al 73 % de la Fase 3.

### Los seis `fail` que quedan

| Problema | Requisitos | Gap | Nivel |
|---|---|---|---|
| No hay cambio de contraseña autenticado | V6.2.2, V6.2.3 | G8 | 2 |
| Nada frena el *credential stuffing* | V6.2.4, V6.3.1 | G9 | 2 |
| El token de recuperación viaja en la URL | V14.2.1 | G10 | 2 |
| Sin HSTS | V3.4.1 | G14 | 3 |

Cinco de los seis son de **Nivel 2** y estaban fuera del alcance de esta fase por decisión registrada (Charter, cambio #6). El sexto, V3.4.1, **no se puede cerrar sin TLS**: emitir `Strict-Transport-Security` sobre HTTP plano es inútil y potencialmente destructivo, así que entra con G14.

---

*Continúa en 5.4: consolidación de los gaps del threat model y de la autoevaluación.*
