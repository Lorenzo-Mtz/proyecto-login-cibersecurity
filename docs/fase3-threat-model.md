# Threat Model — Sistema de Login Seguro

**Fase:** 3 — Stretch Goal ASVS Level 1
**Paquete:** WBS 5.2
**Fecha:** 25 de septiembre de 2026
**Preparado por:** Lorenzo Mtz
**Método:** STRIDE sobre un diagrama de flujo de datos

> **Estado:** completo — paquetes 5.2.1 a 5.2.5.

---

## 1. Supuesto de modelado

**Se modela la aplicación como si estuviera desplegada en internet y servida por HTTPS**, aunque hoy corra en `localhost` con `debug=True`, sin TLS y sin usuarios reales.

El supuesto no es un adorno: sin él, la mitad de las amenazas se vuelven vacías —no hay red que interceptar ni datos que valgan— y el ejercicio no diría nada. Con él, los controles que ya existen se pueden evaluar de verdad.

**La brecha entre el supuesto y el estado actual no se ignora: se registra como hallazgo.** La ausencia de TLS, `app.run(debug=True)` y la falta de un servidor WSGI no desaparecen por modelar un despliegue hipotético; aparecen donde deben, que es en la lista de gaps. Ya están identificadas en el recorrido del OWASP Top 10 (A02 y A04) y en la deuda de Fase 2.

**Fuera del modelo:** el error propio del desarrollador —subir un secreto al repositorio, por ejemplo— es un riesgo del **proyecto**, no una amenaza al **sistema en ejecución**. El Risk Register ya lo trata en R7, y meterlo aquí mezclaría dos planos distintos.

---

## 2. Activos (WBS 5.2.1)

Un activo no es "la base de datos". Es **lo que alguien quiere, o lo que se pierde si cae**. El archivo SQLite es un contenedor; lo valioso adentro son cosas distintas, con atacantes y consecuencias distintas.

| # | Activo | Dónde vive | Propiedad que importa | Por qué lo quiere un atacante |
|---|---|---|---|---|
| A1 | **`SECRET_KEY`** | `.env`, fuera del repo | Confidencialidad | **Activo raíz.** Con ella se fabrica una cookie firmada con cualquier `user_id`, y todo el control de sesión deja de existir. No es configuración: es la llave maestra |
| A2 | Hashes de contraseña | `users.password_hash` | Confidencialidad | Reutilización de credenciales en otros sitios (*credential stuffing*). bcrypt cost 12 encarece cada intento, no lo impide |
| A3 | **Secretos TOTP** | `users.totp_secret`, **en claro** | Confidencialidad | Generar códigos válidos y anular el segundo factor. Es R12, aceptado a conciencia: validar exige recalcular un HMAC, y no se puede con el hash de la llave |
| A4 | Tokens de recuperación | SHA-256 en `password_reset_tokens`; el token **en claro** solo en el canal de entrega y en la URL | Confidencialidad | Tomar control de una cuenta sin saber la contraseña. Es un token al portador: quien lo tenga es tratado como su dueño |
| A5 | Datos de cuenta | `users.username`, `users.email` | Confidencialidad | Enumeración de cuentas, phishing dirigido, correlación con filtraciones de otros sitios |
| A6 | **Integridad del registro de auditoría** | `instance/audit.log` | **Integridad y disponibilidad** | El único activo cuyo valor no es que nadie lo lea, sino que **nadie lo altere**: un atacante quiere borrar su rastro. Hoy nada lo impide (A09 del Top 10) |
| A7 | Disponibilidad del login | El servicio | Disponibilidad | Bloquear a propósito la cuenta de un usuario legítimo (*account DoS*, R10) |
| A8 | Sesiones activas | Cookie firmada, en el navegador del usuario | Confidencialidad e integridad | Una cookie robada es acceso directo sin credenciales. Vive **fuera** del servidor, que es lo que obliga a `session_version` (LL5) |

**Dos activos que suelen quedarse fuera de un inventario y que aquí sí pesan:** la `SECRET_KEY` como raíz de confianza —de la que cuelgan A8 y, por la sesión pendiente, también el flujo de MFA— y la **integridad del log**, que es el único cuya amenaza es la escritura y no la lectura.

---

## 3. Actores / perfiles de atacante

| # | Perfil | Qué tiene | Nota |
|---|---|---|---|
| P1 | Remoto sin credenciales | Acceso a las rutas públicas | El caso base: fuerza bruta, enumeración, CSRF, robo de cookie |
| P2 | Usuario legítimo malicioso | Cuenta válida y sesión abierta | Intenta alcanzar lo que su cuenta no cubre |
| P3 | **Con acceso al sistema de archivos** | Lee `instance/app.db` y `.env` | **No es opcional en este modelo.** R12 se aceptó razonando exactamente sobre este perfil; excluirlo dejaría esa aceptación sin sustento |
| P4 | En la red | Puede observar o alterar el tráfico | Solo tiene sentido bajo el supuesto de despliegue. Es donde aparece la ausencia de TLS |

---

## 4. Diagrama de flujo de datos y fronteras de confianza (WBS 5.2.2)

```
                        FRONTERA 1: internet / servidor
                                      |
  [ Usuario ]                         |            [ Proceso Flask ]
   navegador  --- (1) credenciales, codigo TOTP, --->  create_app()
              |     token de recuperacion en la URL |   rutas de auth.py
              |                                     |   throttle / reset_tokens
              <--- (2) cookie firmada, QR data: URI -   mfa / audit / mailer
              |                       |                        |
  [ Cookie de sesion ]                |            FRONTERA 2: proceso / disco
   almacen EN EL CLIENTE              |                        |
   FRONTERA 4 --------------+         |         (3) consultas parametrizadas
                                      |                        v
                                      |              [ SQLite: instance/app.db ]
  [ App autenticadora ]               |               users / login_attempts
   telefono                           |               password_reset_tokens
      ^                               |                        |
      | (5) codigo, FUERA DE BANDA    |         (4) una linea JSON por evento
      | (el servidor nunca lo ve)     |                        v
  [ Usuario ]                         |              [ instance/audit.log ]
                                      |                        |
                                      |              [ .env : SECRET_KEY ]
                                      |
            FRONTERA 3: servidor / canal de entrega del enlace
                                      |
                        (6) enlace de recuperacion --->  [ consola del servidor ]
                            (hoy print; bajo el supuesto     (hoy)
                             de despliegue, SMTP y una
                             bandeja de terceros)
```

### Las cuatro fronteras

| # | Frontera | Qué cambia al cruzarla | Control que la sostiene hoy |
|---|---|---|---|
| **F1** | Internet ↔ servidor | Todo lo que llega es **no confiable**: lo escribe el cliente | Consultas parametrizadas, autoescape de Jinja2, validación de entrada, CSRF, `@login_required` |
| **F2** | Proceso ↔ disco | El proceso confía en lo que lee; quien alcance el disco altera esa confianza | `PRAGMA foreign_keys`, `.gitignore` sobre `.env` y `*.db`. **A6 no tiene control: el log es escribible** |
| **F3** | Servidor ↔ canal de entrega | El token en claro **sale del sistema** por un canal que no es HTTP y que el servidor no controla | El enlace va por `print`, nunca por la respuesta HTTP ni por `audit.log` (`mailer.py` es el punto de costura) |
| **F4** | **Servidor ↔ navegador, como almacén** | El estado de sesión **vive fuera del servidor**. El servidor no puede revocar lo que no guarda | Cookie **firmada** (no cifrada), `HttpOnly`/`Secure`/`SameSite=Strict`, `session_version` para revocar, y los dos timeouts de 4.5.4 |

**F4 es la frontera conceptualmente importante**, y es la que costó una lección: LL5 nació de asumir que `session.clear()` invalidaba la sesión. Firmar impide modificar; no permite revocar. Todo `session_version` existe por esta frontera.

**F3 es la más rara**, y merece nombrarse: es el único punto donde un secreto vivo **abandona el sistema a propósito**. Hoy termina en la consola del mismo host, así que la frontera casi no existe; bajo el supuesto de despliegue cruza a una bandeja de entrada de terceros, que es precisamente el lugar que se compromete — y es la razón de que el token dure 30 minutos y un solo uso.

**El flujo (5) no toca el servidor.** El código TOTP viaja del teléfono al usuario y del usuario al servidor por F1; el teléfono nunca habla con la aplicación. Por eso el único momento en que el secreto compartido cruza una frontera es el enrolamiento, y por eso el QR se embebe como `data:` URI en lugar de servirse desde una ruta propia, que sería una URL entregando el secreto.

---

## 5. Amenazas por elemento (WBS 5.2.3)

### Cómo se aplica STRIDE

STRIDE no es una lluvia de ideas: es un recorrido mecánico. A **cada elemento** del diagrama se le pregunta por las letras que ese tipo de elemento admite, y las que no admite se saltan con razón.

| Letra | Amenaza | Propiedad que rompe |
|---|---|---|
| **S** | *Spoofing* — suplantación | Autenticación |
| **T** | *Tampering* — manipulación | Integridad |
| **R** | *Repudiation* — repudio | No repudio / trazabilidad |
| **I** | *Information disclosure* — divulgación | Confidencialidad |
| **D** | *Denial of service* — denegación | Disponibilidad |
| **E** | *Elevation of privilege* — elevación | Autorización |

| Tipo de elemento | Letras aplicables | Por qué las demás no |
|---|---|---|
| Entidad externa | S, R | No se "manipula" algo que está fuera del sistema, ni se le eleva privilegio |
| Proceso | S, T, R, I, D, E | Las seis: es donde se decide todo |
| Almacén de datos | T, I, D (+ R si es un log) | No se suplanta un archivo; la R aparece solo cuando el almacén **es** la evidencia |
| Flujo de datos | T, I, D | Un flujo no tiene identidad ni privilegios propios |

Las amenazas se numeran `TM-nn`. Aquí solo se **identifican**; el mapeo a controles va en la sección 6 (5.2.4).

### 5.1 Entidades externas

| ID | Elemento | Letra | Amenaza | Actor |
|---|---|---|---|---|
| TM-01 | Usuario / navegador | S | Alguien se autentica como un usuario legítimo probando contraseñas, o reutilizando credenciales filtradas de otro sitio | P1 |
| TM-02 | Usuario / navegador | S | Alguien actúa como el usuario **sin credenciales**, presentando una cookie de sesión robada | P1, P4 |
| TM-03 | Usuario / navegador | R | El usuario niega una acción sensible (cambio de contraseña, activación de MFA) y no hay evidencia que lo sostenga, porque el log es alterable | P2 |
| TM-04 | App autenticadora | S | Con el secreto TOTP, un atacante genera códigos **indistinguibles** de los del teléfono legítimo: el servidor no tiene forma de saber cuál es cuál | P3 |
| TM-05 | Canal de entrega del enlace | S | Bajo el supuesto de despliegue, un tercero envía un correo que aparenta ser del sistema con un enlace falso. La aplicación no firma sus mensajes | P1 |

### 5.2 Proceso Flask

| ID | Letra | Amenaza | Actor |
|---|---|---|---|
| TM-06 | S | **Suplantación del servidor**: sin TLS ni HSTS, nada garantiza al usuario que habla con esta aplicación y no con una copia | P4 |
| TM-07 | T | Inyección SQL a través de cualquier campo de formulario | P1 |
| TM-08 | T | XSS almacenado: un `username` con marcado que se ejecute al renderizarse | P1 |
| TM-09 | T | *Log injection*: un `username` con saltos de línea que fabrique entradas falsas en el registro | P1 |
| TM-10 | T | CSRF: hacer que el navegador de la víctima envíe una acción autenticada desde otro sitio | P1 |
| TM-11 | R | **Acciones sin rastro**: el GET de `/reset-password/<token>` no audita —a propósito, para no escribir el token— y un 500 imprevisto tampoco. Ambos accesos quedan fuera de la trazabilidad | P1 |
| TM-12 | I | Enumeración de cuentas por diferencias en el mensaje, el código de estado o el HTML | P1 |
| TM-13 | I | Enumeración por **latencia**: si el camino "no existe" responde antes que el camino "existe" | P1 |
| TM-14 | I | Un error no previsto devuelve el traceback de Werkzeug con código fuente y variables locales | P1 |
| TM-15 | I | El secreto TOTP se filtra a una plantilla por quedar en `g.user` en cada petición protegida | P1 |
| TM-16 | D | Bloquear a propósito la cuenta de un usuario legítimo acumulando fallos contra su nombre | P1 |
| TM-17 | D | Pedir enlaces de recuperación en serie: como uno nuevo invalida los anteriores, la víctima nunca llega a usar el suyo | P1 |
| TM-18 | D | Peticiones desmesuradas o en volumen: no hay límite de tamaño, ni cuotas, ni rate limiting general | P1 |
| TM-19 | E | Alcanzar una ruta protegida sin sesión válida | P1 |
| TM-20 | E | La **sesión pendiente de MFA** alcanza rutas protegidas: la contraseña ya se validó, el segundo factor no | P1 |
| TM-21 | E | Una ruta nueva que olvide `@login_required` nace accesible, y nada avisa | P1 |
| TM-22 | E | Una cookie emitida antes de un logout o un cambio de contraseña sigue autorizando | P1 |

### 5.3 Almacenes de datos

| ID | Elemento | Letra | Amenaza | Actor |
|---|---|---|---|---|
| TM-23 | SQLite | I | Lectura directa del archivo: secretos TOTP **en claro**, hashes y emails | P3 |
| TM-24 | SQLite | T | Alterar `mfa_enabled`, `session_version` o un hash para tomar una cuenta | P3 |
| TM-25 | SQLite | D | Borrar o corromper el archivo: el servicio deja de existir | P3 |
| TM-26 | **`audit.log`** | **T/R** | **Borrar o editar líneas para ocultar el rastro.** El archivo no es *append-only*, no está firmado, y quien pueda escribir en `instance/` lo altera | P3 |
| TM-27 | `audit.log` | I | El registro contiene nombres de usuario, y una contraseña escrita por error en el campo "Usuario" queda ahí | P3 |
| TM-28 | `audit.log` | D | Crece sin techo ni rotación: llenar el disco es una denegación de servicio al sistema entero | P1 |
| TM-29 | **`.env`** | I | Lectura de la **`SECRET_KEY`**. Es el peor caso del modelo: con ella se fabrica una sesión de cualquier usuario y ningún control de sesión sirve | P3 |
| TM-30 | Cookie en el cliente | T | Modificar el `user_id` o la marca `login_at` dentro de la cookie | P1 |
| TM-31 | Cookie en el cliente | I | Robo de la cookie por XSS, por red sin cifrar o por acceso al equipo | P1, P4 |

### 5.4 Flujos de datos

| ID | Flujo | Letra | Amenaza | Actor |
|---|---|---|---|---|
| TM-32 | (1) navegador → servidor | I | Credenciales y códigos TOTP observados en tránsito si el transporte no va cifrado | P4 |
| TM-33 | (1) navegador → servidor | T | Alteración del tráfico en el camino | P4 |
| TM-34 | (1) token en la **URL** | I | El token queda en el historial del navegador, en registros de proxies y puede filtrarse por la cabecera `Referer` | P1, P4 |
| TM-35 | (2) servidor → navegador | I | La respuesta del enrolamiento lleva el **secreto compartido** dentro del QR | P4 |
| TM-36 | (6) enlace por el canal de entrega | I | El token en claro reposa en una bandeja de entrada, que es justo el lugar que se compromete | P1, P3 |

---

## 6. Cobertura: cada amenaza contra su control (WBS 5.2.4)

**Estados:** `Cubierto` — hay control y evidencia · `Parcial` — hay control pero queda superficie · `Aceptado` — decisión registrada · **`Sin control`** — nada lo impide hoy.

### Entidades externas

| ID | Estado | Control / evidencia | Riesgo |
|---|---|---|---|
| TM-01 | Parcial | bcrypt cost 12, límite de 5 fallos / 15 min, política de longitud 12–64. **No cubre *credential stuffing***: no hay comprobación contra contraseñas filtradas, ni límite por IP | R10 |
| TM-02 | Cubierto | Cookie firmada, `HttpOnly`/`Secure`/`SameSite=Strict`, `session_version`, 60 min de inactividad y 12 h de vida máxima | R9 |
| TM-03 | Parcial | Se registran `password_reset_success` y `mfa_activated` con `user_id`, `ts` e `ip`. **Pero TM-26 lo socava**: la evidencia es alterable | — |
| TM-04 | Aceptado | `last_mfa_timecode` impide repetir un código, pero no distingue quién lo generó. Con el secreto, los códigos del atacante son indistinguibles | **R12** |
| TM-05 | **Sin control** | La aplicación no firma sus mensajes; nada impide un correo que la aparente | — |

### Proceso Flask

| ID | Estado | Control / evidencia | Riesgo |
|---|---|---|---|
| TM-06 | **Sin control** | Sin TLS ni HSTS | A02 del Top 10 |
| TM-07 | Cubierto | Consultas parametrizadas en todo el código; ni una concatenación de SQL | — |
| TM-08 | Parcial | Autoescape de Jinja2. **Sin CSP** como segunda línea | A02 |
| TM-09 | Cubierto | `json.dumps` escapa saltos y comillas; `username` recortado a 64. Verificado con un usuario que llevaba un salto de línea y un `login_success` falso | R14 |
| TM-10 | Cubierto | `CSRFProtect` global, `/logout` solo por POST, `SameSite=Strict`. `test_csrf.py` | — |
| TM-11 | **Sin control** | El GET del token no audita (decisión correcta: registrarlo filtraría el token) y un 500 imprevisto tampoco | — |
| TM-12 | Cubierto | Mensajes genéricos, `DUMMY_HASH`, y respuesta idéntica en código, destino y HTML. LL15 | R11 |
| TM-13 | Cubierto | `bcrypt.checkpw` contra `DUMMY_HASH` en el camino bloqueado. Medido: 371 ms vs 340 ms | R10 |
| TM-14 | **Sin control** | `debug=True` y ningún `errorhandler` salvo el de `CSRFError` | A02, A10 |
| TM-15 | Cubierto | El `SELECT` de `@login_required` lista columnas explícitas y no `*` | R12 |
| TM-16 | Cubierto | El intento bloqueado se audita **pero no se cuenta**. `MAX(id)` sin cambios tras tres intentos bloqueados | R10 |
| TM-17 | **Sin control** | `/forgot-password` no tiene límite de tasa | R11 residual |
| TM-18 | **Sin control** | Sin límite de tamaño de petición, cuotas ni rate limiting general | A06, A10 |
| TM-19 | Cubierto | `@login_required`. `test_session.py` | R9 |
| TM-20 | Cubierto | La sesión pendiente no lleva `user_id`, así que el guard la rechaza igual que a un visitante. `test_mfa.py` | R4 |
| TM-21 | **Sin control** | No hay *deny by default*: el decorador hay que acordarse de ponerlo | A01 |
| TM-22 | Cubierto | `session_version`, validado en cada petición protegida. LL5 | R9 |

### Almacenes

| ID | Estado | Control / evidencia | Riesgo |
|---|---|---|---|
| TM-23 | Aceptado | Exposición acotada: el secreto no entra a `g.user`, ni a la cookie, ni al log | **R12** |
| TM-24 | **Sin control** | Nada impide escribir en la base: alterar `mfa_enabled` o `session_version` toma una cuenta | — |
| TM-25 | **Sin control** | Sin copias de respaldo | — |
| TM-26 | **Sin control** | El log no es *append-only* ni está firmado | A09 |
| TM-27 | Parcial | La firma de `audit()` no acepta campos libres, así que un secreto no se pasa por accidente. Queda el caso de la contraseña escrita en el campo "Usuario" | R14 residual |
| TM-28 | **Sin control** | Sin rotación ni techo de tamaño | A09 |
| TM-29 | **Sin control** | `.gitignore` protege del repositorio (R7), no del disco | — |
| TM-30 | Cubierto | La firma de la cookie. Verificado con `login_at` en 4.5.4 | R9 |
| TM-31 | Parcial | `HttpOnly` cubre el XSS y `SameSite` el envío cruzado. **Sin TLS real**, la red queda abierta | R9 |

### Flujos

| ID | Estado | Control / evidencia | Riesgo |
|---|---|---|---|
| TM-32 | **Sin control** | `SESSION_COOKIE_SECURE = True` es declarativo mientras no haya TLS | A04 |
| TM-33 | **Sin control** | Sin TLS | A04 |
| TM-34 | **Sin control** | El token viaja en el path. Una `Referrer-Policy` restrictiva lo acotaría | R11 residual |
| TM-35 | Parcial | El QR se embebe como `data:` URI y no se sirve desde una ruta propia. En tránsito sin cifrar sigue visible | R12 |
| TM-36 | Parcial | Vigencia de 30 minutos y un solo uso: no evita la exposición, acota su ventana | R11 |

### Resumen

| Estado | Amenazas |
|---|---|
| Cubierto | 13 |
| Parcial | 7 |
| Aceptado | 2 |
| **Sin control** | **14** |

Los catorce sin control **no son catorce problemas independientes**: se agrupan en tres causas raíz.

**Raíz 1 — No hay TLS** (TM-06, TM-32, TM-33; agrava TM-31 y TM-35). Cinco amenazas con un solo origen. Ya estaba identificado como gap de configuración; lo que aporta el modelo es el tamaño: es el hallazgo individual que más superficie abre.

**Raíz 2 — El modelo no tiene defensa frente a P3** (TM-23, TM-24, TM-25, TM-26, TM-29). Este es **el hallazgo del ejercicio**, y merece su propia sección.

**Raíz 3 — El registro de auditoría no sostiene no repudio** (TM-26, TM-03, TM-11, TM-28). Existe, es disciplinado, tiene catálogo cerrado y pruebas… y aun así no sirve como evidencia frente a quien alcance el disco.

---

## 7. El hallazgo: R12 aceptó al atacante equivocado

R12 se aceptó razonando sobre un atacante con acceso al sistema de archivos: *"quien lea la BD SQLite puede generar códigos MFA válidos"*. La decisión está bien argumentada y la exposición del secreto TOTP quedó acotada con cuidado.

**Pero ese mismo atacante alcanza cosas que valen más, y ninguna se evaluó:**

| Lo que alcanza P3 | Consecuencia | ¿Estaba registrado? |
|---|---|---|
| `users.totp_secret` | Genera códigos MFA válidos | **Sí — R12** |
| **`.env` → `SECRET_KEY`** | **Fabrica una sesión de cualquier usuario. Ningún control de sesión sobrevive: ni `session_version`, ni los timeouts, ni MFA** | **No** |
| Escritura en `users` | Pone `mfa_enabled = 0` y toma la cuenta sin tocar el segundo factor | **No** |
| Escritura en `audit.log` | Borra su rastro | **No** |
| Borrado de `app.db` | Destruye el servicio; no hay respaldos | **No** |

Dicho de otra forma: **la aceptación de R12 se hizo sobre el activo menos valioso de todos los que ese atacante alcanza.** Un atacante capaz de leer `totp_secret` está a un `cat .env` de no necesitar códigos MFA en absoluto.

Esto no invalida R12 —cifrar el secreto seguiría sin resolverse sin gestión de llaves— pero sí cambia su lectura: dejaba entender que la exposición estaba acotada al segundo factor, y en realidad el perfil P3 rompe el sistema entero. Es exactamente lo que un threat model existe para encontrar: **el riesgo no estaba mal analizado, estaba mal delimitado.**

---

## 8. Amenazas sin control: altas en el Risk Register (WBS 5.2.5)

De las tres raíces, la primera ya está registrada como gap de configuración (A02 y A04 del recorrido del Top 10, y la deuda de Fase 2). Las otras dos no tenían entrada propia:

| Nuevo | Cubre | Por qué es riesgo y no solo hallazgo |
|---|---|---|
| **R17** | TM-24, TM-25, TM-26, TM-29 y la relectura de R12 | El alcance real del perfil P3 nunca se evaluó más allá del secreto TOTP. Sin entrada propia, R12 seguiría sugiriendo que esa exposición está acotada |
| **R18** | TM-03, TM-11, TM-26, TM-28 | Un registro de auditoría que no sostiene no repudio da una garantía que no tiene, y la confianza en él es justamente lo que lo hace peligroso |

Las demás sin control ya tienen dueño: TM-17 y TM-34 son residuales de R11; TM-14, TM-18 y TM-21 son gaps abiertos por 4.5.6; TM-05 se anota junto a la Raíz 1, porque firmar mensajes solo tiene sentido con un canal de entrega real.

---

*Fin del threat model. Los gaps de este documento se consolidan con los de la autoevaluación ASVS en 5.4.1.*
