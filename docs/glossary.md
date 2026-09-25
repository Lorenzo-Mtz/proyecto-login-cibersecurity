# Glosario del Proyecto / Project Glossary

Glosario bilingüe de términos técnicos usados a lo largo del proyecto. Se va actualizando conforme avanzamos en cada fase.

---

## 1. Conceptos de Git / GitHub

| Español | English | Definición |
|---|---|---|
| Repositorio | Repository (repo) | Carpeta de proyecto rastreada por Git, con historial completo de cambios |
| Área de preparación | Staging area | Zona intermedia donde marcas qué cambios se incluirán en el próximo commit |
| Confirmación | Commit | "Fotografía" guardada de un conjunto de cambios, con mensaje descriptivo |
| Rama | Branch | Línea de desarrollo independiente dentro del repositorio |
| Rama principal | Main branch | Rama por default del repositorio, considerada la versión estable/actual |
| Remoto | Remote | Copia del repositorio alojada en un servidor externo (ej. GitHub) |
| Subir cambios | Push | Enviar commits locales al remoto |
| Bajar cambios | Pull | Traer cambios del remoto hacia la copia local |
| Clonar | Clone | Descargar copia completa de un repositorio remoto por primera vez |
| Fusionar | Merge | Combinar cambios de una rama en otra |
| Historial | Log | Registro cronológico de todos los commits |
| Gestor de credenciales | Credential Manager | Herramienta que guarda tu sesión autenticada de GitHub para no pedir login en cada operación |
| Autenticación de dos factores | Two-Factor Authentication (2FA) | Capa extra de seguridad al iniciar sesión, más allá de usuario/contraseña |
| Archivo de exclusión | `.gitignore` | Archivo que le dice a Git qué archivos/carpetas NO debe rastrear (ej. secretos, entornos virtuales) |

---

## 2. Comandos de Bash usados hasta ahora

| Comando | Función |
|---|---|
| `pwd` | Muestra la ruta de la carpeta actual (*print working directory*) |
| `ls` | Lista archivos y carpetas en la ubicación actual |
| `ls -a` | Lista incluyendo archivos ocultos (los que empiezan con `.`) |
| `cd <ruta>` | Cambia de carpeta (*change directory*) |
| `mkdir <nombre>` | Crea una carpeta nueva (*make directory*) |
| `nano <archivo>` | Abre un editor de texto simple dentro de la terminal |
| `git --version` | Muestra la versión de Git instalada |
| `git config --global user.name "..."` | Configura tu nombre de usuario global para commits |
| `git config --global user.email "..."` | Configura tu correo global para commits |
| `git clone <url>` | Descarga una copia local de un repositorio remoto |
| `git status` | Muestra el estado actual: cambios pendientes, rama activa, etc. |
| `git add <archivo>` / `git add .` | Mueve archivos al área de preparación (staging) |
| `git commit -m "mensaje"` | Confirma los cambios en staging con un mensaje descriptivo |
| `git push` | Sube los commits locales al repositorio remoto |

---

## 3. Conceptos de PMBOK / Gestión de Proyectos

| Español | English | Definición |
|---|---|---|
| Acta de Constitución del Proyecto | Project Charter | Documento que autoriza formalmente el proyecto y define su propósito, alcance y objetivos de alto nivel |
| Interesado | Stakeholder | Cualquier persona con interés o influencia en el proyecto |
| Patrocinador | Sponsor | Quien autoriza y respalda el proyecto |
| Alcance | Scope | Todo el trabajo necesario (y solo ese trabajo) para completar el proyecto exitosamente |
| Enunciado del Alcance | Scope Statement | Documento que detalla el alcance incluido y excluido del proyecto |
| Estructura de Desglose del Trabajo | Work Breakdown Structure (WBS) | Descomposición jerárquica del trabajo del proyecto en entregables más pequeños y manejables |
| Hito | Milestone | Punto o evento significativo dentro del cronograma del proyecto |
| Entregable | Deliverable | Cualquier producto, resultado o capacidad único y verificable que debe producirse |
| Registro de Riesgos | Risk Register | Documento donde se registran los riesgos identificados, su análisis y planes de respuesta |
| Supuesto | Assumption | Factor que se considera verdadero sin comprobación formal, para efectos de planeación |
| Restricción | Constraint | Factor limitante que afecta la ejecución del proyecto (tiempo, presupuesto, recursos) |
| Planeación gradual / en olas sucesivas | Rolling Wave Planning | Técnica de planeación progresiva: se detalla con precisión el trabajo cercano y de forma general el trabajo futuro |
| Adaptación | Tailoring | Ajustar los procesos y artefactos de una metodología (como PMBOK) al tamaño y contexto real del proyecto |
| Lecciones Aprendidas | Lessons Learned | Conocimiento adquirido durante el proyecto que puede mejorar el desempeño futuro |

---

## 4. Conceptos de Ciberseguridad

### 4.1 Protocolo HTTP / HTTPS (Fase 0.1)

| Español | English | Definición |
|---|---|---|
| Protocolo de transferencia de hipertexto | HTTP | Protocolo de petición y respuesta sobre el que funciona la web. Viaja en **texto plano**: quien esté en la red lee y modifica todo lo que pasa, credenciales incluidas. Es la razón de que exista HTTPS |
| HTTP sobre TLS | HTTPS | HTTP dentro de un canal cifrado. Aporta **tres** cosas distintas que conviene no confundir: confidencialidad (nadie lee), integridad (nadie altera) y autenticación del servidor (hablas con quien crees). El proyecto declara `SESSION_COOKIE_SECURE` pero **no tiene TLS**, así que hoy las tres son declarativas (gap G14) |
| Seguridad de la capa de transporte | TLS (Transport Layer Security) | El protocolo de cifrado que envuelve a HTTP. *SSL* es su nombre anterior y todas sus versiones están obsoletas; ASVS V12.1.1 exige TLS 1.2 o 1.3 |
| Sin estado | Stateless | HTTP **no recuerda nada** entre una petición y la siguiente. Es el hecho del que nace todo lo demás: si el servidor no recuerda quién eres, alguien tiene que llevar esa información consigo — y de ahí salen las cookies, las sesiones y prácticamente todos los problemas que este proyecto trata |
| Método HTTP | HTTP method | El verbo de la petición: `GET`, `POST`, `PUT`, `DELETE`. La especificación llama **seguros** a los que no deben cambiar estado (`GET`, `HEAD`), y por eso `/logout` se movió a `POST` en 4.5.3 (ASVS V3.5.3) |
| Código de estado | Status code | El número de la respuesta: 200, 302, 404, 500. Es **observable por quien ataca**, así que dos caminos que quieran ser indistinguibles tienen que devolver el mismo: un 500 delata tanto como un mensaje distinto (LL15) |
| Cabecera HTTP | HTTP header | Metadatos que acompañan a la petición o a la respuesta. Varios controles del proyecto **son** exactamente cabeceras: `Set-Cookie`, `Content-Security-Policy`, `Referrer-Policy`, `Strict-Transport-Security` |
| Cadena de consulta | Query string | La parte de la URL que sigue a `?`. Junto con el *path*, es lo que queda en el historial del navegador y en los registros de cualquier intermediario — por eso ASVS V14.2.1 prohíbe poner ahí datos sensibles, y por eso el token de recuperación en la URL es un incumplimiento abierto (gap G10) |
| Cuerpo de la petición | Request body | Lo que viaja dentro de un `POST`, fuera de la URL. No queda en el historial ni en los registros de los intermediarios, que es la razón de mover ahí cualquier dato sensible |
| Origen | Origin | La tripleta **esquema + dominio + puerto**. Es la unidad con la que el navegador decide qué puede leer qué: de ella dependen la política del mismo origen, CORS y el prefijo `__Host-` de las cookies |
| Contexto seguro | Secure context | Origen que el navegador considera confiable: HTTPS y, por excepción, `localhost`. Es lo que permite que una cookie `Secure` funcione en desarrollo local sin TLS — y también la razón de que ese control **hoy no se esté ejerciendo de verdad** |
| Ataque de intermediario | Man-in-the-middle (MitM) | Alguien situado en la red que puede leer o alterar el tráfico. Es el perfil de atacante **P4** del threat model, y sin TLS no hay ningún control que lo estorbe |
| HSTS | HTTP Strict Transport Security | Cabecera con la que el servidor le dice al navegador *"a este dominio, siempre por HTTPS"*. **No debe emitirse sobre HTTP plano**: se ignora, y si llegara a tomar efecto sin TLS dejaría el sitio inalcanzable. Por eso V3.4.1 sigue abierto hasta que exista despliegue |
| Certificado y autoridad certificadora | Certificate / Certificate Authority (CA) | El documento que acredita que un dominio es quien dice ser, firmado por un tercero en el que el navegador confía. Es lo que convierte el cifrado en **autenticación**: sin un certificado válido, TLS te protege de un espía pero no te dice con quién estás hablando |

### 4.2 Criptografía y Hashing (Fase 0.2)

| Español | English | Definición |
|---|---|---|
| Función hash | Hash function | Función que convierte una entrada de cualquier tamaño en una salida de tamaño fijo, de forma determinista y (idealmente) irreversible |
| Cifrado | Encryption | Transformación de datos que SÍ es reversible mediante una clave — se usa cuando se necesita recuperar el valor original; por eso no es apropiado para contraseñas |
| Sal | Salt | Valor aleatorio único agregado a cada contraseña antes de hashear, para que dos contraseñas iguales generen hashes distintos y así prevenir ataques de rainbow table |
| Factor de trabajo | Work Factor (cost factor) | Parámetro de bcrypt que controla cuántas rondas de cómputo se requieren para generar un hash — entre más alto, más lento y más resistente a fuerza bruta |
| bcrypt | bcrypt | Algoritmo de hashing diseñado específicamente para contraseñas: lento por diseño, con salt incorporado automáticamente en el propio hash resultante |
| Tabla arcoíris | Rainbow Table | Tabla precalculada de hashes usada por atacantes para revertir hashes rápidamente — ineficaz contra hashes con salt |
| Ataque de fuerza bruta | Brute-force attack | Intentar sistemáticamente muchas combinaciones de contraseñas hasta encontrar la correcta; su viabilidad depende de qué tan rápido se pueda calcular cada intento |

### 4.3 Autenticación y Autorización (Fase 0.3)

| Español | English | Definición |
|---|---|---|
| Autenticación | Authentication (AuthN) | Proceso de verificar que un usuario es quien dice ser |
| Autorización | Authorization (AuthZ) | Proceso de determinar qué acciones o recursos puede acceder un usuario ya autenticado |
| Control de acceso basado en roles | Role-Based Access Control (RBAC) | Modelo de autorización donde los permisos se asignan según el rol del usuario (ej. admin, usuario estándar) |
| Referencia directa a objeto insegura | Insecure Direct Object Reference (IDOR) | Falla de AuthZ donde un usuario autenticado puede acceder a recursos de otro usuario manipulando identificadores (ej. cambiar un ID en la URL) |
| Enumeración de usuarios | Username Enumeration | Falla donde el sistema revela, por mensajes de error distintos, si un username/email existe o no en la base de datos |
| Principio de mínimo privilegio | Principle of Least Privilege | Un usuario o proceso debe tener solo los permisos mínimos necesarios para su función |


### 4.4 Gestión de Sesiones (Fase 0.4)

| Español | English | Definición |
|---|---|---|
| Sesión | Session | Periodo de interacción continua entre un usuario autenticado y la aplicación, mantenido mediante un identificador que el servidor usa para "recordar" quién es en cada petición |
| Cookie de sesión | Session cookie | Pequeño fragmento de datos que el navegador guarda y reenvía en cada petición, normalmente conteniendo el identificador de sesión |
| Token de sesión | Session token | Identificador único (aleatorio e impredecible) que representa una sesión activa; debe generarse con suficiente entropía para no poder adivinarse |
| Secuestro de sesión | Session hijacking | Ataque donde un tercero obtiene el identificador de sesión de un usuario legítimo (ej. robándolo en tránsito o vía XSS) y lo usa para hacerse pasar por él |
| Fijación de sesión | Session fixation | Ataque donde el atacante fuerza a la víctima a usar un ID de sesión que el atacante ya conoce, para luego usarlo tras el login |
| Bandera HttpOnly | HttpOnly flag | Atributo de cookie que impide que JavaScript del lado del cliente la lea, mitigando el robo de la cookie vía XSS |
| Bandera Secure | Secure flag | Atributo de cookie que obliga al navegador a enviarla solo por conexiones HTTPS, evitando exponerla en texto plano |
| Atributo SameSite | SameSite attribute | Atributo de cookie que restringe si se envía en peticiones que se originan desde otro sitio, mitigando ataques CSRF |
| Expiración de sesión | Session expiration / timeout | Tiempo límite (absoluto o por inactividad) tras el cual una sesión deja de ser válida automáticamente |
| Regeneración de ID de sesión | Session ID regeneration | Práctica de emitir un nuevo identificador de sesión justo después de un login exitoso (o cambio de privilegios), para invalidar cualquier ID previamente fijado por un atacante |
| Invalidación de sesión / Cierre de sesión | Session invalidation / Logout | Acción de destruir la sesión en el servidor (no solo borrar la cookie del cliente) al cerrar sesión, para que el token ya no sirva |

### 4.5 Protocolos de Verificación y Recuperación (Fase 0.5)

| Español | English | Definición |
|---|---|---|
| Contraseña de un solo uso | One-Time Password (OTP) | Código válido para un único uso (o por un tiempo muy corto), usado como segundo factor de autenticación o para verificar identidad |
| OTP basada en HMAC | HMAC-based One-Time Password (HOTP) | Variante de OTP donde el código se deriva de un secreto compartido y un contador que se incrementa en cada uso |
| OTP basada en tiempo | Time-based One-Time Password (TOTP) | Variante de OTP (RFC 6238) donde el código se deriva de un secreto compartido y la marca de tiempo actual, cambiando cada cierto intervalo (normalmente 30 segundos) |
| Autenticación multifactor | Multi-Factor Authentication (MFA) | Requerir dos o más factores independientes de autenticación (algo que sabes, algo que tienes, algo que eres) para confirmar identidad |
| Secreto compartido / Semilla | Shared secret / Seed | Valor secreto conocido tanto por el servidor como por el dispositivo del usuario (ej. app autenticadora), usado como entrada para generar los códigos OTP |
| Ventana de tiempo | Time step / Time window | Intervalo de tiempo (ej. 30 segundos) durante el cual un código TOTP específico es válido |
| Código QR de aprovisionamiento | Provisioning QR code | Código QR que codifica la URL `otpauth://` con el secreto compartido, usado para configurar una app autenticadora sin transcribir el secreto a mano |
| RFC 6238 | RFC 6238 | Estándar técnico (IETF) que define el algoritmo TOTP |

### 4.6 Fundamentos de OWASP (Fase 0.6)

| Español | English | Definición |
|---|---|---|
| OWASP | OWASP (Open Worldwide Application Security Project) | Fundación sin fines de lucro dedicada a mejorar la seguridad del software, conocida por publicar guías y estándares de referencia gratuitos |
| OWASP Top 10 | OWASP Top 10 | Lista, actualizada periódicamente, de las 10 categorías de riesgo más críticas en aplicaciones web, usada como referencia mínima de seguridad |
| OWASP ASVS | OWASP Application Security Verification Standard (ASVS) | Estándar de OWASP con una lista detallada de requisitos de seguridad verificables, organizados por nivel de rigor, usado para diseñar y auditar aplicaciones |
| Niveles L1/L2/L3 de ASVS | ASVS Levels L1/L2/L3 | Niveles crecientes de rigor de ASVS: L1 (mínimo, aplicable a casi todo), L2 (aplicaciones con datos sensibles), L3 (alto valor/alto riesgo, requiere análisis profundo) |
| Vulnerabilidad | Vulnerability | Debilidad en un sistema que puede ser explotada para comprometer su confidencialidad, integridad o disponibilidad |
| Superficie de ataque | Attack surface | Conjunto de todos los puntos por donde un atacante podría intentar entrar o extraer datos de un sistema |
| Inyección | Injection | Categoría de vulnerabilidad donde datos no confiables se envían a un intérprete (SQL, comandos, etc.) y se ejecutan como parte de un comando o consulta |
| Control de acceso roto | Broken Access Control | Categoría del OWASP Top 10 donde fallas en las reglas de autorización permiten a un usuario acceder a datos o funciones que no le corresponden |
| Fallas criptográficas | Cryptographic Failures | Categoría del OWASP Top 10 relacionada con datos sensibles expuestos por cifrado ausente, débil o mal implementado |

### 4.7 Endurecimiento OWASP (Fase 2)

| Español | English | Definición |
|---|---|---|
| Falsificación de petición en sitios cruzados | Cross-Site Request Forgery (CSRF) | Ataque donde un sitio externo hace que el navegador de la víctima envíe una petición a otra aplicación; como el navegador adjunta las cookies automáticamente, la app la procesa como si la hubiera hecho el usuario |
| Token CSRF / Token sincronizador | CSRF token / Synchronizer token | Valor secreto ligado a la sesión que el servidor inserta como campo oculto en cada formulario y verifica en cada POST; un sitio externo no puede leerlo (Same-Origin Policy), así que no puede falsificar la petición. En el proyecto lo implementa `CSRFProtect` de Flask-WTF (WBS 4.5.3) |
| CSRF de inicio de sesión | Login CSRF | Variante de CSRF donde el atacante hace que la víctima inicie sesión en la cuenta *del atacante*, para capturar lo que la víctima escriba después; `SameSite` no lo evita porque la víctima aún no tiene cookie de sesión |
| Política del mismo origen | Same-Origin Policy (SOP) | Regla del navegador que impide que una página lea respuestas de otro origen (esquema + dominio + puerto); es lo que hace que un token CSRF sea secreto para otros sitios |
| Métodos seguros de HTTP | Safe HTTP methods | Métodos (GET, HEAD) que por especificación no deben cambiar estado en el servidor; por eso el logout se hace por POST y no con un enlace |
| Post/Redirect/Get | Post/Redirect/Get (PRG) | Patrón donde, tras un POST que cambia estado, el servidor responde con una redirección (302) a una página que se carga por GET, para que recargar la página no reenvíe el formulario |
| Redirección abierta | Open redirect | Vulnerabilidad donde la app redirige a una URL controlada por el usuario (ej. `?next=` o el encabezado `Referer`), lo que permite usar el dominio legítimo para enviar víctimas a un sitio malicioso |
| Fuerza bruta | Brute force | Ataque que prueba contraseñas una tras otra contra una misma cuenta hasta acertar; no rompe el hash, le pide al servidor que lo verifique por él. El costo de bcrypt lo frena pero no lo detiene: hace falta un límite de intentos (WBS 4.1) |
| Relleno de credenciales | Credential stuffing | Ataque que reutiliza pares usuario/contraseña filtrados de otro sitio; a diferencia de la fuerza bruta no necesita miles de intentos, con frecuencia basta uno |
| Rociado de contraseñas | Password spraying | Ataque que prueba una sola contraseña común contra muchas cuentas distintas; un contador por nombre de usuario **no lo detecta**, porque ninguna cuenta acumula fallos. Mitigarlo requiere un límite por IP (fuera del alcance de 4.1) |
| Ventana deslizante | Sliding window | Técnica de conteo que sólo considera los eventos ocurridos en los últimos N segundos respecto de *ahora*, en lugar de reiniciar un contador en instantes fijos; el bloqueo se libera solo, conforme los intentos viejos salen de la ventana |
| Anti-automatización | Anti-automation | Controles que impiden probar credenciales a volumen (límite de intentos, bloqueo temporal, CAPTCHA); exigidos por ASVS V2.2.1. Son independientes de la fuerza del hash |
| Bloqueo de cuenta / DoS de cuenta | Account lockout / Account DoS | Efecto secundario de bloquear por intentos fallidos: un tercero puede bloquear a propósito a un usuario legítimo escribiendo contraseñas incorrectas. Se mitiga con bloqueos cortos, nunca permanentes, y no registrando intentos mientras el bloqueo está vigente |
| Oráculo | Oracle | Cualquier diferencia observable en la respuesta —mensaje, código de estado o **tiempo de respuesta**— que le revela al atacante información que no debería tener, como si una cuenta existe o si está bloqueada |
| Token al portador | Bearer token | Credencial que autoriza por el solo hecho de presentarla, sin pedir nada más: quien la tenga es tratado como su dueño. El enlace de recuperación es uno, y por eso se le pone vigencia corta y un solo uso (WBS 4.2) |
| Token de un solo uso | Single-use token | Credencial que se invalida al consumirse (aquí, marcando `used_at`). Sin ese marcado el enlace del correo seguiría abriendo la cuenta indefinidamente, aunque la contraseña ya haya cambiado |
| Generador pseudoaleatorio criptográficamente seguro | Cryptographically Secure Pseudo-Random Number Generator (CSPRNG) | Generador cuya salida no permite deducir los valores siguientes ni los anteriores. En Python es el módulo `secrets`; `random` **no** lo es (es determinista a partir de su semilla) y no debe usarse para secretos |
| Entropía | Entropy | Medida de cuánta aleatoriedad real contiene un secreto, en bits. `secrets.token_urlsafe(32)` da 256 bits: es la razón por la que ese token se guarda con SHA-256 y no con bcrypt — no hay diccionario que probar, así que encarecer cada intento no compra nada |
| Enumeración de usuarios | Username / account enumeration | Deducir qué cuentas existen a partir de diferencias en la respuesta. En el formulario de recuperación se evita respondiendo lo mismo exista o no el email: mismo código, mismo destino y mismo HTML |
| Fallo abierto / Fallo cerrado | Fail-open / Fail-closed | Cómo se comporta un control cuando algo sale mal. *Fail-closed* rechaza y se nota de inmediato; *fail-open* deja pasar y **no se nota nunca**, porque la aplicación se sigue viendo igual. Todo control de seguridad debe fallar cerrado |
| Punto de costura | Seam | Lugar del código pensado para sustituirse sin tocar lo demás. `mailer.py` es uno: recibe dos cadenas ya armadas y no sabe de tokens ni de usuarios, así que cambiar la consola por SMTP real no modifica ningún otro archivo |
| Ataque de repetición | Replay attack | Reutilizar una credencial capturada tal cual: el mismo código TOTP, el mismo token, la misma cookie. Un segundo factor sin defensa contra repetición deja de ser "algo que tienes" y pasa a ser "algo que alguien vio". Se cierra guardando el periodo del último código aceptado y exigiendo que el siguiente sea estrictamente mayor (WBS 4.3.5) |
| Comparación en tiempo constante | Constant-time comparison | Comparar dos secretos sin que el tiempo empleado dependa de en qué carácter difieren. `==` corta en el primer carácter distinto, así que su duración revela cuántos se acertaron; `hmac.compare_digest` recorre siempre todo. Es lo que impide adivinar un código de seis dígitos de uno en uno |
| Desfase de reloj | Clock drift / clock skew | Diferencia entre la hora del servidor y la del teléfono. TOTP depende del reloj de ambos, así que se acepta una tolerancia de ±1 periodo; ampliarla triplica los códigos válidos en cada instante |
| Enrolamiento | Enrollment | Proceso de dar de alta un segundo factor en una cuenta. La regla es activarlo solo después de validar un primer código: activarlo al mostrar el QR deja fuera de su cuenta a quien no llegue a escanearlo |
| Sesión pendiente | Pending / partial session | Estado intermedio del login en dos pasos: la contraseña ya se validó pero el segundo factor no. No lleva `user_id`, así que el guard de rutas protegidas la rechaza igual que a un visitante, y caduca en minutos |
| Firmado ≠ cifrado | Signed vs encrypted | La cookie de sesión de Flask va **firmada**: nadie puede modificarla sin la `SECRET_KEY`, pero cualquiera que la tenga puede **leerla**. Por eso sirve para marcar "este navegador ya puso la contraseña" y no sirve para guardar un secreto TOTP |
| Expiración por inactividad | Idle timeout / inactivity timeout | Vida de la sesión contada desde la **última petición**: se renueva con el uso y solo mata la sesión de quien dejó de usar la app. En Flask es `PERMANENT_SESSION_LIFETIME`, cuyo nombre despista: no es una vida máxima (WBS 4.5.4) |
| Vida máxima de sesión | Absolute session lifetime | Vida contada desde el **login**, que la actividad **no** renueva. Es el único de los dos límites que una cookie robada no puede estirar usándola, y por eso el que cierra el riesgo residual de R9. Flask no lo trae: se comprueba a mano contra una marca de tiempo guardada al iniciar sesión |
| Sesión deslizante | Rolling / sliding session | Sesión cuyo vencimiento se empuja hacia adelante en cada petición. Es el default de Flask (`SESSION_REFRESH_EACH_REQUEST = True`), que vuelve a firmar la cookie con un timestamp nuevo cada vez. Convierte cualquier límite configurado en un *idle timeout*, aunque el nombre de la clave sugiera otra cosa |
| Dependencia transitiva | Transitive dependency | Paquete que no se pidió: llega arrastrado por otro que sí. `requirements.txt` declara 8 y el entorno tiene 22. Importa porque el código vulnerable se ejecuta igual venga de donde venga: en una app Flask los avisos caen históricamente en **Werkzeug y Jinja2**, que nadie escribió en el archivo |
| Cadena de suministro de software | Software supply chain | Todo el código de terceros que termina ejecutándose en tu proceso. Cada dependencia agregada la alarga, y lo que se evalúa no es solo si la librería es buena, sino qué arrastra: es la razón de usar la factory SVG de `qrcode` y no la PNG, que exigiría Pillow entero (R6) |
| Aviso de seguridad | Security advisory | Publicación que dice que ciertas versiones de un paquete tienen un fallo conocido (PyPI Advisory Database, OSV, GHSA, CVE). `pip-audit` compara nombre + versión contra esa base: no analiza tu código, así que un resultado limpio significa *nada conocido hoy*, no *sin vulnerabilidades* |
| Cabeceras de seguridad | Security headers | Cabeceras HTTP con las que el servidor le pide al navegador que aplique restricciones: `Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`, `Strict-Transport-Security` y `Referrer-Policy`. Esta última controla cuánta URL se envía al navegar a otro sitio, y por eso acota el riesgo de que un token que viaja en la URL se filtre por `Referer` |
| Denegar por defecto | Deny by default | Que el acceso esté cerrado salvo donde se abra explícitamente, en lugar de abierto salvo donde se proteja. Un decorador que hay que acordarse de poner es lo segundo: la ruta que lo olvide nace accesible y nada avisa |
| Inventario de componentes | Software Bill of Materials (SBOM) | Lista formal y legible por máquina de todo lo que compone un artefacto de software, dependencias transitivas incluidas. Es lo que permite contestar "¿me afecta este aviso?" sin revisar a mano, y lo que A03:2025 pide como base de la gestión de la cadena de suministro |
| Prueba de mutación | Mutation testing | Romper el código a propósito para comprobar que alguna prueba se pone en rojo. Es lo que distingue una prueba que verifica un control de una que solo lo acompaña: una prueba que nunca se ha visto fallar no prueba nada |

---

*Última actualización: Septiembre 2026 — **cierre del proyecto (WBS 7.2)**: se agrega la sección **4.1 Protocolo HTTP/HTTPS**, que era el único tema de la Fase 0 sin términos en el glosario, y las secciones siguientes se renumeran (la antigua 4.1 pasa a 4.2, y así hasta la 4.7). Antes: se amplió 4.7 Endurecimiento OWASP con los términos del recorrido del Top 10 (Fase 2, WBS 4.5.6); antes, con los de cadena de suministro (WBS 4.5.5); antes, con los de caducidad de sesión (WBS 4.5.4); antes, con los de MFA/TOTP (WBS 4.3); antes, con los de recuperación de contraseña (WBS 4.2) y fuerza bruta (WBS 4.1). Las secciones 4.1 – 4.6 corresponden a los temas 0.1 a 0.6 de la Fase 0.*
