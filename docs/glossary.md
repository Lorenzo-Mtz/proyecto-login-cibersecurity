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

### 4.1 Criptografía y Hashing (Fase 0.2)

| Español | English | Definición |
|---|---|---|
| Función hash | Hash function | Función que convierte una entrada de cualquier tamaño en una salida de tamaño fijo, de forma determinista y (idealmente) irreversible |
| Cifrado | Encryption | Transformación de datos que SÍ es reversible mediante una clave — se usa cuando se necesita recuperar el valor original; por eso no es apropiado para contraseñas |
| Sal | Salt | Valor aleatorio único agregado a cada contraseña antes de hashear, para que dos contraseñas iguales generen hashes distintos y así prevenir ataques de rainbow table |
| Factor de trabajo | Work Factor (cost factor) | Parámetro de bcrypt que controla cuántas rondas de cómputo se requieren para generar un hash — entre más alto, más lento y más resistente a fuerza bruta |
| bcrypt | bcrypt | Algoritmo de hashing diseñado específicamente para contraseñas: lento por diseño, con salt incorporado automáticamente en el propio hash resultante |
| Tabla arcoíris | Rainbow Table | Tabla precalculada de hashes usada por atacantes para revertir hashes rápidamente — ineficaz contra hashes con salt |
| Ataque de fuerza bruta | Brute-force attack | Intentar sistemáticamente muchas combinaciones de contraseñas hasta encontrar la correcta; su viabilidad depende de qué tan rápido se pueda calcular cada intento |

### 4.2 Autenticación y Autorización (Fase 0.3)

| Español | English | Definición |
|---|---|---|
| Autenticación | Authentication (AuthN) | Proceso de verificar que un usuario es quien dice ser |
| Autorización | Authorization (AuthZ) | Proceso de determinar qué acciones o recursos puede acceder un usuario ya autenticado |
| Control de acceso basado en roles | Role-Based Access Control (RBAC) | Modelo de autorización donde los permisos se asignan según el rol del usuario (ej. admin, usuario estándar) |
| Referencia directa a objeto insegura | Insecure Direct Object Reference (IDOR) | Falla de AuthZ donde un usuario autenticado puede acceder a recursos de otro usuario manipulando identificadores (ej. cambiar un ID en la URL) |
| Enumeración de usuarios | Username Enumeration | Falla donde el sistema revela, por mensajes de error distintos, si un username/email existe o no en la base de datos |
| Principio de mínimo privilegio | Principle of Least Privilege | Un usuario o proceso debe tener solo los permisos mínimos necesarios para su función |


### 4.3 Gestión de Sesiones (Fase 0.4)

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

### 4.4 Protocolos de Verificación y Recuperación (Fase 0.5)

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

### 4.5 Fundamentos de OWASP (Fase 0.6)

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

### 4.6 Endurecimiento OWASP (Fase 2)

| Español | English | Definición |
|---|---|---|
| Falsificación de petición en sitios cruzados | Cross-Site Request Forgery (CSRF) | Ataque donde un sitio externo hace que el navegador de la víctima envíe una petición a otra aplicación; como el navegador adjunta las cookies automáticamente, la app la procesa como si la hubiera hecho el usuario |
| Token CSRF / Token sincronizador | CSRF token / Synchronizer token | Valor secreto ligado a la sesión que el servidor inserta como campo oculto en cada formulario y verifica en cada POST; un sitio externo no puede leerlo (Same-Origin Policy), así que no puede falsificar la petición. En el proyecto lo implementa `CSRFProtect` de Flask-WTF (WBS 4.5.3) |
| CSRF de inicio de sesión | Login CSRF | Variante de CSRF donde el atacante hace que la víctima inicie sesión en la cuenta *del atacante*, para capturar lo que la víctima escriba después; `SameSite` no lo evita porque la víctima aún no tiene cookie de sesión |
| Política del mismo origen | Same-Origin Policy (SOP) | Regla del navegador que impide que una página lea respuestas de otro origen (esquema + dominio + puerto); es lo que hace que un token CSRF sea secreto para otros sitios |
| Métodos seguros de HTTP | Safe HTTP methods | Métodos (GET, HEAD) que por especificación no deben cambiar estado en el servidor; por eso el logout se hace por POST y no con un enlace |
| Post/Redirect/Get | Post/Redirect/Get (PRG) | Patrón donde, tras un POST que cambia estado, el servidor responde con una redirección (302) a una página que se carga por GET, para que recargar la página no reenvíe el formulario |
| Redirección abierta | Open redirect | Vulnerabilidad donde la app redirige a una URL controlada por el usuario (ej. `?next=` o el encabezado `Referer`), lo que permite usar el dominio legítimo para enviar víctimas a un sitio malicioso |

---

*Última actualización: Septiembre 2026 — se agrega 4.6 Endurecimiento OWASP (Fase 2, WBS 4.5.3). Las secciones 4.1 – 4.5 se completaron durante la Fase 0 (temas 0.2 a 0.6).*
