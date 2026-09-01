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

---

*Última actualización: sección 4 agregada (4.1 Criptografía y Hashing, 4.2 Autenticación y Autorización) durante Fase 0, temas 0.2 y 0.3. Secciones 1, 2 y 3 completadas durante la configuración inicial y la redacción del Project Charter.*
