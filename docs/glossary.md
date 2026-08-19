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

*Última actualización: sección 1 y 2 completadas durante la configuración inicial del entorno de desarrollo.*

