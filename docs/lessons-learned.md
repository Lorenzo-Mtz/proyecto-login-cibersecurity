# Lessons Learned Log

**Proyecto:** Sistema de Login Seguro — Proyecto de Aprendizaje en Ciberseguridad
**Preparado por:** Lorenzo Mtz

---

## Propósito

Registro continuo de lecciones aprendidas — técnicas, de herramientas y de gestión de proyecto. No se espera al cierre del proyecto para llenarlo: se agrega una entrada cada vez que algo enseña algo útil, sea un error o un acierto. Se revisa formalmente al cierre de cada fase (ver WBS).

---

## Registro

| ID | Fecha | Fase | Categoría | ¿Qué pasó? | Lección aprendida | Acción a futuro |
|---|---|---|---|---|---|---|
| LL1 | Agosto 2026 | M0 (Setup) | Herramientas (Git) | Se ejecutó `git commit` sin haber corrido `git add` antes; el commit no guardó nada | `git commit` solo confirma lo que ya está en el área de preparación (*staging area*) — no detecta cambios por sí solo | Correr `git status` como paso previo obligatorio antes de cualquier `commit` |
| LL2 | Agosto 2026 | M0 (Setup) | Convenciones / Nomenclatura | Archivos creados con nombres inconsistentes (`Wbs.md` con mayúscula, acento accidental en `scopé-statement.md`), detectado ya después de subirlos a GitHub | Windows no distingue mayúsculas/minúsculas en nombres de archivo, pero Git sí las rastrea tal como se guardan; los acentos automáticos del sistema pueden colarse sin notarlo | Revisar el nombre exacto del archivo (con `ls`) antes de hacer el primer `git add` |
| LL3 | Agosto 2026 | M0 (Setup) | Git | Fue necesario corregir nombres de archivos ya trackeados por Git | `mv` normal hace que Git vea un archivo borrado + uno nuevo, perdiendo el historial de ese archivo; `git mv` sí registra el cambio como un rename | Usar siempre `git mv` para renombrar archivos que ya están trackeados, nunca `mv` a secas |
| LL4 | Septiembre 2026 | Fase 1 | Técnico (SQLite) | Se agregó la columna `session_version` a `schema.sql`, pero la BD existente no la tenía y las consultas fallaban | `CREATE TABLE IF NOT EXISTS` solo crea tablas nuevas: si la tabla ya existe no hace nada, así que no migra columnas. Además, SQLite parsea toda la sentencia antes de evaluar el `IF NOT EXISTS`, por lo que un error de sintaxis (una coma faltante) rompe el arranque aunque la tabla exista | Al cambiar el esquema, recrear la BD de desarrollo o aplicar un `ALTER TABLE`; en fases futuras considerar scripts de migración |
| LL5 | Septiembre 2026 | Fase 1 | Seguridad (Sesiones) | Se asumió que `session.clear()` en el logout invalidaba la sesión, pero una cookie copiada antes del logout seguía siendo válida | Flask guarda la sesión en una cookie firmada del lado del cliente, no en el servidor: firmar evita que se modifique, pero no permite revocarla. Invalidar requiere estado en el servidor (se implementó `session_version`, ver R9) | Ante cualquier mecanismo de sesión, preguntar "¿dónde vive el estado?" y probar explícitamente el escenario de cookie robada, no solo el flujo feliz |
| LL6 | Septiembre 2026 | Fase 1 | Técnico (Flask) | Se escribió `session.permanent()` y el login tronaba con `TypeError: 'bool' object is not callable` | `session.permanent` es un atributo booleano que se asigna (`= True`), no un método. Además, `PERMANENT_SESSION_LIFETIME` no tiene efecto si la sesión no se marca como permanente | Revisar la documentación oficial antes de usar una API nueva, y verificar el resultado real (fecha *Expires* de la cookie en DevTools) en vez de asumir que la configuración basta |
| LL7 | Septiembre 2026 | Fase 1 | Herramientas (Git) | `git push` fue rechazado porque GitHub tenía un commit hecho desde la web que no estaba en la copia local | Editar desde GitHub y localmente a la vez divide la historia; Git rechaza el push para no sobrescribir trabajo remoto. Se resolvió con `git fetch` + `git rebase origin/main` (sin `--force`) | Correr `git pull --rebase` antes de empezar a trabajar localmente, sobre todo si se editó algo desde la web |
| LL8 | Septiembre 2026 | Fase 2 | Seguridad (Configuración) | Al hacer obligatoria la `SECRET_KEY` (WBS 4.5.1) se descubrió que durante toda la Fase 1 la app firmó las cookies con el valor por defecto `"dev-only-inseguro-cambiame"`. `.env` nunca se creó, pero aunque hubiera existido no se habría leído: `app.py` importaba `Config` antes de llamar a `load_dotenv()` | Los atributos de una clase se evalúan al importar el módulo, no al usarla. Un valor por defecto "de desarrollo" oculta el error: la app funciona igual y nada avisa que el secreto es público. Por eso fallar al arrancar es más seguro que tener un *fallback* | Para secretos, sin valores por defecto: validar al arrancar y detener la app si faltan. Verificar el valor efectivo en ejecución (`app.config`), no solo que el archivo de configuración exista |

---

*Próxima entrada esperada: cierre de Fase 0 (ver WBS, tarea 2.7.3).*
