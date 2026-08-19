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

---

*Próxima entrada esperada: cierre de Fase 0 (ver WBS, tarea 2.7.3).*
