# Registro de Riesgos / Risk Register

**Proyecto:** Sistema de Login Seguro — Proyecto de Aprendizaje en Ciberseguridad
**Fecha de elaboración:** Agosto 2026
**Preparado por:** Lorenzo Mtz

---

## 1. Propósito

Este registro identifica los riesgos (amenazas y oportunidades) que pueden afectar el proyecto, con una respuesta planeada para cada uno. Al ser un proyecto individual, se usa una versión **tailored** (adaptada) del Risk Register de PMBOK: sin gestión cuantitativa de riesgo, solo evaluación cualitativa simple.

Es un documento **vivo**: se revisa al cierre de cada fase (ver WBS, tareas "Cierre de Fase"), igual que el Lessons Learned Log.

---

## 2. Escala de Probabilidad e Impacto

| Nivel | Probabilidad | Impacto |
|---|---|---|
| **Baja** | Poco probable que ocurra | Efecto menor, fácil de absorber |
| **Media** | Podría ocurrir | Retrasa una fase o requiere ajustar el plan |
| **Alta** | Muy probable / ya está ocurriendo | Pone en riesgo un objetivo del Charter |

**Exposición** = combinación cualitativa de Probabilidad × Impacto (Baja / Media / Alta).

---

## 3. Registro de Riesgos (Amenazas)

| ID | Categoría | Descripción del riesgo | Probabilidad | Impacto | Exposición | Estrategia | Plan de respuesta |
|---|---|---|---|---|---|---|---|
| R1 | Alcance | El criterio original "calidad de mercado" era ambiguo y puede generar scope creep | Media | Media | Media | Mitigar | Ya mitigado en el Charter: criterios de éxito objetivos = OWASP ASVS Level 1 (Sección 3) |
| R2 | Cronograma | Subestimar el tiempo real de la Fase 2 (MFA, rate limiting, logging) por ser la más técnica | Alta | Media | Alta | Mitigar | Reservar margen extra al planear Fase 2; desglosar a work packages (WBS) *antes* de empezar a programarla, no a mitad de camino |
| R3 | Recursos | Disponibilidad de tiempo variable (4-8 hrs/semana) alarga los tiempos entre hitos | Alta | Baja | Media | Aceptar | Se acepta como restricción natural del proyecto (ver Charter, Sección 8); se compensa con rolling wave planning en vez de fechas fijas |
| R4 | Técnico | Primera implementación de MFA/TOTP: alto riesgo de implementarlo de forma insegura o incorrecta sin experiencia previa | Media | Alta | Alta | Mitigar | Reforzar el tema en Fase 0 (notas de estudio 0.5) antes de programarlo; usar una librería TOTP probada (ej. `pyotp`) en vez de implementar el algoritmo desde cero |
| R5 | Seguridad | Al ser el primer proyecto práctico de seguridad, se pueden introducir vulnerabilidades sin darse cuenta (falsa sensación de seguridad) | Media | Alta | Alta | Mitigar | Autoevaluación honesta contra checklist ASVS Level 1 (Fase 3) antes de dar el proyecto por "seguro"; no asumir que "funciona" = "seguro" |
| R6 | Técnico / Cadena de suministro | Dependencias (librerías de Python) con vulnerabilidades conocidas | Baja | Media | Baja | Mitigar | Revisar dependencias con `pip list` / herramientas como `pip-audit` antes del cierre de cada fase |
| R7 | Seguridad / Operacional | Exponer credenciales o secretos por accidente en el historial de Git | Baja | Alta | Media | Mitigar | `.gitignore` ya cubre `.env`, `*.key`, `*.pem`, `*.db` (ver guía de Git, Sección 6); revisar `git status` antes de cada `add` |
| R8 | Gobernanza del proyecto | Los artefactos PMBOK (Charter, Scope, WBS) se desactualizan y dejan de reflejar el alcance real | Media | Baja | Baja | Mitigar | Usar el Registro de Cambios del Charter (Sección 10) cada vez que el alcance se ajuste, como ya se hizo al agregar la Fase 0 |

---

## 4. Registro de Riesgos (Oportunidades)

PMBOK también contempla riesgos positivos — cosas que, si ocurren, benefician al proyecto más allá de lo planeado.

| ID | Categoría | Descripción de la oportunidad | Probabilidad | Impacto | Estrategia | Plan de respuesta |
|---|---|---|---|---|---|---|
| O1 | Portafolio profesional | La documentación PMBOK + el proyecto técnico completo pueden servir como pieza de portafolio para prácticas profesionales o empleo | Media | Alta | Mejorar (Enhance) | Mantener el repo con buena calidad de documentación desde ahora, pensando en que alguien más lo pueda leer eventualmente |

---

## 5. Notas de seguimiento

- Este registro se revisa al cierre de cada fase (Fase 0, 1, 2, 3) — se agregan riesgos nuevos que hayan surgido y se cierran los que ya no aplican.
- Los riesgos cerrados no se borran: se marcan como **Cerrado** para mantener trazabilidad, siguiendo el mismo principio de control de cambios usado en el Charter.
