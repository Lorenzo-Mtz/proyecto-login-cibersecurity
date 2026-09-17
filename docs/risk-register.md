# Registro de Riesgos / Risk Register

**Proyecto:** Sistema de Login Seguro — Proyecto de Aprendizaje en Ciberseguridad
**Fecha de elaboración:** Agosto 2026
**Última revisión:** Septiembre 2026 — Fase 2, cierre de WBS 4.1 (R10 marcado como Mitigado)
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
| R2 | Cronograma | Subestimar el tiempo real de la Fase 2 (MFA, rate limiting, logging) por ser la más técnica | Alta | Media | Alta | Mitigar | Reservar margen extra al planear Fase 2; desglosar a work packages (WBS) *antes* de empezar a programarla, no a mitad de camino. **Actualización (Septiembre 2026, inicio de Fase 2):** desglose hecho antes de programar (WBS v1.2, paquetes 4.1 – 4.6) con orden de ejecución por dependencias; se implementa, prueba y commitea un paquete a la vez, y MFA (4.3), el más complejo, va al final para no bloquear el resto. Referencia: la Fase 1 tomó ~2 semanas para 12 paquetes de trabajo (3.1 – 3.5); la Fase 2 tiene 28 (4.1 – 4.5) y más complejos, así que no se fija fecha de cierre. **Estado: En seguimiento** |
| R3 | Recursos | Disponibilidad de tiempo variable (4-8 hrs/semana) alarga los tiempos entre hitos | Alta | Baja | Media | Aceptar | Se acepta como restricción natural del proyecto (ver Charter, Sección 8); se compensa con rolling wave planning en vez de fechas fijas |
| R4 | Técnico | Primera implementación de MFA/TOTP: alto riesgo de implementarlo de forma insegura o incorrecta sin experiencia previa | Media | Alta | Alta | Mitigar | Reforzar el tema en Fase 0 (notas de estudio 0.5) antes de programarlo; usar una librería TOTP probada (ej. `pyotp`) en vez de implementar el algoritmo desde cero. **Actualización (Septiembre 2026, inicio de Fase 2):** los conceptos quedaron cubiertos en Fase 0 (glosario: OTP, HOTP, TOTP, secreto compartido, QR de aprovisionamiento) y se confirma `pyotp`. Los errores típicos se convirtieron en paquetes explícitos del WBS 4.3: activar MFA solo tras validar un primer código, sesión "pendiente de MFA" sin acceso a rutas protegidas, tolerancia de ±1 periodo, rechazo de códigos reutilizados y límite de intentos. **Estado: En seguimiento** |
| R5 | Seguridad | Al ser el primer proyecto práctico de seguridad, se pueden introducir vulnerabilidades sin darse cuenta (falsa sensación de seguridad) | Media | Alta | Alta | Mitigar | Autoevaluación honesta contra checklist ASVS Level 1 (Fase 3) antes de dar el proyecto por "seguro"; no asumir que "funciona" = "seguro" |
| R6 | Técnico / Cadena de suministro | Dependencias (librerías de Python) con vulnerabilidades conocidas | Baja | Media | Baja | Mitigar | Revisar dependencias con `pip list` / herramientas como `pip-audit` antes del cierre de cada fase |
| R7 | Seguridad / Operacional | Exponer credenciales o secretos por accidente en el historial de Git | Baja | Alta | Media | Mitigar | `.gitignore` ya cubre `.env`, `*.key`, `*.pem`, `*.db` (ver guía de Git, Sección 6); revisar `git status` antes de cada `add` |
| R8 | Gobernanza del proyecto | Los artefactos PMBOK (Charter, Scope, WBS) se desactualizan y dejan de reflejar el alcance real | Media | Baja | Baja | Mitigar | Usar el Registro de Cambios del Charter (Sección 10) cada vez que el alcance se ajuste, como ya se hizo al agregar la Fase 0 |
| R9 | Seguridad | Flask guarda la sesión en una cookie firmada del lado del cliente: `logout()` no la invalida en el servidor, y una cookie robada sigue siendo válida hasta 14 días (`PERMANENT_SESSION_LIFETIME`) | Baja | Alta | Media | Mitigar | Columna `session_version` en `users`: se guarda en la sesión al hacer login, se valida en cada ruta protegida y se incrementa en logout (y en cambio de contraseña, Fase 2). **Estado: Mitigado (Septiembre 2026)** — implementado en `schema.sql` y `auth.py`; verificado que una cookie copiada antes del logout es rechazada. Riesgo residual: si el usuario nunca hace logout, una cookie robada sigue válida hasta 14 días (se atiende en WBS 4.5.4) |
| R10 | Seguridad | El bloqueo temporal por intentos fallidos (4.1) puede usarse para bloquear a propósito a un usuario legítimo (DoS de cuenta), o revelar qué cuentas existen si el mensaje o el tiempo de respuesta cambian al bloquear | Media | Media | Media | Mitigar | Bloqueo temporal corto, nunca permanente; contador por nombre de usuario enviado, exista o no la cuenta; mismo mensaje genérico y misma comparación contra `DUMMY_HASH` que un login fallido normal. **Estado: Mitigado (Septiembre 2026)** — `src/throttle.py` y el guard de `login()`: 5 fallos en 15 minutos, con ventana deslizante que libera sola (nunca permanente); la tabla `login_attempts` no tiene `FOREIGN KEY` a `users`, así que las cuentas inexistentes se cuentan igual; el camino bloqueado ejecuta `bcrypt.checkpw` contra `DUMMY_HASH` y **no registra el intento**, de modo que un atacante no puede prolongar el bloqueo de una víctima. Verificado con 13 pruebas sobre el flujo HTTP: la contraseña correcta es rechazada durante el bloqueo, `MAX(id)` no cambia tras tres intentos bloqueados, la latencia bloqueado/fallo normal fue 371 ms vs 340 ms (ratio 1.09) y el bloqueo se liberó solo al vencer la ventana. **Riesgo residual:** contar por nombre de usuario no detecta *password spraying* (una contraseña común contra muchas cuentas), que requiere límite por IP, fuera del alcance de 4.1 |
| R11 | Seguridad | El token de recuperación de contraseña (4.2) es predecible, reutilizable, no expira, o el formulario revela si un email está registrado | Media | Alta | Alta | Mitigar | Token con `secrets.token_urlsafe`; en la BD solo su hash SHA-256; expiración corta; marcado como usado al consumirse; mensaje genérico en la solicitud; al cambiar la contraseña se incrementa `session_version` |
| R12 | Seguridad | El secreto TOTP (4.3) debe guardarse de forma recuperable para validar códigos: quien lea la BD SQLite puede generar códigos MFA válidos | Baja | Alta | Media | Aceptar | Cifrarlo requiere gestión de llaves, fuera del alcance de esta iteración. La BD ya está fuera del repo (`*.db` en `.gitignore`, R7). Se documenta como gap en la autoevaluación ASVS (Fase 3) |
| R13 | Técnico | Perder el dispositivo con la app autenticadora deja la cuenta inaccesible: los códigos de respaldo (*backup codes*) no están en el alcance | Baja | Media | Baja | Aceptar | Proyecto individual sin usuarios reales: la recuperación es manual, desactivando MFA directamente en la BD. Los códigos de respaldo quedan como mejora futura, vía Registro de Cambios del Charter |
| R14 | Seguridad | El registro de auditoría (4.4) filtra datos sensibles (contraseñas, tokens, códigos TOTP escritos por accidente) o permite *log injection* mediante saltos de línea en el nombre de usuario | Media | Alta | Alta | Mitigar | Catálogo cerrado de eventos y campos (4.4.1); regla explícita de no registrar secretos y neutralizar saltos de línea (4.4.3); archivo de log ignorado por git (4.4.2). **Estado: Mitigado (Septiembre 2026)** — `src/audit.py`: la firma de `audit()` no acepta campos libres, así que un secreto no puede pasarse por accidente; cada evento se escribe como una línea JSON (`json.dumps` escapa saltos de línea y comillas) y el `username` se recorta a 64 caracteres. Verificado: un usuario con un salto de línea y un `login_success` falso quedó registrado en una sola línea, escapado, como `login_failure`. **Riesgo residual:** si alguien escribe su contraseña en el campo "Usuario" por error, queda en el log como `username` de un `login_failure` |

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
