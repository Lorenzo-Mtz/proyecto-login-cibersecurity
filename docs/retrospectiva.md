# Retrospectiva general del proyecto

**Proyecto:** Sistema de Login Seguro — Proyecto de Aprendizaje en Ciberseguridad
**Paquete:** WBS 7.3 — Cierre del Proyecto
**Fecha:** 25 de septiembre de 2026
**Preparado por:** Lorenzo Mtz

> **Qué es este documento.** El cierre formal del proyecto. Compara lo que el Charter
> prometió contra lo que existe, deja los números y separa lo que funcionó de lo que no.
> No es un resumen de logros: un cierre que solo enumera aciertos no sirve para planear
> el siguiente proyecto, que es para lo que existe un cierre.

---

## 1. Lo que el Charter prometió y lo que hay

### 1.1 Objetivos

| Obj | Qué pedía | Estado | Nota |
|---|---|---|---|
| **O1** | Login funcional con **calidad de UX/UI de nivel comercial** | **No cumplido** | Funcional sí; "nivel comercial" no. 102 líneas de CSS y 9 plantillas sin trabajo de diseño. Ver 4.1 |
| **O2** | Mecanismos de seguridad estándar (OWASP Top 10 / ASVS L1 como referencia) | **Cumplido, con seis incumplimientos documentados** | 38 de 44 requisitos de Nivel 1 con veredicto en `pass`. Los seis `fail` restantes están nombrados, priorizados y con dueño |
| **O3** | Documentación PMBOK con artefactos reales | **Cumplido y excedido** | Charter, Scope Statement, WBS, Risk Register y Lessons Learned, más tres documentos de evaluación que no estaban previstos |
| **O4** | Glosario bilingüe actualizado de forma continua | **Cumplido** | 134 términos. Lo de "continua" se sostuvo hasta el final: la última sección entró en este mismo cierre |

### 1.2 Criterios de éxito (Charter, sección 3)

Los nueve puntos de la *definition of done* están implementados y cubiertos por pruebas:

| Criterio | Dónde vive | Pruebas |
|---|---|---|
| Registro con validación de entrada y política de contraseñas | `auth.register`, `validar_username()` | `test_register.py` |
| Login con bcrypt y mensajes que no filtran información | `auth.login` | `test_bruteforce.py`, `test_session.py` |
| Logout con invalidación real de sesión | `session_version` en servidor | `test_session.py` |
| Recuperación por token de un solo uso con expiración | `reset_tokens.py` | `test_password_reset.py` |
| Cookies `HttpOnly`, `Secure`, `SameSite` | `config.py`, prefijo `__Host-` | `test_session.py`, `test_headers.py` |
| Protección contra fuerza bruta | `throttle.py` | `test_bruteforce.py` |
| MFA por TOTP | `mfa.py` | `test_mfa.py` |
| Registro de auditoría | `audit.py` — 16 eventos, con rotación | `test_audit.py` |
| **Autoevaluación documentada contra ASVS Level 1** | `docs/fase3-asvs-l1.md` | — |

El último era el "de forma adicional" del Charter. Terminó siendo el entregable que más cambió el proyecto: de ahí salieron la consolidación de gaps y la Fase 4 entera.

---

## 2. Los números

### 2.1 Tamaño

| | |
|---|---|
| Duración | 18 de agosto – 25 de septiembre de 2026 (**38 días**) |
| Commits | 39, contando el del cierre |
| Archivos versionados | 59 |
| Código de aplicación | **1 263 líneas** de Python — 10 módulos, 10 rutas, 9 plantillas |
| Pruebas | **2 116 líneas**, 130 pruebas en 10 archivos |
| Documentación | **2 980 líneas** (~49 600 palabras) en 14 documentos, incluido este |
| Dependencias de ejecución | 8 paquetes directos |

Dos proporciones describen el proyecto mejor que cualquier párrafo: **1,7 líneas de prueba por línea de código**, y **más documentación que aplicación**. Para un proyecto de aprendizaje con propósito doble —seguridad y PMBOK— eso es coherencia, no desbalance. En un proyecto de producto sería una señal de alarma.

### 2.2 Gestión

| Artefacto | Resultado |
|---|---|
| Cambios de alcance registrados | **6**, ninguno reescrito después |
| Riesgos en el registro | **20** — 8 mitigados, 2 cerrados, 2 aceptados, 3 abiertos, 5 de gestión atendidos de forma continua |
| Lecciones aprendidas | **31** |
| Etiquetas de fase | 5 (`fase-0` … `fase-4`) |
| Hitos alcanzados | M0 – M6 |

### 2.3 Evaluación de seguridad

| Ejercicio | Qué produjo |
|---|---|
| Recorrido OWASP Top 10:2025 (4.5.6) | 10 categorías, **5 huecos** que ningún artefacto registraba |
| Threat model STRIDE (5.2) | **36 amenazas**, 14 sin control, en 3 causas raíz |
| Autoevaluación ASVS 5.0.0 Level 1 (5.3) | **70 requisitos**, 44 con veredicto, 12 `fail` |
| Consolidación (5.4) | **23 gaps** priorizados: 7 de Nivel 1, 6 de Nivel 2, 10 de Nivel 3 |
| Fase 4 — remediación acotada | **7 de 7** gaps de Nivel 1 cerrados |

Resultado ASVS: de **32 `pass` / 12 `fail`** (73 %) a **38 / 6** (86 %) sobre los requisitos con veredicto.

---

## 3. Qué funcionó

**Desglosar antes de programar, y solo la fase siguiente.** El *rolling wave* no fue decorativo: la Fase 2 se desglosó al cerrar la Fase 1, la Fase 3 al cerrar la Fase 2, y dentro de la Fase 3 el paquete 5.3.5 esperó a que 5.3.1 diera el número real de requisitos aplicables. Esa última espera evitó planear contra una estimación que resultó estar **cuatro veces mal** (LL26).

**Romper cada control a propósito.** La disciplina de mutación (LL14) es lo que separa "la prueba pasa" de "la prueba prueba algo". Encontró pruebas que pasaban sin cubrir nada, y en la Fase 4 se refinó: no basta con que la suite se ponga roja, tiene que ponerse roja **por la aserción correcta** (LL30). Su corolario también funcionó: cuando una mutación no queda atrapada, el hueco se documenta en el código, en `tests/README.md` y en el Risk Register, en vez de inventar una prueba frágil (LL22).

**Tres marcos de evaluación en vez de uno, y en ese orden.** Es el hallazgo metodológico del proyecto. Cada uno vio cosas que los otros no:

- El **Top 10** y el **threat model** evalúan lo que existe; el **ASVS** es el único que pregunta por lo que falta — y lo que solo él encontró fueron **ausencias**, no debilidades.
- El **threat model** encontró que el registro de auditoría no sostiene no repudio (R18), un hallazgo que el ASVS Level 1 **no podía ver**: el capítulo V16 no aporta ni un requisito a ese nivel (LL28).
- Lo que apareció en **los tres** —el token de recuperación viajando en la URL— es el hallazgo más sólido del inventario, precisamente porque tres métodos distintos llegaron a él por caminos distintos.

**Umbrales en la configuración, no en el código.** Cada límite —intentos, ventanas, vidas de sesión, tamaño del log— vive en `config.py`. La razón no fue la elegancia: es lo que permite que una prueba lo baje a segundos o a bytes y **observe el control ocurrir de verdad**, en vez de confiar en que ocurrirá dentro de una hora.

**No reescribir el pasado.** Ni una entrada del registro de cambios, ni una evaluación de la Fase 3. Cuando la Fase 4 corrigió seis requisitos, el documento ASVS **conservó el veredicto original** y marcó `fail → pass` al lado: un documento de auditoría que se sobrescribe deja de poder demostrar qué se corrigió. Lo mismo con el cambio #5 del Charter, que quedó apuntando a unos números de WBS que el cambio #6 movió — se anotó en el #6, no se editó el #5.

**Decidir el alcance como decisión de alcance.** Con 23 gaps sobre la mesa, la pregunta "¿cuáles?" no se resolvió técnicamente sino en el Charter, con justificación escrita, y se eligió el Nivel 1 completo por encima de un Nivel 2 parcial. Con 4–8 h/semana el riesgo real no era fallar: era quedarse a medias (R16).

---

## 4. Qué no funcionó

### 4.1 Un objetivo sin criterio medible no se cumple, y nadie lo nota

**O1 pedía "calidad de UX/UI de nivel comercial" y el proyecto entregó 102 líneas de CSS.** No hubo un momento en que se decidiera abandonarlo: simplemente nunca compitió por tiempo, porque era el único objetivo sin criterio de aceptación. Los otros tres tenían uno verificable —una lista de nueve mecanismos, una lista de artefactos, un glosario— y los tres se cumplieron.

El propio Charter lo había anticipado en su sección 6: *"alcance ambiguo ('calidad de mercado') puede generar scope creep"*. Se equivocó de dirección. La ambigüedad no produjo exceso de trabajo, produjo **cero**. Es el hallazgo de gestión más útil del proyecto: un objetivo sin criterio de aceptación no genera desbordamiento, genera silencio.

### 4.2 Anotar un pendiente no es gestionarlo

Tres pendientes quedaron abiertos al cerrar la Fase 0 en agosto y se saldaron **más de un mes después**, en este cierre. Estuvieron escritos todo ese tiempo en una lista que nadie revisaba, porque no era la lista de nadie. Lo que finalmente los desbloqueó no fue recordarlos: fue **darles dueño en el WBS**, como paquetes 7.1 y 7.2 (LL31).

Y la parte incómoda: al revisarlos, **uno de los tres ya estaba resuelto** y la lista llevaba semanas diciendo lo contrario. Una lista de pendientes sin revisar miente en las dos direcciones.

### 4.3 El ritmo fue muy desigual, y no por la razón prevista

Las Fases 0, 1 y 2 tomaron cinco semanas. Las Fases 3 y 4 —threat model, autoevaluación de 70 requisitos, consolidación de 23 gaps y la remediación de siete— **cupieron en un solo día**. El Charter avisó del riesgo contrario (R2: subestimar el endurecimiento), y ese sí se cumplió: la Fase 2 fue la más larga con diferencia.

Lo que no se anticipó es que documentar sobre código ya escrito avanza a otra velocidad. La lectura útil no es "las fases de documentación son baratas": es que **evaluar es barato comparado con construir, y por eso conviene evaluar seguido**, no una sola vez al final y como stretch goal.

### 4.4 Errores de proceso que costaron trabajo real

Vale la pena nombrarlos porque ninguno fue un error de seguridad — todos fueron de método:

- **`git checkout` sobre trabajo sin commitear** destruyó la implementación de un paquete completo. Se recuperó, pero invalidó dos mutaciones que hubo que rehacer.
- **Una mutación que rompía el arranque** en lugar del control puso la suite en rojo sin probar nada, y por poco se da por buena porque *el color era el correcto* (LL30).
- **Una prueba afirmaba algo falso** sobre la rotación del log —que sobrevivían 30 de 40 eventos, cuando sobreviven 10— y pasaba igual. Rotar acota el disco **descartando**, y la prueba no decía qué se descarta.
- **Tres pruebas correctas se rompieron** al mejorar el código, porque fijaban valores absolutos en vez de medir la propiedad que decían verificar (LL29).
- Varias veces se afirmó que algo estaba pendiente **cuando ya estaba hecho** (LL24), que es la versión activa del problema de 4.2.

El patrón común: **el error caro no fue equivocarse, fue no verificar antes de afirmar.** Nueve de las 31 lecciones son sobre diseño o verificación de pruebas.

---

## 5. Lo que queda abierto

Este proyecto **no entrega un sistema listo para producción**, y el cierre debe decirlo con precisión en vez de con una advertencia genérica.

### 5.1 Seis requisitos ASVS Level 1 en `fail`

| Problema | Requisitos | Gap | Nivel |
|---|---|---|---|
| No hay cambio de contraseña autenticado | V6.2.2, V6.2.3 | G8 | 2 |
| Nada frena el *credential stuffing* | V6.2.4, V6.3.1 | G9 | 2 |
| El token de recuperación viaja en la URL | V14.2.1 | G10 | 2 |
| Sin HSTS | V3.4.1 | G14 | 3 |

Cinco son de Nivel 2 y quedaron fuera por decisión registrada (Charter, cambio #6). El sexto **no se puede cerrar sin despliegue**: emitir `Strict-Transport-Security` sobre HTTP plano no protege y sí puede dejar el sitio inalcanzable.

### 5.2 Lo que falta no es solo esa lista

- **No hay TLS.** `SESSION_COOKIE_SECURE` y el prefijo `__Host-` están declarados, pero sobre `localhost` el navegador los acepta por excepción. **Los controles de transporte hoy son declarativos**, y el atacante intermediario (P4 del threat model) no encuentra nada que lo estorbe.
- **Nadie lee el registro de auditoría.** Se escribe bien, se rota y no filtra detalle — y no existe nada que aplique un umbral ni que dispare una alerta. Es A09 del Top 10 y sigue abierto (R18).
- **El registro tampoco sostiene no repudio**: quien alcance el disco puede escribirlo. Cerrarlo exige enviarlo fuera del alcance de escritura de la aplicación, que es infraestructura.
- **SQLite y un solo proceso.** Fue una decisión explícita de aprendizaje, no un descuido, pero fija el techo de lo que este código puede sostener.
- **Diez gaps de Nivel 3** esperan a que exista un despliegue real. Hasta entonces no son deuda: son alcance futuro correctamente excluido.

### 5.3 Si hubiera una Fase 5

En orden de rendimiento por hora invertida: **G8** (cambio de contraseña autenticado — es la ausencia más visible para un usuario real), **G10** (sacar el token de recuperación de la URL), **G9** (frenar el *credential stuffing*), y solo después el Nivel 3, que no tiene sentido antes de que exista despliegue. Y, fuera de la lista de seguridad, **O1**: darle a la interfaz un criterio de aceptación verificable antes de tocarla.

---

## 6. Cierre

El proyecto cumple su propósito doble. Del lado de seguridad, entrega un sistema de autenticación con los mecanismos estándar implementados y **verificados por 130 pruebas que se rompieron a propósito, una por una**, más un inventario honesto de lo que le falta. Del lado de gestión, entrega un expediente PMBOK capaz de reconstruir por qué se tomó cada decisión: seis cambios de alcance justificados, 20 riesgos seguidos hasta su estado final y 31 lecciones con su causa.

Lo que más se aprendió no fue un control en particular. Fue que **la seguridad de un sistema no se mide por lo que implementa, sino por lo que puede demostrar** — y que la distancia entre las dos cosas es exactamente el trabajo de las Fases 3 y 4, las dos que empezaron siendo opcionales.

**Estado del proyecto: cerrado.**

---

*WBS 7.3 — Retrospectiva general. Cierra el hito M6 y con él el proyecto.*
