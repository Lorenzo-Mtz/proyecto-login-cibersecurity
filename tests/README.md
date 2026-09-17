# Pruebas automatizadas

Suite de regresión de los controles de seguridad de la Fase 2. Cada archivo
corresponde a un paquete del WBS y conserva la verificación con la que ese
paquete se dio por cerrado.

## Cómo correrlas

```powershell
cd C:\Users\loren\Proyecto\proyecto-login-cibersecurity
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pytest
```

Un archivo suelto, o una prueba suelta:

```powershell
pytest tests/test_bruteforce.py
pytest tests/test_bruteforce.py::test_sin_oraculo_por_latencia
```

La suite tarda ~100 s. Casi todo es bcrypt con cost 12: cada login cuesta
~330 ms **a propósito**, y `test_el_bloqueo_expira_solo` espera 11 s reales a
que venza una ventana. No es lentitud accidental.

Nada toca `instance/`: cada prueba recibe una base de datos y un log de
auditoría nuevos en un directorio temporal.

## Qué hay en cada archivo

| Archivo | WBS | Qué cubre |
|---|---|---|
| `conftest.py` | — | Fixtures compartidas: la app aislada, el cliente HTTP, la conexión a la BD, un usuario de prueba y el lector del log |
| `test_bruteforce.py` | 4.1 | Protección contra fuerza bruta y bloqueo temporal (R10) |
| `test_audit.py` | 4.4 | Registro de auditoría: formato, catálogo cerrado y *log injection* (R14) |
| `test_session.py` | 4.5.2 | `@login_required` e invalidación real de sesión con `session_version` (R9) |
| `test_csrf.py` | 4.5.3 | Tokens CSRF, logout solo por POST y *open redirect* |

Cada archivo abre con un docstring que explica **qué propiedad prueba y qué
pasaría si esa propiedad se rompiera**. Esa es la parte que hay que leer antes
de tocar una prueba: dice para qué existe, no solo qué hace.

## Por qué existe esta carpeta

Durante las Fases 1 y 2 cada paquete se verificó con un script temporal fuera
del proyecto que después se borraba. El resultado era que el proyecto podía
contestar *"¿funcionó aquel día?"*, pero no *"¿sigue funcionando?"*.

El problema es concreto: **tres de las propiedades que aquí se verifican son
invisibles al probar en el navegador.**

- Que un login bloqueado y uno fallido tarden lo mismo. Nadie distingue 340 ms
  a ojo. Si alguien quita el `bcrypt.checkpw` contra `DUMMY_HASH` del camino
  bloqueado —parece código muerto, su resultado se descarta— vuelve el oráculo
  por latencia y la aplicación se sigue viendo idéntica.
- Que un intento bloqueado no se registre. Hacen falta 8 intentos seguidos y
  mirar la tabla para notarlo.
- Que una cookie copiada antes del logout deje de servir después. Requiere
  guardar la cookie, cerrar sesión y reinyectarla.

Además, los paquetes que siguen vuelven sobre este mismo código: **4.2.6** llama
a `reset_attempts` y **4.3.5** reutiliza el contador de intentos.

## Cómo se escriben las pruebas aquí

Tres criterios que salieron de errores reales:

**Probar el efecto, no la respuesta.** Que un POST sin token CSRF devuelva una
redirección no prueba nada; lo que se comprueba es que la cuenta *no se creó* y
que la sesión *no se inició*.

**Preferir hechos concretos a agregados** (LL10). Un `COUNT(*)` puede quedar
igual porque dos errores se cancelaron: en `test_intento_bloqueado_no_prolonga_el_bloqueo`
se compara `MAX(id)`, que distingue "no se insertó nada" de "se insertó una fila
y se borró otra".

**Cuidar los márgenes de tiempo** (LL10). Una ventana más corta que el costo de
la operación que se mide hace que la prueba mida otra cosa. `VENTANA = 10` en
`test_bruteforce.py` es holgada frente a los ~330 ms de cada request; bajarla
rompe las pruebas por una razón que no tiene nada que ver con el código.

## Qué falta

- **WBS 4.5.1** (`SECRET_KEY` obligatoria) no tiene pruebas. `validate_secret_key`
  es una función pura y son cuatro asserts: clave ausente, el valor de ejemplo
  de `.env.example`, una de menos de 32 caracteres y una válida.
- El registro (`/register`) solo se ejercita de paso. Sus validaciones propias
  —email, longitud de contraseña, límite de 72 bytes, confirmación— no tienen
  pruebas dedicadas.
