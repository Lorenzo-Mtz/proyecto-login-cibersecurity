# Pruebas automatizadas

Suite de regresión de los controles de seguridad de la Fase 2. Cada archivo
corresponde a un paquete del WBS y conserva la verificación con la que ese
paquete se dio por cerrado.

## Cómo correrlas

```powershell
cd C:\Users\loren\Proyecto\proyecto-login-cibersecurity
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt -r requirements-dev.txt
pytest
```

Un archivo suelto, o una prueba suelta:

```powershell
pytest tests/test_bruteforce.py
pytest tests/test_bruteforce.py::test_sin_oraculo_por_latencia
```

La suite son 130 pruebas y tarda ~130 s. Casi todo es bcrypt con cost 12: cada
login cuesta ~330 ms **a propósito**, y seis pruebas esperan tiempo real a que
venza algo (`test_el_bloqueo_expira_solo`, 11 s; `test_un_token_expirado_es_rechazado`,
3 s; `test_la_sesion_pendiente_caduca`, 2 s; las tres de caducidad de sesión de
`test_session_expiry.py`, 3 s cada una). No es lentitud accidental.

**El tiempo total no es señal de nada.** En la misma máquina y con el mismo
código se han medido 96 s, 128 s, 140 s y 202 s en una sola sesión. La variación
es del sistema operativo (LL21), no del proyecto: no salgas a buscar una
regresión de rendimiento a partir de una corrida lenta.

Las pruebas de TOTP **no esperan** a que cambie el periodo: `verificar_codigo()`
recibe el reloj como parámetro (`ahora=`), así que la ventana de ±1 se prueba
parándose en un instante fijo.

**Si una prueba con ventana temporal falla, re-córrela antes de mirar el diff.**
`VENTANA = 10` es holgada frente a los ~330 ms de bcrypt, pero no frente a un
atascón del sistema operativo: un parón de cinco minutos a media corrida hace
que la ventana expire y la prueba mida otra cosa. Ya pasó una vez (LL21).

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
| `test_password_reset.py` | 4.2 | Recuperación de contraseña: un solo uso, expiración, sin enumeración de cuentas y sin fuga del token (R11) |
| `test_mfa.py` | 4.3 | Segundo factor TOTP: ventana de ±1 periodo, rechazo de códigos reutilizados, login en dos pasos y límite de intentos (R4, R12) |
| `test_headers.py` | 6.1 | Cabeceras de seguridad en toda respuesta, y la CSP estricta que permite `data:` solo en imágenes (gap G1) |
| `test_errors.py` | 6.4 | Manejadores de 404 y 500: no filtran detalle, el 500 se audita sin traceback y las cabeceras salen también en los errores (gap G4) |
| `test_register.py` | 6.6 | Política del nombre de usuario por lista blanca, límites de longitud y validación del email (gap G6) |
| `test_session_expiry.py` | 4.5.4 | Caducidad de la sesión: expiración por inactividad y vida máxima que la actividad no renueva (R9) |

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

**Ver fallar la prueba antes de creerle** (LL14), **y por la razón correcta**
(LL30). Al cerrar un paquete se rompe cada control a propósito —una mutación a
la vez, revirtiendo después— y se confirma que la prueba correspondiente se pone
en rojo. Que la suite enrojezca no basta: si el fallo es un `TypeError` al
arrancar, la mutación rompió el arranque y no el control, y hay que rehacerla. Así se descubrió que
`test_se_marca_la_fila_del_token_usado_y_no_otra` pasaba con el bug puesto: en
datos de prueba pequeños los ids coinciden por accidente y tapan justo los
errores de "columna equivocada". Por eso ahora esa prueba emite los tokens en
un orden que desalinea los ids, con un `assert` que lo verifica.

**Cuidar los márgenes de tiempo** (LL10). Una ventana más corta que el costo de
la operación que se mide hace que la prueba mida otra cosa. `VENTANA = 10` en
`test_bruteforce.py` es holgada frente a los ~330 ms de cada request; bajarla
rompe las pruebas por una razón que no tiene nada que ver con el código.

## Qué falta

- **WBS 4.5.1** (`SECRET_KEY` obligatoria) no tiene pruebas. `validate_secret_key`
  es una función pura y son cuatro asserts: clave ausente, el valor de ejemplo
  de `.env.example`, una de menos de 32 caracteres y una válida.
- ~~El registro (`/register`) se ejercita solo en parte.~~ **Resuelto en 6.6:**
  `test_register.py` cubre la política del nombre de usuario y el formato del
  email. Sigue sin prueba propia el límite de 72 bytes de bcrypt.
- **WBS 6.2**: el prefijo `__Host-` de la cookie **no se puede verificar aquí**.
  El test client de Werkzeug no implementa las reglas de prefijo, así que
  aceptaría una cookie que un navegador rechazaría. La prueba comprueba el
  nombre y los atributos; la verificación real es **manual, en un navegador**.
  Es un tercer tipo de hueco, distinto de los dos de abajo: no es que el
  control sea difícil de medir, es que **el arnés no implementa la regla**.
  **Comprobado a mano el 25 de septiembre de 2026** en `http://127.0.0.1:5000`
  con una cuenta sin MFA: el login funcionó, el navegador aceptó la cookie. La
  comprobación hay que rehacerla si cambia el nombre de la cookie o si importa
  otro navegador.
- **WBS 4.2**: falta cubrir el riesgo residual, cuando se atienda — que pedir
  enlaces en serie no deba poder mantener invalidado el de la víctima.
- **WBS 4.5.4**: el camino con MFA no tiene prueba de caducidad **propia**.
  Quitar `login_at` de `mfa_verify()` sí se atrapa, pero por rebote: lo detecta
  `test_mfa.py::test_el_login_completo_con_mfa_abre_sesion`, que asevera un 200
  en `/dashboard`. Es cobertura real e incidental; si alguien reorganiza ese
  archivo, se pierde sin que nada lo señale.
- **WBS 4.3**: sustituir `hmac.compare_digest` por `==` en `mfa.py` **no lo
  atrapa ninguna prueba** — medido con una mutación, no supuesto. Medir
  microsegundos sobre seis dígitos dentro del mismo proceso no da una señal
  estable, a diferencia de los ~330 ms de bcrypt que sí sostienen
  `test_sin_oraculo_por_latencia`. Ese control se sostiene por revisión de
  código; está comentado en `mfa.py` para que quien lo toque sepa qué rompe.
