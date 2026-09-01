"""
Punto de entrada de la aplicacion.

Uso:
    python run.py

Ejecuta este archivo desde la raiz del repositorio (no desde dentro de src/),
para que el paquete `src` se pueda importar correctamente.
"""
from src.app import create_app
from src.database import init_db

app = create_app()

if __name__ == "__main__":
    # Crea la base de datos (tabla users) si todavia no existe.
    with app.app_context():
        init_db()

    # debug=True esta bien para desarrollo local (WBS Fase 1).
    # NUNCA debe usarse asi en produccion.
    app.run(debug=True, port=5000)
