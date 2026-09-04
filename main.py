"""
Punto de entrada principal para ejecutar la aplicación localmente.
Permite ejecutar 'python main.py' o 'uvicorn main:app --reload'.
"""
import sys
from pathlib import Path

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Asegurar que el directorio raíz esté en sys.path
root_path = Path(__file__).resolve().parent
if str(root_path) not in sys.path:
    sys.path.insert(0, str(root_path))

from backend.main import app
from backend.config import PORT, HOST

if __name__ == "__main__":
    import uvicorn
    print(f"✨ Iniciando la Nube Privada de Camila en http://127.0.0.1:{PORT}")
    uvicorn.run("backend.main:app", host="127.0.0.1", port=PORT, reload=True)
