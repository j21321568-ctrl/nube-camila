"""
Configuración central de la Nube Privada de Camila.
Diseñado para funcionar sin problemas tanto en desarrollo local como en plataformas
cloud (Render, Railway, Heroku, VPS) mediante Variables de Entorno.
"""
import os
import json
import base64
from pathlib import Path

# Intentar cargar python-dotenv si está disponible
try:
    from dotenv import load_dotenv
    # Buscar .env en la raíz del proyecto
    root_dir = Path(__file__).resolve().parent.parent
    env_file = root_dir / ".env"
    if env_file.exists():
        load_dotenv(env_file)
    else:
        load_dotenv()
except ImportError:
    pass

ROOT_DIR = Path(__file__).resolve().parent.parent

# 1. Contraseña maestra de acceso
ACCESS_PASSWORD = os.getenv("ACCESS_PASSWORD", "camila2026")

# 2. Clave secreta para firmar tokens de sesión
SECRET_KEY = os.getenv("SECRET_KEY", "camila-cloud-super-secure-token-vault-key-2026")

# 3. Puerto y Host
PORT = int(os.getenv("PORT", 8000))
HOST = os.getenv("HOST", "0.0.0.0")

# 4. Orígenes CORS permitidos (Vercel, GitHub Pages, Localhost, etc.)
CORS_ORIGINS_ENV = os.getenv("CORS_ORIGINS", "*")
if CORS_ORIGINS_ENV.strip() == "*":
    CORS_ORIGINS = ["*"]
else:
    CORS_ORIGINS = [orig.strip() for orig in CORS_ORIGINS_ENV.split(",") if orig.strip()]

# 5. ID de la Carpeta de Google Drive
def get_drive_folder_id() -> str:
    env_folder = os.getenv("DRIVE_FOLDER_ID")
    if env_folder and env_folder.strip():
        return env_folder.strip()
    
    # Buscar en archivo Folder-ID.txt
    folder_file_candidates = [
        ROOT_DIR / "Folder-ID.txt",
        Path("Folder-ID.txt"),
    ]
    for candidate in folder_file_candidates:
        if candidate.exists():
            try:
                content = candidate.read_text(encoding="utf-8").strip()
                if content:
                    return content
            except Exception:
                pass
    
    raise RuntimeError("No se encontró el Folder ID de Google Drive. Configura DRIVE_FOLDER_ID en variables de entorno o crea Folder-ID.txt")

# 6. Obtener Credenciales de Cuenta de Servicio
def get_service_account_info() -> dict:
    """
    Carga las credenciales de Google Service Account en orden de prioridad:
    1. Variable de entorno GOOGLE_CREDENTIALS_JSON (ideal para Render/Railway)
    2. Variable de entorno GOOGLE_CREDENTIALS_BASE64 (base64 de credentials.json)
    3. Archivo físico credentials.json (desarrollo local)
    """
    # Opción 1: JSON directo en variable de entorno
    raw_json = os.getenv("GOOGLE_CREDENTIALS_JSON")
    if raw_json and raw_json.strip():
        try:
            return json.loads(raw_json.strip())
        except Exception as e:
            raise ValueError(f"Error al decodificar GOOGLE_CREDENTIALS_JSON: {e}")

    # Opción 2: Base64 en variable de entorno
    raw_b64 = os.getenv("GOOGLE_CREDENTIALS_BASE64")
    if raw_b64 and raw_b64.strip():
        try:
            decoded = base64.b64decode(raw_b64.strip()).decode("utf-8")
            return json.loads(decoded)
        except Exception as e:
            raise ValueError(f"Error al decodificar GOOGLE_CREDENTIALS_BASE64: {e}")

    # Opción 3: Archivo credentials.json local
    file_candidates = [
        os.getenv("CREDENTIALS_FILE"),
        ROOT_DIR / "credentials.json",
        Path("credentials.json"),
    ]
    for candidate in file_candidates:
        if candidate and Path(candidate).exists():
            try:
                with open(candidate, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                raise ValueError(f"Error al leer archivo de credenciales {candidate}: {e}")

    raise RuntimeError(
        "No se encontraron credenciales de Google Drive. Configura GOOGLE_CREDENTIALS_JSON en producción o coloca credentials.json en la raíz del proyecto."
    )
