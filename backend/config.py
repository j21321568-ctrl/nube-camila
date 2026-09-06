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

# Lista negra de valores por defecto conocidos o comprometidos
INSECURE_SECRETS_BLACKLIST = {
    "camila2026",
    "camila-cloud-super-secure-token-vault-key-2026",
    "camila-cloud-super-secret-token-vault-2026",
    "changeme",
    "admin",
    "password",
    "12345678",
    "secret",
    "default",
}

def _require_secret_env(name: str, min_length: int = 16) -> str:
    """
    Obtiene una variable de entorno crítica de seguridad aplicando arquitectura Fail-Closed:
    1. Verifica que la variable esté definida y no esté vacía.
    2. Exige una longitud mínima segura.
    3. Rechaza valores predeterminados o comprometidos de la lista negra.
    Lanza RuntimeError para impedir que el servidor arranque en un estado inseguro.
    """
    val = os.getenv(name)
    if not val or not val.strip():
        raise RuntimeError(
            f"❌ ERROR CRÍTICO DE SEGURIDAD (FAIL-CLOSED): Falta definir la variable de entorno obligatoria '{name}'. "
            f"El servidor no arrancará sin una clave explícita y segura. Define '{name}' en tu archivo .env o en el panel de Render/Railway."
        )
    val = val.strip()
    if len(val) < min_length:
        raise RuntimeError(
            f"❌ ERROR CRÍTICO DE SEGURIDAD: La variable '{name}' es demasiado corta ({len(val)} caracteres). "
            f"Se requiere un mínimo de {min_length} caracteres para garantizar entropía criptográfica adecuada."
        )
    if val.lower() in INSECURE_SECRETS_BLACKLIST:
        raise RuntimeError(
            f"❌ ERROR CRÍTICO DE SEGURIDAD: La variable '{name}' contiene un valor por defecto inseguro o comprometido ('{val}'). "
            f"Genera una clave criptográfica segura ejecutando: python tools/generate_secrets.py"
        )
    return val

# 1. Contraseña maestra de acceso (Mínimo 12 caracteres, fail-closed)
ACCESS_PASSWORD = _require_secret_env("ACCESS_PASSWORD", min_length=12)

# 2. Clave secreta para firmar tokens de sesión HMAC-SHA256 (Mínimo 32 caracteres, fail-closed)
SECRET_KEY = _require_secret_env("SECRET_KEY", min_length=32)

# 3. Puerto y Host
PORT = int(os.getenv("PORT", 8000))
HOST = os.getenv("HOST", "0.0.0.0")

# 4. Orígenes CORS permitidos (Vercel, GitHub Pages, Localhost, etc.)
CORS_ORIGINS_ENV = os.getenv("CORS_ORIGINS", "*")
if CORS_ORIGINS_ENV.strip() == "*":
    CORS_ORIGINS = ["*"]
else:
    CORS_ORIGINS = [orig.strip() for orig in CORS_ORIGINS_ENV.split(",") if orig.strip()]

# 5. Configuración de Cookies de Sesión (SameSite: lax, none, strict)
COOKIE_SAMESITE = os.getenv("COOKIE_SAMESITE", "lax").lower().strip()
if COOKIE_SAMESITE not in ("lax", "strict", "none"):
    COOKIE_SAMESITE = "lax"

# 6. Scope de permisos de Google Drive (Principio de Mínimo Privilegio - H5)
# Por defecto 'drive.file': restringe acceso únicamente a archivos gestionados por la app
DRIVE_SCOPES = [os.getenv("GOOGLE_DRIVE_SCOPE", "https://www.googleapis.com/auth/drive.file").strip()]

# 7. ID de la Carpeta de Google Drive
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
