"""
Módulo de Autenticación y Seguridad para la Nube Privada de Camila.
Implementa:
- Tokens de sesión criptográficos HMAC-SHA256 acotados a 8 horas (C3).
- Huella digital de contraseña (pwd_fp): Invalida automáticamente todos los tokens si se cambia ACCESS_PASSWORD.
- Session Epoch persistente: Revocación global de sesiones con un clic ("Cerrar sesión en todos los dispositivos").
- Autenticación por Cabeceras (Authorization: Bearer, X-Auth-Token) y Cookies HttpOnly seguras (C2).
- Tokens efímeros de archivo único (Scoped Tokens) con TTL corto (120s) para streaming/descarga (C2).
- Blindaje contra filtraciones: Rechazo de tokens de sesión maestros en URLs.
"""
import os
import time
import json
import base64
import hmac
import hashlib
from pathlib import Path
from typing import Optional
from fastapi import HTTPException, Header, Query, Request, status

from .config import ACCESS_PASSWORD, SECRET_KEY, ROOT_DIR

# Duración del token de sesión: 8 horas (en segundos)
TOKEN_EXPIRATION_SECONDS = 8 * 60 * 60

# Duración por defecto de tokens efímeros acotados: 120 segundos
EPHEMERAL_TOKEN_TTL_SECONDS = 120

SESSION_EPOCH_FILE = ROOT_DIR / ".session_epoch"

def _base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")

def _base64url_decode(data_str: str) -> bytes:
    padding = 4 - (len(data_str) % 4)
    if padding != 4:
        data_str += "=" * padding
    return base64.urlsafe_b64decode(data_str.encode("utf-8"))

def _get_password_fingerprint() -> str:
    """Genera una huella criptográfica de 16 caracteres de la contraseña maestra activa."""
    return hashlib.sha256(ACCESS_PASSWORD.strip().encode("utf-8")).hexdigest()[:16]

def get_session_epoch() -> int:
    """
    Obtiene el timestamp de epoch de sesión global en segundos enteros.
    Cualquier token emitido antes de este timestamp es considerado revocado.
    """
    if SESSION_EPOCH_FILE.exists():
        try:
            content = SESSION_EPOCH_FILE.read_text(encoding="utf-8").strip()
            if content:
                return int(float(content))
        except Exception:
            pass
    env_epoch = os.getenv("SESSION_EPOCH")
    if env_epoch and env_epoch.strip():
        try:
            return int(float(env_epoch.strip()))
        except Exception:
            pass
    return 0

def revoke_all_sessions() -> int:
    """
    Invalida inmediatamente todos los tokens de sesión en todos los dispositivos
    actualizando el epoch de sesión al segundo actual.
    """
    new_epoch = int(time.time())
    try:
        SESSION_EPOCH_FILE.write_text(str(new_epoch), encoding="utf-8")
    except Exception:
        os.environ["SESSION_EPOCH"] = str(new_epoch)
    return new_epoch

def verify_password(plain_password: str) -> bool:
    """Compara la contraseña en tiempo constante para evitar ataques de temporización."""
    if not plain_password:
        return False
    return hmac.compare_digest(plain_password.strip(), ACCESS_PASSWORD.strip())

def create_access_token(subject: str = "camila") -> str:
    """Crea un token de sesión maestro firmado con HMAC-SHA256 (Vigencia: 8 horas)."""
    now = int(time.time())
    payload = {
        "sub": subject,
        "type": "session",
        "pwd_fp": _get_password_fingerprint(),
        "iat": now,
        "exp": now + TOKEN_EXPIRATION_SECONDS
    }
    payload_bytes = json.dumps(payload, separators=(',', ':')).encode("utf-8")
    payload_b64 = _base64url_encode(payload_bytes)
    
    signature = hmac.new(
        SECRET_KEY.encode("utf-8"),
        payload_b64.encode("utf-8"),
        hashlib.sha256
    ).digest()
    sig_b64 = _base64url_encode(signature)
    
    return f"{payload_b64}.{sig_b64}"

def create_scoped_token(file_id: str, scope: str = "file_access", ttl_seconds: int = EPHEMERAL_TOKEN_TTL_SECONDS) -> str:
    """
    Crea un token efímero de corta duración (60-120s) acotado estrictamente a un file_id.
    Incluso si queda registrado en un log o historial, solo sirve para ese archivo específico
    y expira en un par de minutos.
    """
    now = int(time.time())
    payload = {
        "sub": "camila",
        "type": "scoped",
        "file_id": file_id,
        "scope": scope,
        "iat": now,
        "exp": now + ttl_seconds
    }
    payload_bytes = json.dumps(payload, separators=(',', ':')).encode("utf-8")
    payload_b64 = _base64url_encode(payload_bytes)
    
    signature = hmac.new(
        SECRET_KEY.encode("utf-8"),
        payload_b64.encode("utf-8"),
        hashlib.sha256
    ).digest()
    sig_b64 = _base64url_encode(signature)
    
    return f"{payload_b64}.{sig_b64}"

def verify_token(token: str) -> dict:
    """Valida la integridad, vigencia temporal, epoch y huella de contraseña de cualquier token."""
    if not token or "." not in token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token de acceso inválido o ausente",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    try:
        payload_b64, sig_b64 = token.split(".", 1)
        expected_sig = hmac.new(
            SECRET_KEY.encode("utf-8"),
            payload_b64.encode("utf-8"),
            hashlib.sha256
        ).digest()
        
        expected_sig_b64 = _base64url_encode(expected_sig)
        if not hmac.compare_digest(sig_b64, expected_sig_b64):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Firma de token inválida",
                headers={"WWW-Authenticate": "Bearer"},
            )
            
        payload = json.loads(_base64url_decode(payload_b64).decode("utf-8"))
        
        # 1. Comprobar expiración por tiempo
        if time.time() > payload.get("exp", 0):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="El token ha expirado, por favor ingresa nuevamente",
                headers={"WWW-Authenticate": "Bearer"},
            )
            
        # 2. Si es un token de sesión maestro, verificar epoch de revocación global
        if payload.get("type") == "session":
            token_iat = payload.get("iat", 0)
            current_epoch = get_session_epoch()
            if token_iat < current_epoch:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Tu sesión ha sido revocada globalmente. Por favor ingresa nuevamente.",
                    headers={"WWW-Authenticate": "Bearer"},
                )
                
            # 3. Comprobar si la contraseña fue cambiada desde la emisión del token
            token_pwd_fp = payload.get("pwd_fp")
            current_pwd_fp = _get_password_fingerprint()
            if token_pwd_fp and token_pwd_fp != current_pwd_fp:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="La contraseña de acceso fue modificada. Por seguridad, debes ingresar nuevamente.",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            
        return payload
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Error al procesar el token de seguridad",
            headers={"WWW-Authenticate": "Bearer"},
        )

def verify_scoped_token(token: str, expected_file_id: str, required_scope: str = "file_access") -> dict:
    """
    Valida un token efímero acotado a un archivo.
    Garantiza que el token no pueda reutilizarse para acceder a otros archivos.
    """
    payload = verify_token(token)
    token_file_id = payload.get("file_id")
    token_scope = payload.get("scope")
    
    if not token_file_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Token no acotado: los tokens maestros no están permitidos en parámetros de URL. Usa cabeceras, cookies o un token efímero.",
            headers={"WWW-Authenticate": "Bearer"},
        )
        
    if token_file_id != expected_file_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Token no autorizado para este archivo específico",
            headers={"WWW-Authenticate": "Bearer"},
        )
        
    if token_scope != required_scope and token_scope != "file_access":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Permisos insuficientes en el token efímero",
            headers={"WWW-Authenticate": "Bearer"},
        )
        
    return payload

def require_auth(
    request: Request,
    authorization: Optional[str] = Header(None),
    x_auth_token: Optional[str] = Header(None)
) -> dict:
    """
    Dependencia FastAPI que valida la sesión del usuario a través de canales seguros
    que NUNCA viajan en la URL:
    1. Header 'Authorization: Bearer <token>'
    2. Header 'X-Auth-Token: <token>'
    3. Cookie HttpOnly 'camila_session'
    """
    raw_token = None
    
    if authorization and authorization.lower().startswith("bearer "):
        raw_token = authorization.split(" ", 1)[1].strip()
    elif x_auth_token and x_auth_token.strip():
        raw_token = x_auth_token.strip()
    elif request.cookies.get("camila_session"):
        raw_token = request.cookies.get("camila_session")
        
    if not raw_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Autenticación requerida para acceder al espacio privado",
            headers={"WWW-Authenticate": "Bearer"},
        )
        
    return verify_token(raw_token)

def require_file_access(
    file_id: str,
    request: Request,
    authorization: Optional[str] = Header(None),
    x_auth_token: Optional[str] = Header(None),
    token: Optional[str] = Query(None)
) -> dict:
    """
    Dependencia de seguridad específica para streaming y descarga de archivos (/preview y /download).
    
    Acepta:
    1. Canales seguros directos: Header Authorization, Header X-Auth-Token, o Cookie HttpOnly 'camila_session'.
    2. Parámetro de URL '?token=...': ÚNICAMENTE si es un token efímero acotado a este 'file_id' (TTL 120s).
    
    Rechaza tajantemente:
    - Intentar pasar el token de sesión maestro en la query string (previene fugas en logs de Uvicorn/Render).
    - Tokens efímeros acotados a un archivo diferente.
    """
    raw_session_token = None
    if authorization and authorization.lower().startswith("bearer "):
        raw_session_token = authorization.split(" ", 1)[1].strip()
    elif x_auth_token and x_auth_token.strip():
        raw_session_token = x_auth_token.strip()
    elif request.cookies.get("camila_session"):
        raw_session_token = request.cookies.get("camila_session")

    if raw_session_token:
        payload = verify_token(raw_session_token)
        return payload

    if token and token.strip():
        return verify_scoped_token(token.strip(), expected_file_id=file_id, required_scope="file_access")

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Se requiere sesión activa o token efímero para acceder a este archivo",
        headers={"WWW-Authenticate": "Bearer"},
    )
