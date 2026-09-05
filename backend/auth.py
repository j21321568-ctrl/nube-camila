"""
Módulo de Autenticación y Seguridad para la Nube Privada de Camila.
Implementa:
- Tokens de sesión criptográficos HMAC-SHA256 con protección contra timing attacks.
- Autenticación por Cabeceras (Authorization: Bearer, X-Auth-Token) y Cookies HttpOnly.
- Tokens efímeros de archivo único (Scoped Tokens) con TTL corto (120s) para streaming/descarga.
- Blindaje contra filtraciones: Rechazo de tokens de sesión maestros en URLs (query strings).
"""
import time
import json
import base64
import hmac
import hashlib
from typing import Optional
from fastapi import HTTPException, Header, Query, Request, status

from .config import ACCESS_PASSWORD, SECRET_KEY

# Duración del token de sesión: 30 días (en segundos)
TOKEN_EXPIRATION_SECONDS = 30 * 24 * 60 * 60

# Duración por defecto de tokens efímeros acotados: 120 segundos
EPHEMERAL_TOKEN_TTL_SECONDS = 120

def _base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")

def _base64url_decode(data_str: str) -> bytes:
    padding = 4 - (len(data_str) % 4)
    if padding != 4:
        data_str += "=" * padding
    return base64.urlsafe_b64decode(data_str.encode("utf-8"))

def verify_password(plain_password: str) -> bool:
    """Compara la contraseña en tiempo constante para evitar ataques de temporización."""
    if not plain_password:
        return False
    return hmac.compare_digest(plain_password.strip(), ACCESS_PASSWORD.strip())

def create_access_token(subject: str = "camila") -> str:
    """Crea un token de sesión maestro firmado con HMAC-SHA256."""
    payload = {
        "sub": subject,
        "type": "session",
        "iat": int(time.time()),
        "exp": int(time.time()) + TOKEN_EXPIRATION_SECONDS
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
    payload = {
        "sub": "camila",
        "type": "scoped",
        "file_id": file_id,
        "scope": scope,
        "iat": int(time.time()),
        "exp": int(time.time()) + ttl_seconds
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
    """Valida la integridad y vigencia de cualquier token firmado por la aplicación."""
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
        if time.time() > payload.get("exp", 0):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="El token ha expirado, por favor ingresa nuevamente",
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
        # Es un token sin acotamiento (p.ej. token maestro)
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
    - Intentar pasar el token de sesión maestro de 30 días en la query string (previene fugas en logs de Uvicorn/Render).
    - Tokens efímeros acotados a un archivo diferente.
    """
    # 1. Intentar autenticación por canales seguros (Header o Cookie)
    raw_session_token = None
    if authorization and authorization.lower().startswith("bearer "):
        raw_session_token = authorization.split(" ", 1)[1].strip()
    elif x_auth_token and x_auth_token.strip():
        raw_session_token = x_auth_token.strip()
    elif request.cookies.get("camila_session"):
        raw_session_token = request.cookies.get("camila_session")

    if raw_session_token:
        payload = verify_token(raw_session_token)
        # Si vino por cabecera/cookie y es válido, conceder acceso completo
        return payload

    # 2. Si no hay cabecera ni cookie, evaluar el query parameter ?token=...
    if token and token.strip():
        # Validar como token efímero acotado específicamente a este file_id
        return verify_scoped_token(token.strip(), expected_file_id=file_id, required_scope="file_access")

    # 3. Sin credenciales válidas
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Se requiere sesión activa o token efímero para acceder a este archivo",
        headers={"WWW-Authenticate": "Bearer"},
    )
