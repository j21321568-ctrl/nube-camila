"""
Módulo de Autenticación y Seguridad para la Nube Privada de Camila.
Implementa tokens criptográficos HMAC-SHA256 con expiración, protección contra timing attacks
y soporte flexible de tokens vía Headers o Query Params (esencial para streaming multimedia).
"""
import time
import json
import base64
import hmac
import hashlib
from typing import Optional
from fastapi import HTTPException, Header, Query, status

from .config import ACCESS_PASSWORD, SECRET_KEY

# Duración del token de sesión: 30 días (en segundos)
TOKEN_EXPIRATION_SECONDS = 30 * 24 * 60 * 60

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
    """Crea un token de sesión seguro firmado con HMAC-SHA256."""
    payload = {
        "sub": subject,
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

def verify_token(token: str) -> dict:
    """Valida la integridad y vigencia de un token de acceso."""
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
                detail="La sesión ha expirado, por favor ingresa nuevamente",
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

def require_auth(
    authorization: Optional[str] = Header(None),
    x_auth_token: Optional[str] = Header(None),
    token: Optional[str] = Query(None)
) -> dict:
    """
    Dependencia FastAPI que extrae y valida el token de autenticación desde:
    1. Header 'Authorization: Bearer <token>'
    2. Header 'X-Auth-Token: <token>'
    3. Query parameter '?token=<token>' (Permite visualización de imágenes y streaming de audio/video)
    """
    raw_token = None
    
    if authorization and authorization.lower().startswith("bearer "):
        raw_token = authorization.split(" ", 1)[1].strip()
    elif x_auth_token and x_auth_token.strip():
        raw_token = x_auth_token.strip()
    elif token and token.strip():
        raw_token = token.strip()
        
    if not raw_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Autenticación requerida para acceder al espacio privado",
            headers={"WWW-Authenticate": "Bearer"},
        )
        
    return verify_token(raw_token)
