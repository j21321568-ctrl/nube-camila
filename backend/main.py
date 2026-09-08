"""
Servidor FastAPI para la Nube Privada de Camila.
Proporciona la API REST segura para Google Drive y sirve los archivos estáticos
del frontend cuando se ejecuta en modo unificado o local.
"""
import io
import os
from pathlib import Path
from typing import List, Optional
from pydantic import BaseModel
from urllib.parse import quote

from fastapi import FastAPI, UploadFile, File, Form, Depends, HTTPException, Query, Header, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles

from .config import (
    PORT, HOST, CORS_ORIGINS, COOKIE_SAMESITE, MAX_UPLOAD_MB, MAX_UPLOAD_BYTES,
    is_2fa_enabled, save_2fa_config, disable_2fa_config, get_2fa_config,
    TURNSTILE_SITE_KEY, TURNSTILE_SECRET_KEY, POW_DIFFICULTY, POW_TTL_SECONDS
)
from .auth import (
    verify_password,
    create_access_token,
    create_scoped_token,
    require_auth,
    require_file_access,
    revoke_all_sessions,
    TOKEN_EXPIRATION_SECONDS,
    generate_new_totp_secret,
    get_totp_uri,
    generate_qr_svg_data_uri,
    verify_totp_code
)
from .logging_filter import setup_secure_logging
from .drive_manager import drive_manager
from .shiori_guard import (
    ShioriSecurityHeadersMiddleware,
    shiori_limiter,
    shiori_entropy,
    shiori_guard,
    get_client_ip,
    resolve_disposition,
    ShioriProofOfWork,
    verify_turnstile_token
)

# Inicializar filtro de censura de tokens en logs (previene fuga en Uvicorn/Render)
setup_secure_logging()

app = FastAPI(
    title="Nube Privada de Camila API",
    description="API de almacenamiento personal y privada en la nube — Blindada por Shiori Sentinel v14",
    version="2.0.0"
)

FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"
if not FRONTEND_DIR.exists():
    FRONTEND_DIR = Path(__file__).resolve().parent.parent / "static"

# Blindaje de cabeceras HTTP de Shiori Sentinel v14
app.add_middleware(ShioriSecurityHeadersMiddleware)

# Configurar CORS restrictivo para permitir comunicación segura desde Vercel y entornos locales (M1)
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["Content-Disposition", "Content-Length", "X-Shiori-Protection"]
)

# Middleware de límite de tamaño de petición en streaming (M2: Mitigación DoS / OOM)
@app.middleware("http")
async def limit_upload_payload_size(request: Request, call_next):
    """Rechazo temprano por Content-Length antes de parsear multipart o consumir memoria."""
    if request.method == "POST" and request.url.path == "/api/upload":
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                total_bytes = int(content_length)
                if total_bytes > MAX_UPLOAD_BYTES:
                    return JSONResponse(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        content={
                            "detail": f"El tamaño total de la solicitud ({total_bytes / (1024 * 1024):.1f} MB) excede el límite máximo permitido de {MAX_UPLOAD_MB} MB."
                        }
                    )
            except ValueError:
                pass
    return await call_next(request)

# ----------------- Modelos de Datos -----------------
class LoginRequest(BaseModel):
    password: str
    turnstile_token: Optional[str] = None
    pow_challenge: Optional[str] = None
    pow_nonce: Optional[str] = None

class Login2FaRequest(BaseModel):
    totp_code: str

class Setup2FaConfirmRequest(BaseModel):
    secret: str
    code: str

class Disable2FaRequest(BaseModel):
    password: str

class RenameRequest(BaseModel):
    name: str

class StarRequest(BaseModel):
    starred: bool

class DeleteConfirmRequest(BaseModel):
    password: Optional[str] = None

# ----------------- Rutas de Salud y Diagnóstico -----------------
@app.get("/health")
@app.get("/api/health")
def health_check():
    """Endpoint público ultraligero y mínimo para verificar disponibilidad y despertar servidores (Render).
    Previene fingerprinting de versiones y stack de seguridad (M7)."""
    return {"status": "online"}

@app.get("/api/health/detail")
def health_detail(_user: dict = Depends(require_auth)):
    """Endpoint de diagnóstico interno y métricas completas, accesible solo con sesión autenticada (M7)."""
    return {
        "status": "online",
        "app": "Nube Privada de Camila",
        "version": "2.0.0",
        "protection": "Shiori Sentinel v14.0",
        "message": "Servidor activo y listo para procesar peticiones ✨"
    }


@app.get("/favicon.ico", include_in_schema=False)
def favicon():
    """Sirve el favicon oficial de la Nube Privada de Camila."""
    fav = FRONTEND_DIR / "favicon.ico"
    if fav.exists():
        return FileResponse(fav, media_type="image/x-icon")
    return Response(status_code=204)

# ----------------- Rutas de Autenticación -----------------
@app.get("/api/auth/challenge")
def get_auth_challenge(request: Request):
    """
    Verifica si la IP actual o el estado global del sistema requieren resolver un desafío
    de seguridad (Cloudflare Turnstile o Proof-of-Work) antes de intentar login (M9).
    """
    client_ip = get_client_ip(request)
    req_challenge = shiori_limiter.is_challenge_required(client_ip)
    data = {
        "challenge_required": req_challenge,
        "turnstile_enabled": bool(TURNSTILE_SITE_KEY and TURNSTILE_SECRET_KEY),
        "turnstile_site_key": TURNSTILE_SITE_KEY if TURNSTILE_SITE_KEY else None,
        "pow_difficulty": POW_DIFFICULTY
    }
    if req_challenge:
        data["pow_challenge"] = ShioriProofOfWork.generate_challenge()
    return data

@app.post("/api/auth/login")
def login(req: LoginRequest, request: Request, response: Response):
    """Verifica la contraseña maestra con protección contra fuerza bruta de Shiori v14 y CAPTCHA/PoW (M9)."""
    client_ip = get_client_ip(request)
    
    # 1. Comprobar si la IP está bloqueada por exceso de intentos fallidos
    is_allowed, wait_seconds = shiori_limiter.check_login_allowed(client_ip)
    if not is_allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Protección Shiori Sentinel: IP bloqueada temporalmente por reiterados intentos fallidos. Espera {wait_seconds} segundos.",
            headers={"Retry-After": str(wait_seconds)}
        )

    # 2. Comprobar desafío de seguridad (Turnstile o PoW) si está requerido (M9)
    if shiori_limiter.is_challenge_required(client_ip):
        challenge_passed = False
        challenge_error = ""

        if req.turnstile_token and TURNSTILE_SECRET_KEY:
            ok, err = verify_turnstile_token(req.turnstile_token, client_ip)
            if ok:
                challenge_passed = True
            else:
                challenge_error = err or "Token de Turnstile inválido"
        elif req.pow_challenge and req.pow_nonce:
            ok, err = ShioriProofOfWork.verify_solution(
                req.pow_challenge,
                req.pow_nonce,
                difficulty=POW_DIFFICULTY,
                ttl_seconds=POW_TTL_SECONDS
            )
            if ok:
                challenge_passed = True
            else:
                challenge_error = err or "Prueba de trabajo (PoW) incorrecta o insuficiente"
        else:
            challenge_error = "Se requiere resolver un desafío de seguridad (Turnstile o PoW) tras intentos fallidos previos"

        if not challenge_passed:
            failed_count, lockout_sec = shiori_limiter.record_login_failure(client_ip)
            if lockout_sec > 0:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"Protección Shiori Sentinel: Límite de 5 intentos superado. IP bloqueada por {lockout_sec // 60} minutos.",
                    headers={"Retry-After": str(lockout_sec)}
                )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Protección contra ataques distribuidos (M9): {challenge_error}",
                headers={"X-Challenge-Required": "true"}
            )

    # 3. Verificar contraseña maestra en tiempo constante
    if not verify_password(req.password):
        failed_count, lockout_sec = shiori_limiter.record_login_failure(client_ip)
        if lockout_sec > 0:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Protección Shiori Sentinel: Límite de 5 intentos superado. IP bloqueada por {lockout_sec // 60} minutos.",
                headers={"Retry-After": str(lockout_sec)}
            )
        attempts_left = max(0, 5 - failed_count)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Contraseña incorrecta. Te quedan {attempts_left} intento(s) antes del bloqueo temporal.",
            headers={"X-Challenge-Required": "true"}
        )

    # 4. Login exitoso: limpiar contador de fallos de la IP
    shiori_limiter.record_login_success(client_ip)
    token = create_access_token(subject="camila")
    
    # Inyectar cookie HttpOnly (protege contra XSS y viaja de forma transparente sin exponerse en URL)
    response.set_cookie(
        key="camila_session",
        value=token,
        httponly=True,
        secure=True,
        samesite=COOKIE_SAMESITE,
        max_age=TOKEN_EXPIRATION_SECONDS,
        path="/"
    )
    
    return {
        "success": True,
        "token": token,
        "expiresIn": TOKEN_EXPIRATION_SECONDS,
        "userName": "Camila",
        "message": "¡Bienvenida a tu espacio seguro, Camila! ✨"
    }

@app.post("/api/auth/logout")
def logout(response: Response):
    """Cierra la sesión eliminando la cookie de sesión HttpOnly."""
    response.delete_cookie(key="camila_session", path="/", samesite=COOKIE_SAMESITE, secure=True)
    return {"success": True, "message": "Sesión cerrada con éxito"}

@app.post("/api/auth/refresh")
def refresh_session(response: Response, user=Depends(require_auth)):
    """Renovación silenciosa: genera un nuevo token de 8 horas y renueva la cookie de sesión."""
    new_token = create_access_token(subject=user.get("sub", "camila"))
    response.set_cookie(
        key="camila_session",
        value=new_token,
        httponly=True,
        secure=True,
        samesite=COOKIE_SAMESITE,
        max_age=TOKEN_EXPIRATION_SECONDS,
        path="/"
    )
    return {
        "success": True,
        "token": new_token,
        "expiresIn": TOKEN_EXPIRATION_SECONDS,
        "message": "Sesión renovada exitosamente ✨"
    }

@app.post("/api/auth/revoke-all")
def revoke_all_devices(response: Response, user=Depends(require_auth)):
    """
    Revocación global de sesiones (Session Epoch):
    Invalida instantáneamente todos los tokens de sesión en todos los dispositivos.
    """
    revoke_all_sessions()
    response.delete_cookie(key="camila_session", path="/", samesite=COOKIE_SAMESITE, secure=True)
    return {
        "success": True,
        "message": "Se han cerrado y revocado todas las sesiones en todos los dispositivos de manera inmediata."
    }

@app.get("/api/auth/verify")
def verify_session(user=Depends(require_auth)):
    """Comprueba si la sesión activa en el navegador sigue siendo válida."""
    return {
        "valid": True,
        "user": user.get("sub", "camila"),
        "twoFactorEnabled": is_2fa_enabled()
    }

# ----------------- Rutas de Segundo Factor (2FA / TOTP - M3) -----------------
@app.get("/api/auth/2fa/status")
def get_2fa_status():
    """Retorna si el segundo factor de autenticación (2FA) está configurado y activo."""
    return {
        "enabled": is_2fa_enabled()
    }

@app.post("/api/auth/2fa/setup")
def setup_2fa(user=Depends(require_auth)):
    """
    Inicia la configuración de 2FA:
    Genera un secreto provisional Base32, URL otpauth:// y código QR SVG sin llamadas externas.
    """
    secret = generate_new_totp_secret()
    account_name = user.get("sub", "Camila")
    otp_uri = get_totp_uri(secret, account_name=account_name)
    qr_data_uri = generate_qr_svg_data_uri(otp_uri)
    return {
        "secret": secret,
        "otpauth_url": otp_uri,
        "qr_code_svg": qr_data_uri,
        "account_name": account_name
    }

@app.post("/api/auth/2fa/confirm")
def confirm_2fa(req: Setup2FaConfirmRequest, user=Depends(require_auth)):
    """
    Valida el código de prueba de 6 dígitos introducido por Camila y activa permanentemente el 2FA.
    """
    if not req.secret or not req.code:
        raise HTTPException(status_code=400, detail="Faltan datos requeridos (secreto o código)")

    if not verify_totp_code(req.code, secret=req.secret):
        raise HTTPException(
            status_code=400,
            detail="El código de 6 dígitos ingresado es incorrecto o ha expirado. Verifica la hora de tu dispositivo e inténtalo nuevamente."
        )

    save_2fa_config(req.secret)
    return {
        "success": True,
        "enabled": True,
        "message": "¡Segundo factor de autenticación (2FA) activado exitosamente! ✨"
    }

@app.post("/api/auth/2fa/disable")
def disable_2fa_route(req: Disable2FaRequest, user=Depends(require_auth)):
    """Desactiva 2FA previa confirmación obligatoria de la contraseña maestra."""
    if not verify_password(req.password):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Contraseña incorrecta. No se puede desactivar el segundo factor."
        )
    disable_2fa_config()
    return {
        "success": True,
        "enabled": False,
        "message": "Segundo factor de autenticación desactivado."
    }

@app.post("/api/auth/login-2fa")
def login_2fa(req: Login2FaRequest, request: Request, response: Response):
    """
    Acceso de rescate mediante código 2FA (TOTP de 6 dígitos).
    Permite acceder si Camila olvidó su contraseña, o como vía de autenticación alternativa.
    Protegido contra ataques de fuerza bruta mediante Shiori Persistent Rate Limiter.
    """
    if not is_2fa_enabled():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="La autenticación en dos pasos (2FA) no está activada en esta cuenta. Ingresa con tu contraseña habitual."
        )

    client_ip = get_client_ip(request)

    # 1. Verificar bloqueo por fuerza bruta de IP
    is_allowed, wait_seconds = shiori_limiter.check_login_allowed(client_ip)
    if not is_allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Protección Shiori Sentinel: IP bloqueada temporalmente por reiterados intentos fallidos. Espera {wait_seconds} segundos.",
            headers={"Retry-After": str(wait_seconds)}
        )

    # 2. Verificar código TOTP
    if not verify_totp_code(req.totp_code):
        failed_count, lockout_sec = shiori_limiter.record_login_failure(client_ip)
        if lockout_sec > 0:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Protección Shiori Sentinel: Límite de 5 intentos superado. IP bloqueada por {lockout_sec // 60} minutos.",
                headers={"Retry-After": str(lockout_sec)}
            )
        attempts_left = max(0, 5 - failed_count)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Código 2FA incorrecto o expirado. Te quedan {attempts_left} intento(s) antes del bloqueo temporal."
        )

    # 3. Código 2FA válido: limpiar contador de fallos de la IP y emitir sesión
    shiori_limiter.record_login_success(client_ip)
    token = create_access_token(subject="camila")

    response.set_cookie(
        key="camila_session",
        value=token,
        httponly=True,
        secure=True,
        samesite=COOKIE_SAMESITE,
        max_age=TOKEN_EXPIRATION_SECONDS,
        path="/"
    )

    return {
        "success": True,
        "token": token,
        "expiresIn": TOKEN_EXPIRATION_SECONDS,
        "userName": "Camila",
        "message": "¡Acceso de respaldo con 2FA concedido exitosamente! ✨"
    }

# ----------------- Rutas de Archivos en Google Drive -----------------
@app.get("/api/files")
def get_files(
    category: Optional[str] = Query("all"),
    q: Optional[str] = Query(None),
    starred: Optional[bool] = Query(False),
    user=Depends(require_auth)
):
    """Lista los archivos almacenados en la carpeta de Drive con filtros."""
    try:
        files = drive_manager.list_files(
            category=category,
            search_query=q,
            starred_only=starred or False
        )
        return {"success": True, "files": files, "count": len(files)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al listar archivos: {str(e)}")

@app.post("/api/upload")
async def upload_files(
    request: Request,
    files: List[UploadFile] = File(...),
    user=Depends(require_auth)
):
    """Sube archivos con sanitización de ruta, límites de memoria (M2) y escáner de integridad de Shiori v14."""
    # 1. Validación temprana por Content-Length antes de procesar el cuerpo (M2)
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            total_bytes = int(content_length)
            if total_bytes > MAX_UPLOAD_BYTES:
                raise HTTPException(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    detail=f"El tamaño de la solicitud ({total_bytes / (1024 * 1024):.1f} MB) excede el límite máximo permitido de {MAX_UPLOAD_MB} MB."
                )
        except ValueError:
            pass

    if not files:
        raise HTTPException(status_code=400, detail="No se recibieron archivos para subir")

    uploaded = []
    errors = []

    for file in files:
        try:
            # 2. Validación de tamaño individual mediante seek sin volcar en RAM (M2)
            file.file.seek(0, os.SEEK_END)
            file_size = file.file.tell()
            file.file.seek(0)

            if file_size > MAX_UPLOAD_BYTES:
                errors.append({
                    "filename": file.filename,
                    "error": f"El archivo excede el tamaño máximo permitido de {MAX_UPLOAD_MB} MB ({file_size / (1024 * 1024):.1f} MB)"
                })
                continue

            safe_name = shiori_guard.sanitize_filename(file.filename or "archivo", fallback="archivo_seguro")

            # 3. Escaneo de integridad Shiori Sentinel v14 mediante streaming (M2 / H2)
            # Solo lee hasta 4 MB para firmas / magic bytes, sin cargar el archivo completo en memoria
            is_safe, scan_reason = shiori_entropy.scan_file_stream(file.file, safe_name)
            if not is_safe:
                errors.append({"filename": file.filename, "error": scan_reason})
                continue

            # 4. Subida a Google Drive pasando el flujo directamente (Streaming sin buffer RAM)
            result = drive_manager.upload_file(
                file_stream=file.file,
                filename=safe_name,
                content_type=file.content_type
            )
            uploaded.append(result)
        except Exception as e:
            errors.append({"filename": file.filename, "error": str(e)})

    return {
        "success": len(uploaded) > 0,
        "uploaded": uploaded,
        "errors": errors,
        "totalUploaded": len(uploaded)
    }

@app.post("/api/files/{file_id}/preview-token")
def get_preview_token(file_id: str, user=Depends(require_auth)):
    """
    Genera un token efímero acotado exclusivamente a este file_id (TTL 120s).
    Permite streaming multimedia o descarga segura sin exponer el token de sesión maestro en URLs ni logs.
    """
    scoped_token = create_scoped_token(file_id=file_id, scope="file_access", ttl_seconds=120)
    return {
        "success": True,
        "fileId": file_id,
        "token": scoped_token,
        "previewUrl": f"/api/files/{file_id}/preview?token={scoped_token}",
        "downloadUrl": f"/api/files/{file_id}/download?token={scoped_token}",
        "expiresIn": 120
    }

@app.get("/api/files/{file_id}/preview")
def preview_file(file_id: str, user=Depends(require_file_access)):
    """Transmite en línea (inline) el archivo para visualización en navegador (imágenes, audio, video, PDF)."""
    try:
        chunk_gen, meta = drive_manager.stream_file(file_id)
        mime_type = meta.get("mimeType", "application/octet-stream")
        safe_filename = quote(meta.get("name", "archivo"))

        disposition = resolve_disposition(mime_type, requested="inline")
        headers = {
            "Content-Disposition": f"{disposition}; filename*=UTF-8''{safe_filename}",
            "Cache-Control": "private, max-age=120",
            "Accept-Ranges": "bytes"
        }
        return StreamingResponse(chunk_gen, media_type=mime_type, headers=headers)
    except Exception as e:
        raise HTTPException(status_code=404, detail=f"No se pudo previsualizar el archivo: {str(e)}")

@app.get("/api/files/{file_id}/download")
def download_file(file_id: str, user=Depends(require_file_access)):
    """Descarga el archivo forzando guardado como adjunto (attachment)."""
    try:
        chunk_gen, meta = drive_manager.stream_file(file_id)
        mime_type = meta.get("mimeType", "application/octet-stream")
        safe_filename = quote(meta.get("name", "archivo"))

        headers = {
            "Content-Disposition": f"attachment; filename*=UTF-8''{safe_filename}",
            "Cache-Control": "no-cache",
        }
        return StreamingResponse(chunk_gen, media_type=mime_type, headers=headers)
    except Exception as e:
        raise HTTPException(status_code=404, detail=f"No se pudo descargar el archivo: {str(e)}")

@app.post("/api/files/{file_id}/star")
def toggle_star(file_id: str, req: StarRequest, user=Depends(require_auth)):
    """Marca o desmarca un archivo como favorito en Google Drive."""
    try:
        result = drive_manager.toggle_star(file_id, req.starred)
        return {"success": True, "file": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al cambiar favorito: {str(e)}")

@app.patch("/api/files/{file_id}/rename")
def rename_file(file_id: str, req: RenameRequest, user=Depends(require_auth)):
    """Renombra un archivo en Google Drive con sanitización estricta Shiori."""
    try:
        result = drive_manager.rename_file(file_id, req.name)
        return {"success": True, "file": result}
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al renombrar archivo: {str(e)}")

@app.delete("/api/files/{file_id}")
def delete_file(
    file_id: str,
    permanent: bool = Query(False),
    req: Optional[DeleteConfirmRequest] = None,
    x_confirm_password: Optional[str] = Header(None),
    confirm_password: Optional[str] = Query(None),
    user=Depends(require_auth)
):
    """
    Elimina un archivo de Google Drive.
    - permanent=False: Envía el archivo a la papelera (reversible y seguro).
    - permanent=True: Purga permanente con Step-Up Authentication (H6):
      1. Requiere confirmación con contraseña maestra (vía header, body o query param).
      2. Exige que el archivo ya se encuentre en la papelera (flujo en 2 pasos obligatorio).
    """
    if permanent:
        pwd = (req.password if req and req.password else None) or x_confirm_password or confirm_password
        if not pwd:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Step-Up de seguridad requerido: Para purgar un archivo definitivamente debes confirmar con tu contraseña maestra."
            )
        if not verify_password(pwd):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Contraseña de confirmación incorrecta. No se autorizó la eliminación permanente."
            )

    try:
        result = drive_manager.delete_file(file_id, permanent=permanent)
        return {"success": True, "result": result}
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))
    except PermissionError as pe:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(pe))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al eliminar archivo: {str(e)}")

@app.get("/api/stats")
def get_stats(user=Depends(require_auth)):
    """Devuelve estadísticas globales y espacio utilizado en la nube."""
    try:
        stats = drive_manager.get_stats()
        return {"success": True, "stats": stats}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener estadísticas: {str(e)}")

# ----------------- Servidor de Frontend Estático (Unificado) -----------------
# Si existe la carpeta frontend/ o static/, se sirve automáticamente para uso local
if FRONTEND_DIR.exists():
    # Montar también en /static por compatibilidad
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")
    # Montar en la raíz / para servir index.html, style.css, app.js, config.js directamente
    app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")

if __name__ == "__main__":
    import uvicorn
    print(f"Iniciando Nube Privada de Camila en http://{HOST}:{PORT}")
    uvicorn.run("backend.main:app", host=HOST, port=PORT, reload=True)
