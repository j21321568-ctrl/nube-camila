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

from fastapi import FastAPI, UploadFile, File, Form, Depends, HTTPException, Query, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles

from .config import PORT, HOST, CORS_ORIGINS
from .auth import (
    verify_password,
    create_access_token,
    create_scoped_token,
    require_auth,
    require_file_access
)
from .logging_filter import setup_secure_logging
from .drive_manager import drive_manager
from .shiori_guard import (
    ShioriSecurityHeadersMiddleware,
    shiori_limiter,
    shiori_entropy,
    shiori_guard
)

# Inicializar filtro de censura de tokens en logs (previene fuga en Uvicorn/Render)
setup_secure_logging()

app = FastAPI(
    title="Nube Privada de Camila API",
    description="API de almacenamiento personal y privada en la nube — Blindada por Shiori Sentinel v14",
    version="2.0.0"
)

# Blindaje de cabeceras HTTP de Shiori Sentinel v14
app.add_middleware(ShioriSecurityHeadersMiddleware)

# Configurar CORS para permitir comunicación desde Vercel, GitHub Pages, Localhost
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS if CORS_ORIGINS != ["*"] else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ----------------- Modelos de Datos -----------------
class LoginRequest(BaseModel):
    password: str

class RenameRequest(BaseModel):
    name: str

class StarRequest(BaseModel):
    starred: bool

# ----------------- Rutas de Salud y Diagnóstico -----------------
@app.get("/health")
@app.get("/api/health")
def health_check():
    """Endpoint ligero para verificar disponibilidad y despertar servidores (Render)."""
    return {
        "status": "online",
        "app": "Nube Privada de Camila",
        "version": "2.0.0",
        "protection": "Shiori Sentinel v14.0",
        "message": "Servidor activo y listo para procesar peticiones ✨"
    }

# ----------------- Rutas de Autenticación -----------------
@app.post("/api/auth/login")
def login(req: LoginRequest, request: Request, response: Response):
    """Verifica la contraseña maestra con protección contra fuerza bruta de Shiori v14."""
    client_ip = request.client.host if request.client else "127.0.0.1"
    if not shiori_limiter.check_request(client_ip, is_login=True):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Protección Shiori Sentinel: Demasiados intentos continuos. Por seguridad, espera unos segundos.",
        )

    if not verify_password(req.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Contraseña incorrecta. Por favor intenta nuevamente.",
        )
    token = create_access_token(subject="camila")
    
    # Inyectar cookie HttpOnly (protege contra XSS y viaja de forma transparente sin exponerse en URL)
    response.set_cookie(
        key="camila_session",
        value=token,
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=30 * 24 * 60 * 60,
        path="/"
    )
    
    return {
        "success": True,
        "token": token,
        "userName": "Camila",
        "message": "¡Bienvenida a tu espacio seguro, Camila! ✨"
    }

@app.post("/api/auth/logout")
def logout(response: Response):
    """Cierra la sesión eliminando la cookie de sesión HttpOnly."""
    response.delete_cookie(key="camila_session", path="/")
    return {"success": True, "message": "Sesión cerrada con éxito"}

@app.get("/api/auth/verify")
def verify_session(user=Depends(require_auth)):
    """Comprueba si la sesión activa en el navegador sigue siendo válida."""
    return {
        "valid": True,
        "user": user.get("sub", "camila")
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
    files: List[UploadFile] = File(...),
    user=Depends(require_auth)
):
    """Sube archivos con sanitización de ruta y escáner de integridad de Shiori v14."""
    if not files:
        raise HTTPException(status_code=400, detail="No se recibieron archivos para subir")

    uploaded = []
    errors = []

    for file in files:
        try:
            content = await file.read()
            safe_name = shiori_guard.sanitize_filename(file.filename or "archivo")

            # Escaneo de integridad Shiori Sentinel v14
            is_safe, scan_reason = shiori_entropy.scan_file_buffer(content, safe_name)
            if not is_safe:
                errors.append({"filename": file.filename, "error": scan_reason})
                continue

            stream = io.BytesIO(content)
            result = drive_manager.upload_file(
                file_stream=stream,
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

        headers = {
            "Content-Disposition": f"inline; filename*=UTF-8''{safe_filename}",
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
    """Renombra un archivo en Google Drive."""
    try:
        result = drive_manager.rename_file(file_id, req.name)
        return {"success": True, "file": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al renombrar archivo: {str(e)}")

@app.delete("/api/files/{file_id}")
def delete_file(
    file_id: str,
    permanent: bool = Query(False),
    user=Depends(require_auth)
):
    """Elimina el archivo (a la papelera por defecto para mayor seguridad)."""
    try:
        result = drive_manager.delete_file(file_id, permanent=permanent)
        return {"success": True, "result": result}
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
FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"
if not FRONTEND_DIR.exists():
    FRONTEND_DIR = Path(__file__).resolve().parent.parent / "static"

if FRONTEND_DIR.exists():
    # Montar también en /static por compatibilidad
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")
    # Montar en la raíz / para servir index.html, style.css, app.js, config.js directamente
    app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")

if __name__ == "__main__":
    import uvicorn
    print(f"Iniciando Nube Privada de Camila en http://{HOST}:{PORT}")
    uvicorn.run("backend.main:app", host=HOST, port=PORT, reload=True)
