"""
Gestor de Google Drive v3 para la Nube Privada de Camila.
Proporciona operaciones seguras de almacenamiento, streaming sin bloqueo,
categorización inteligente de archivos y persistencia de favoritos nativos.
"""
import os
import json
import io
import mimetypes
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple, Generator
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseUpload, MediaIoBaseDownload
from googleapiclient.errors import HttpError

from .config import get_service_account_info, get_drive_folder_id, ROOT_DIR

SCOPES = ["https://www.googleapis.com/auth/drive"]

def format_bytes(size_bytes: Optional[Any]) -> str:
    """Convierte bytes en formato legible (B, KB, MB, GB)."""
    try:
        bytes_val = int(size_bytes)
    except (TypeError, ValueError):
        return "0 B"

    if bytes_val <= 0:
        return "0 B"
    units = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    double_val = float(bytes_val)
    while double_val >= 1024 and i < len(units) - 1:
        double_val /= 1024.0
        i += 1
    return f"{double_val:.1f} {units[i]}" if i > 0 else f"{int(double_val)} B"

def format_relative_date(iso_str: Optional[str]) -> str:
    """Convierte un timestamp ISO a texto amigable en español."""
    if not iso_str:
        return ""
    try:
        # Formato ISO de Google Drive: 2026-09-04T22:00:00.000Z
        clean_iso = iso_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(clean_iso)
        now = datetime.now(timezone.utc)
        diff = now - dt

        seconds = int(diff.total_seconds())
        if seconds < 60:
            return "Hace unos instantes"
        minutes = seconds // 60
        if minutes < 60:
            return f"Hace {minutes} min"
        hours = minutes // 60
        if hours < 24:
            return f"Hace {hours} h"
        days = hours // 24
        if days == 1:
            return "Ayer"
        if days < 7:
            return f"Hace {days} días"
        if days < 30:
            weeks = days // 7
            return f"Hace {weeks} sem"
        return dt.strftime("%d/%m/%Y")
    except Exception:
        return iso_str[:10]

def categorize_file(mime_type: str, filename: str) -> str:
    """Clasifica el archivo en categorías intuitivas."""
    mime = (mime_type or "").lower()
    name = (filename or "").lower()

    if mime.startswith("image/") or name.endswith((".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".bmp", ".heic")):
        return "image"
    if mime.startswith("video/") or name.endswith((".mp4", ".mov", ".avi", ".mkv", ".webm", ".m4v")):
        return "video"
    if mime.startswith("audio/") or name.endswith((".mp3", ".wav", ".m4a", ".ogg", ".aac", ".flac")):
        return "audio"
    if mime == "application/pdf" or name.endswith(".pdf"):
        return "pdf"
    if (
        "word" in mime
        or "excel" in mime
        or "spreadsheet" in mime
        or "presentation" in mime
        or "powerpoint" in mime
        or name.endswith((".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".csv", ".rtf"))
    ):
        return "document"
    if name.endswith((".zip", ".rar", ".7z", ".tar", ".gz")):
        return "archive"
    if name.endswith((".py", ".js", ".html", ".css", ".json", ".md", ".cpp", ".ts")):
        return "code"
    return "other"

class DriveManager:
    def __init__(self):
        self._service = None
        self._folder_id = None

    @property
    def folder_id(self) -> str:
        if not self._folder_id:
            self._folder_id = get_drive_folder_id()
        return self._folder_id

    @property
    def service(self):
        if not self._service:
            # 1. Prioridad: Credenciales OAuth2 de usuario (para cuentas personales @gmail con 15GB)
            oauth_file = ROOT_DIR / "oauth_token.json"
            env_oauth = os.getenv("GOOGLE_OAUTH_TOKEN")
            
            if env_oauth or oauth_file.exists():
                try:
                    from google.oauth2.credentials import Credentials
                    if env_oauth:
                        token_info = json.loads(env_oauth)
                        creds = Credentials.from_authorized_user_info(token_info, scopes=SCOPES)
                    else:
                        creds = Credentials.from_authorized_user_file(str(oauth_file), scopes=SCOPES)
                    self._service = build("drive", "v3", credentials=creds, cache_discovery=False)
                    return self._service
                except Exception as e:
                    print(f"Aviso: No se pudo cargar token OAuth ({e}), usando Service Account...")

            # 2. Cuenta de Servicio (Service Account)
            info = get_service_account_info()
            creds = service_account.Credentials.from_service_account_info(
                info, scopes=SCOPES
            )
            self._service = build("drive", "v3", credentials=creds, cache_discovery=False)
        return self._service

    def verify_connection(self) -> Dict[str, Any]:
        """Verifica que el servicio esté conectado y la carpeta exista."""
        folder = self.service.files().get(
            fileId=self.folder_id,
            fields="id, name, capabilities",
            supportsAllDrives=True
        ).execute()
        return folder

    def list_files(
        self,
        category: Optional[str] = None,
        search_query: Optional[str] = None,
        starred_only: bool = False
    ) -> List[Dict[str, Any]]:
        """Obtiene la lista de archivos dentro de la carpeta con metadatos enriquecidos."""
        query_parts = [f"'{self.folder_id}' in parents", "trashed = false"]

        if starred_only:
            query_parts.append("starred = true")

        if search_query and search_query.strip():
            safe_q = search_query.strip().replace("'", "\\'")
            query_parts.append(f"name contains '{safe_q}'")

        q = " and ".join(query_parts)

        fields = (
            "files(id, name, mimeType, size, modifiedTime, thumbnailLink, "
            "iconLink, webViewLink, webContentLink, starred)"
        )

        response = self.service.files().list(
            q=q,
            fields=fields,
            orderBy="modifiedTime desc",
            pageSize=100,
            supportsAllDrives=True,
            includeItemsFromAllDrives=True
        ).execute()

        raw_files = response.get("files", [])
        enriched_files = []

        for f in raw_files:
            mime = f.get("mimeType", "")
            name = f.get("name", "")
            cat = categorize_file(mime, name)

            if category and category != "all":
                if category == "starred" and not f.get("starred", False):
                    continue
                elif category != "starred" and cat != category:
                    continue

            raw_size = f.get("size")
            enriched_files.append({
                "id": f.get("id"),
                "name": name,
                "mimeType": mime,
                "size": raw_size,
                "formattedSize": format_bytes(raw_size),
                "modifiedTime": f.get("modifiedTime"),
                "relativeDate": format_relative_date(f.get("modifiedTime")),
                "thumbnailLink": f.get("thumbnailLink"),
                "iconLink": f.get("iconLink"),
                "starred": bool(f.get("starred", False)),
                "category": cat,
                "canPreview": cat in ("image", "video", "audio", "pdf", "code") or mime.startswith("text/")
            })

        return enriched_files

    def upload_file(
        self,
        file_stream: io.BytesIO,
        filename: str,
        content_type: Optional[str] = None
    ) -> Dict[str, Any]:
        """Sube un archivo a la carpeta de Google Drive usando resumable upload."""
        if not content_type or content_type == "application/octet-stream":
            guessed_type, _ = mimetypes.guess_type(filename)
            content_type = guessed_type or "application/octet-stream"

        file_metadata = {
            "name": filename,
            "parents": [self.folder_id]
        }

        media = MediaIoBaseUpload(
            file_stream,
            mimetype=content_type,
            resumable=True,
            chunksize=1024 * 1024 * 5  # 5MB chunks
        )

        try:
            created_file = self.service.files().create(
                body=file_metadata,
                media_body=media,
                supportsAllDrives=True,
                fields="id, name, mimeType, size, modifiedTime, thumbnailLink, starred"
            ).execute()
        except HttpError as err:
            if "storageQuotaExceeded" in str(err) or "Service Accounts do not have storage quota" in str(err):
                raise RuntimeError(
                    "Google Drive bloqueó la subida porque las Cuentas de Servicio (Service Accounts) "
                    "no tienen cuota propia en 'Mi Unidad' personal. Para solucionarlo: "
                    "1) Usa una 'Unidad Compartida' (Shared Drive) en Google Drive, o "
                    "2) Ejecuta 'python setup_oauth.py' para enlazar tu cuenta de Google con 15 GB gratuitos."
                )
            raise

        cat = categorize_file(created_file.get("mimeType", ""), created_file.get("name", ""))
        created_file["formattedSize"] = format_bytes(created_file.get("size"))
        created_file["relativeDate"] = format_relative_date(created_file.get("modifiedTime"))
        created_file["category"] = cat
        created_file["canPreview"] = cat in ("image", "video", "audio", "pdf", "code")
        return created_file

    def get_file_metadata(self, file_id: str) -> Dict[str, Any]:
        """Obtiene los metadatos de un archivo específico verificando aislamiento estricto."""
        meta = self.service.files().get(
            fileId=file_id,
            fields="id, name, mimeType, size, modifiedTime, starred, parents",
            supportsAllDrives=True
        ).execute()

        # Garantía de aislamiento: impedir acceso a cualquier archivo fuera de la carpeta de Cami
        parents = meta.get("parents", [])
        if self.folder_id not in parents:
            raise PermissionError("Acceso denegado: El archivo solicitado no pertenece a la carpeta privada de Camila.")

        return meta

    def stream_file(self, file_id: str) -> Tuple[Generator[bytes, None, None], Dict[str, Any]]:
        """Descarga en streaming el contenido binario del archivo desde Drive."""
        meta = self.get_file_metadata(file_id)
        request = self.service.files().get_media(fileId=file_id, supportsAllDrives=True)
        
        # Generador de chunks para no cargar archivos gigantes en memoria RAM
        def chunk_generator():
            fh = io.BytesIO()
            downloader = MediaIoBaseDownload(fh, request, chunksize=1024 * 256)
            done = False
            while not done:
                fh.seek(0)
                fh.truncate(0)
                status, done = downloader.next_chunk()
                fh.seek(0)
                chunk = fh.read()
                if chunk:
                    yield chunk

        return chunk_generator(), meta

    def toggle_star(self, file_id: str, starred: bool) -> Dict[str, Any]:
        """Marca o desmarca un archivo como favorito en Google Drive tras verificar pertenencia."""
        self.get_file_metadata(file_id)  # Valida aislamiento estricto
        return self.service.files().update(
            fileId=file_id,
            body={"starred": starred},
            supportsAllDrives=True,
            fields="id, name, starred"
        ).execute()

    def rename_file(self, file_id: str, new_name: str) -> Dict[str, Any]:
        """Renombra un archivo tras verificar pertenencia a la carpeta."""
        self.get_file_metadata(file_id)  # Valida aislamiento estricto
        clean_name = new_name.strip()
        if not clean_name:
            raise ValueError("El nombre no puede estar vacío")
        return self.service.files().update(
            fileId=file_id,
            body={"name": clean_name},
            supportsAllDrives=True,
            fields="id, name, modifiedTime"
        ).execute()

    def delete_file(self, file_id: str, permanent: bool = False) -> Dict[str, Any]:
        """Envía el archivo a la papelera o lo elimina definitivamente tras validar pertenencia."""
        self.get_file_metadata(file_id)  # Valida aislamiento estricto
        if permanent:
            self.service.files().delete(fileId=file_id, supportsAllDrives=True).execute()
            return {"id": file_id, "deleted": True, "permanent": True}
        else:
            self.service.files().update(
                fileId=file_id,
                body={"trashed": True},
                supportsAllDrives=True
            ).execute()
            return {"id": file_id, "deleted": True, "permanent": False}

    def get_stats(self) -> Dict[str, Any]:
        """Calcula estadísticas generales de la nube personal."""
        files = self.list_files()
        total_files = len(files)
        total_bytes = 0
        categories_count = {
            "image": 0,
            "video": 0,
            "audio": 0,
            "pdf": 0,
            "document": 0,
            "archive": 0,
            "code": 0,
            "other": 0,
            "starred": 0
        }

        for f in files:
            try:
                total_bytes += int(f.get("size") or 0)
            except (ValueError, TypeError):
                pass
            cat = f.get("category", "other")
            categories_count[cat] = categories_count.get(cat, 0) + 1
            if f.get("starred"):
                categories_count["starred"] += 1

        return {
            "totalFiles": total_files,
            "totalBytes": total_bytes,
            "formattedTotalSize": format_bytes(total_bytes),
            "categories": categories_count
        }

# Instancia global reutilizable
drive_manager = DriveManager()
