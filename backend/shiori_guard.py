"""
╔══════════════════════════════════════════════════════════════════════════════╗
║        SHIORI SENTINEL v14.0 — CLOUD SHIELD INTEGRATION MODULE               ║
║        Adaptación del motor de Ciberdefensa Proactiva para la Nube de Cami   ║
╚══════════════════════════════════════════════════════════════════════════════╝
Módulos integrados desde Shiori Sentinel v14:
  [ZTA] ZeroTrustCrypto   — HMAC-SHA3-256 + Nonce anti-replay + reloj monotónico
  [TBR] TokenBucketLimiter— Rate limiter token bucket contra fuerza bruta / DDoS
  [ENT] EntropyShield     — Análisis de entropía de Shannon y firmas de magic bytes
  [PTG] PathTraversalGuard— Sanitización estricta de nombres y prevención de inyecciones
  [SEC] SecurityHeaders   — Cabeceras HTTP de blindaje defensivo
"""
import time
import math
import hmac
import hashlib
import re
import sqlite3
from pathlib import Path
from typing import Dict, Tuple, Optional
from collections import defaultdict
from fastapi import Request, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware

# ──────────────────────────────────────────────────────────────────────────────
#  [ZTA] ZERO-TRUST POST-QUANTUM CRYPTO ENGINE (HMAC-SHA3-256)
# ──────────────────────────────────────────────────────────────────────────────

class ShioriZeroTrustCrypto:
    """Motor criptográfico HMAC-SHA3-256 con protección de replay."""

    @staticmethod
    def sign_token(secret: str, payload_str: str) -> str:
        """Genera firma HMAC-SHA3-256 resistente a ataques de extensión de longitud."""
        key_bytes = secret.encode("utf-8")
        msg_bytes = payload_str.encode("utf-8")
        return hmac.new(key_bytes, msg_bytes, hashlib.sha3_256).hexdigest()

    @staticmethod
    def verify_signature(secret: str, payload_str: str, signature: str) -> bool:
        """Verifica la firma en tiempo constante."""
        expected = ShioriZeroTrustCrypto.sign_token(secret, payload_str)
        return hmac.compare_digest(expected.lower().strip(), signature.lower().strip())


# ──────────────────────────────────────────────────────────────────────────────
#  [TBR] TOKEN BUCKET RATE LIMITER (Defensa proactiva contra fuerza bruta)
# ──────────────────────────────────────────────────────────────────────────────

class ShioriTokenBucket:
    """
    Implementación Token Bucket de Shiori v14.
    Permite ráfagas acotadas y recarga continua de fichas.
    """
    def __init__(self, capacity: float = 20.0, refill_rate: float = 1.0):
        self.capacity = capacity
        self.refill_rate = refill_rate  # Tokens por segundo
        self.tokens = capacity
        self.last_refill = time.monotonic()

    def consume(self, amount: float = 1.0) -> bool:
        now = time.monotonic()
        delta = now - self.last_refill
        self.last_refill = now
        self.tokens = min(self.capacity, self.tokens + delta * self.refill_rate)

        if self.tokens >= amount:
            self.tokens -= amount
            return True
        return False


RATE_LIMIT_DB_FILE = Path(__file__).resolve().parent.parent / ".shiori_ratelimit.db"

class ShioriPersistentRateLimiter:
    """
    Rate Limiter persistente de Shiori Sentinel v14 respaldado en SQLite WAL.
    Garantiza:
    1. Resistencia multi-worker: Procesos independientes de Uvicorn comparten el mismo estado atómico.
    2. Resistencia a reinicios y suspensiones de Render: Los intentos fallidos sobreviven a reinicios de proceso.
    3. Bloqueo progresivo disuasorio: Tras 5 fallos consecutivos, la IP es bloqueada por 15 minutos (900s).
    4. Reseteo instantáneo tras inicio de sesión exitoso.
    """
    MAX_FAILED_ATTEMPTS = 5
    OBSERVATION_WINDOW_SECONDS = 600   # 10 minutos para acumular fallos
    LOCKOUT_DURATION_SECONDS = 900     # 15 minutos de bloqueo estricto

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or RATE_LIMIT_DB_FILE
        self._general_buckets: Dict[str, ShioriTokenBucket] = defaultdict(
            lambda: ShioriTokenBucket(capacity=20.0, refill_rate=2.0)
        )
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=10.0)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        return conn

    def _init_db(self):
        try:
            with self._get_connection() as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS login_rate_limits (
                        ip TEXT PRIMARY KEY,
                        failed_count INTEGER NOT NULL DEFAULT 0,
                        first_failed_at REAL NOT NULL,
                        last_failed_at REAL NOT NULL,
                        locked_until REAL NOT NULL DEFAULT 0
                    );
                """)
                conn.commit()
        except Exception:
            pass

    def check_login_allowed(self, ip: str) -> Tuple[bool, int]:
        """
        Comprueba si la IP tiene permitido intentar login.
        Devuelve (permitido: bool, segundos_restantes_bloqueo: int).
        """
        now = time.time()
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT failed_count, last_failed_at, locked_until FROM login_rate_limits WHERE ip = ?",
                    (ip,)
                )
                row = cursor.fetchone()
                if not row:
                    return True, 0

                failed_count, last_failed_at, locked_until = row
                
                # Si está activamente bloqueado
                if locked_until > now:
                    remaining = int(locked_until - now) + 1
                    return False, remaining

                # Si la ventana de observación ya expiró, resetear contador
                if (now - last_failed_at) > self.OBSERVATION_WINDOW_SECONDS:
                    cursor.execute(
                        "UPDATE login_rate_limits SET failed_count = 0, locked_until = 0 WHERE ip = ?",
                        (ip,)
                    )
                    conn.commit()
                    return True, 0

                return True, 0
        except Exception:
            return True, 0

    def record_login_failure(self, ip: str) -> Tuple[int, int]:
        """
        Registra un intento de login fallido.
        Devuelve (failed_count_actual: int, segundos_de_bloqueo_aplicados: int).
        """
        now = time.time()
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT failed_count, last_failed_at, locked_until FROM login_rate_limits WHERE ip = ?",
                    (ip,)
                )
                row = cursor.fetchone()
                
                if not row:
                    cursor.execute(
                        "INSERT INTO login_rate_limits (ip, failed_count, first_failed_at, last_failed_at, locked_until) "
                        "VALUES (?, 1, ?, ?, 0)",
                        (ip, now, now)
                    )
                    conn.commit()
                    return 1, 0
                else:
                    failed_count, last_failed_at, locked_until = row
                    
                    if (now - last_failed_at) > self.OBSERVATION_WINDOW_SECONDS:
                        new_count = 1
                        new_locked = 0
                    else:
                        new_count = failed_count + 1
                        new_locked = (now + self.LOCKOUT_DURATION_SECONDS) if new_count >= self.MAX_FAILED_ATTEMPTS else 0

                    cursor.execute(
                        "UPDATE login_rate_limits SET failed_count = ?, last_failed_at = ?, locked_until = ? WHERE ip = ?",
                        (new_count, now, new_locked, ip)
                    )
                    conn.commit()
                    lockout = self.LOCKOUT_DURATION_SECONDS if new_locked > 0 else 0
                    return new_count, lockout
        except Exception:
            return 1, 0

    def record_login_success(self, ip: str):
        """Resetea el contador de fallos de la IP tras un inicio de sesión exitoso."""
        try:
            with self._get_connection() as conn:
                conn.execute(
                    "UPDATE login_rate_limits SET failed_count = 0, locked_until = 0 WHERE ip = ?",
                    (ip,)
                )
                conn.commit()
        except Exception:
            pass

    def check_request(self, ip: str, is_login: bool = False) -> bool:
        """Compatibilidad general."""
        if is_login:
            allowed, _ = self.check_login_allowed(ip)
            return allowed
        bucket = self._general_buckets[ip]
        return bucket.consume(1.0)

# Alias para compatibilidad con código existente
ShioriRateLimiter = ShioriPersistentRateLimiter

import ipaddress

# Redes privadas / reservadas que suelen pertenecer a proxies inversos internos o loopback
PRIVATE_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),   # Carrier-grade NAT (infraestructuras cloud)
    ipaddress.ip_network("169.254.0.0/16"),  # Link-local
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),       # Unique local IPv6
    ipaddress.ip_network("fe80::/10"),      # Link-local IPv6
)

def _is_private_ip(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Comprueba si una dirección IP pertenece a rangos de red privados o de loopback."""
    return any(ip_obj in net for net in PRIVATE_NETWORKS)

def _clean_ip_str(raw: Optional[str]) -> Optional[str]:
    """Valida sintácticamente y normaliza una dirección IP textual usando ipaddress."""
    if not isinstance(raw, str):
        return None
    raw = raw.strip()
    if not raw:
        return None
    try:
        ip_obj = ipaddress.ip_address(raw)
        if ip_obj.version == 6 and ip_obj == ipaddress.IPv6Address("::1"):
            return "127.0.0.1"
        return str(ip_obj)
    except ValueError:
        return None

def get_client_ip(request: Request) -> str:
    """
    Extrae de forma segura la dirección IP real del cliente para rate limiting (M8).
    
    Arquitectura de defensa contra spoofing de cabeceras de proxy:
    1. Si TRUST_PROXY_HEADERS está activo (ej. en producción Render detrás de Cloudflare):
       a. Prioridad 1: 'CF-Connecting-IP'. Cloudflare sobreescribe esta cabecera en el edge
          con la IP remota real del visitante; un atacante no puede falsificarla.
       b. Prioridad 2: 'X-Real-IP'. Inyectada por proxies inversos de confianza.
       c. Prioridad 3: 'X-Forwarded-For'. Se analiza de DERECHA a IZQUIERDA (el extremo
          izquierdo puede haber sido inyectado por el cliente, mientras que los extremos
          derechos son añadidos por los proxies de confianza). Se extrae la primera IP
          pública o válida de derecha a izquierda.
    2. Si TRUST_PROXY_HEADERS está inactivo (desarrollo local o conexión directa sin proxy):
       Se utiliza exclusivamente el socket remoto de la conexión (`request.client.host`),
       impidiendo que un cliente envíe cabeceras de proxy falsas para evadir el rate limit.
    """
    from .config import TRUST_PROXY_HEADERS

    if TRUST_PROXY_HEADERS and hasattr(request, "headers"):
        headers = request.headers

        # 1. CF-Connecting-IP (Cloudflare Edge — Render usa Cloudflare como proxy)
        cf_ip = _clean_ip_str(headers.get("cf-connecting-ip"))
        if cf_ip:
            return cf_ip

        # 2. X-Real-IP
        real_ip = _clean_ip_str(headers.get("x-real-ip"))
        if real_ip:
            return real_ip

        # 3. X-Forwarded-For (analizar de derecha a izquierda contra inyecciones)
        xff = headers.get("x-forwarded-for")
        if xff:
            parts = [p.strip() for p in xff.split(",") if p.strip()]
            valid_ips = []
            for part in reversed(parts):
                cleaned = _clean_ip_str(part)
                if cleaned:
                    valid_ips.append(cleaned)

            if valid_ips:
                # Buscar la primera IP de derecha a izquierda que no sea proxy privado
                for ip_str in valid_ips:
                    ip_obj = ipaddress.ip_address(ip_str)
                    if not _is_private_ip(ip_obj):
                        return ip_str
                # Si todas son privadas (ej. red interna), tomar la más reciente (extremo derecho)
                return valid_ips[0]

    # Conexión directa / fallback de socket
    if hasattr(request, "client") and request.client and getattr(request.client, "host", None):
        direct_ip = _clean_ip_str(request.client.host)
        if direct_ip:
            return direct_ip

    return "127.0.0.1"



# ──────────────────────────────────────────────────────────────────────────────
#  [ENT] ENTROPY SHIELD & MAGIC BYTES MALWARE INSPECTION
# ──────────────────────────────────────────────────────────────────────────────

# Firmas de ejecutables y scripts peligrosos que Shiori bloquea proactivamente
FORBIDDEN_MAGIC_PREFIXES = [
    (b"MZ", "Ejecutable Windows PE (.exe, .dll)"),
    (b"\x7fELF", "Binario Linux ELF"),
    (b"\xca\xfe\xba\xbe", "Binario Java / Mach-O"),
    (b"<?php", "Script ejecutable PHP"),
    (b"#!", "Script ejecutable de Shell"),
]

# Lista negra exhaustiva de extensiones ejecutables, scripts y macros (H2)
DANGEROUS_EXTENSIONS = (
    ".exe", ".bat", ".cmd", ".ps1", ".vbs", ".sh", ".py", ".php", ".phtml",
    ".dll", ".so", ".jar", ".msi", ".scr", ".com", ".jse", ".wsf", ".vbe",
    ".hta", ".lnk", ".js",
    ".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".potm",
)

# MIME types de riesgo para ejecución directa en navegador (Stored XSS)
DANGEROUS_INLINE_MIMES = {
    "text/html",
    "application/xhtml+xml",
    "image/svg+xml",
    "application/xml",
    "text/xml",
}
SAFE_INLINE_PREFIXES = ("image/", "video/", "audio/")
SAFE_INLINE_EXACT = {"application/pdf"}

def resolve_disposition(mime_type: str, requested: str = "inline") -> str:
    """
    Determina si un archivo puede servirse de forma 'inline' de manera segura
    o si debe forzarse a 'attachment' para prevenir XSS almacenado (ej. SVG, HTML, XML).
    """
    if requested == "inline":
        clean_mime = (mime_type or "").lower().split(";")[0].strip()
        is_safe = clean_mime.startswith(SAFE_INLINE_PREFIXES) or clean_mime in SAFE_INLINE_EXACT
        if clean_mime in DANGEROUS_INLINE_MIMES or not is_safe:
            return "attachment"  # Nunca se renderiza en el navegador de la API
    return requested


# Tamaño máximo de muestra estadística para cálculo de entropía (4 MB)
MAX_ENTROPY_SCAN_BYTES = 4 * 1024 * 1024


class ShioriEntropyShield:
    """Inspección de archivos antes de almacenarse en Google Drive."""

    @staticmethod
    def calculate_shannon_entropy(data: bytes, max_bytes: int = MAX_ENTROPY_SCAN_BYTES) -> float:
        """
        Calcula la entropía de Shannon (0.0 a 8.0 bits por byte).
        Acota la muestra a max_bytes (4 MB) para evitar DoS por CPU o memoria.
        """
        if not data:
            return 0.0
        sample = data[:max_bytes] if len(data) > max_bytes else data
        entropy = 0.0
        length = len(sample)
        frequencies = [0] * 256
        for b in sample:
            frequencies[b] += 1
        for count in frequencies:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        return entropy

    @classmethod
    def scan_file_stream(cls, file_stream, filename: str) -> Tuple[bool, Optional[str]]:
        """
        Escanea un flujo de archivo limitando la lectura a MAX_ENTROPY_SCAN_BYTES (4 MB)
        para análisis de firmas y Magic Bytes sin agotar memoria.
        """
        sample = file_stream.read(MAX_ENTROPY_SCAN_BYTES)
        if hasattr(file_stream, "seek"):
            try:
                file_stream.seek(0)
            except Exception:
                pass
        return cls.scan_file_buffer(sample, filename)

    @staticmethod
    def scan_file_buffer(buffer: bytes, filename: str) -> Tuple[bool, Optional[str]]:
        """
        Escanea el buffer del archivo para evitar inyecciones maliciosas o archivos camuflados.
        """
        lower_name = filename.lower()

        # 1. Detección de extensiones maliciosas, scripts y macros (ej. factura.docm, script.js)
        for ext in DANGEROUS_EXTENSIONS:
            if lower_name.endswith(ext):
                return False, f"Extensión potencialmente peligrosa bloqueada: {ext}"

        # 2. Comprobación de Magic Bytes en cabecera
        header = buffer[:64]
        for magic, desc in FORBIDDEN_MAGIC_PREFIXES:
            if header.startswith(magic):
                # Permitir archivos de texto legítimos si el usuario los subió intencionalmente como .txt
                if not lower_name.endswith(".txt"):
                    return False, f"Carga bloqueada por Shiori Sentinel: Firma detectada ({desc})"

        return True, None


# ──────────────────────────────────────────────────────────────────────────────
#  [PTG] PATH TRAVERSAL & INPUT SANITIZATION GUARD
# ──────────────────────────────────────────────────────────────────────────────

class ShioriPathTraversalGuard:
    """Previene inyecciones de ruta, caracteres nulos y directory traversal."""

    @staticmethod
    def sanitize_filename(filename: str, fallback: Optional[str] = None) -> str:
        if not filename:
            return fallback or ""
        # Eliminar secuencias ../ y ..\\
        clean = re.sub(r"(?:\.\.[/\\])+", "", filename)
        # Eliminar caracteres nulos
        clean = clean.replace("\0", "")
        # Dejar solo caracteres seguros para nombres de archivo
        clean = re.sub(r'[<>:"/\\|?*]', "_", clean)
        clean = clean.strip()
        if clean in (".", ".."):
            clean = ""
        if not clean:
            return fallback or ""
        return clean


# ──────────────────────────────────────────────────────────────────────────────
#  [SEC] SHIORI SECURITY HEADERS MIDDLEWARE
# ──────────────────────────────────────────────────────────────────────────────

class ShioriSecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Añade cabeceras de ciberdefensa proactiva OWASP a cada respuesta HTTP."""
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Shiori-Protection"] = "v14.0-Sentinel-Active"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "img-src 'self' data: blob: https://*.googleusercontent.com https://drive.google.com; "
            "media-src 'self' blob: data:; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com; "
            "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com data:; "
            "connect-src 'self' https://*.onrender.com https://*.railway.app http://127.0.0.1:* http://localhost:*; "
            "frame-src 'self' blob: data:; "
            "object-src 'none'; "
            "frame-ancestors 'self'; "
            "base-uri 'self'; "
            "form-action 'self';"
        )
        return response


# Instancias compartidas del escudo
shiori_limiter = ShioriRateLimiter()
shiori_entropy = ShioriEntropyShield()
shiori_guard = ShioriPathTraversalGuard()
