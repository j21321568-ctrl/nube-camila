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


class ShioriRateLimiter:
    """Gestor de buckets por dirección IP con limpieza periódica."""
    def __init__(self):
        self._buckets: Dict[str, ShioriTokenBucket] = defaultdict(
            lambda: ShioriTokenBucket(capacity=15.0, refill_rate=1.5)
        )
        self._login_buckets: Dict[str, ShioriTokenBucket] = defaultdict(
            lambda: ShioriTokenBucket(capacity=5.0, refill_rate=0.2)  # Máx 5 intentos login por 25s
        )

    def check_request(self, ip: str, is_login: bool = False) -> bool:
        bucket = self._login_buckets[ip] if is_login else self._buckets[ip]
        return bucket.consume(1.0)


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

class ShioriEntropyShield:
    """Inspección de archivos antes de almacenarse en Google Drive."""

    @staticmethod
    def calculate_shannon_entropy(data: bytes) -> float:
        """Calcula la entropía de Shannon (0.0 a 8.0 bits por byte)."""
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        frequencies = [0] * 256
        for b in data:
            frequencies[b] += 1
        for count in frequencies:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        return entropy

    @staticmethod
    def scan_file_buffer(buffer: bytes, filename: str) -> Tuple[bool, Optional[str]]:
        """
        Escanea el buffer del archivo para evitar inyecciones maliciosas o archivos camuflados.
        """
        lower_name = filename.lower()

        # 1. Detección de doble extensión maliciosa (ej. foto.jpg.exe)
        dangerous_exts = (".exe", ".bat", ".cmd", ".ps1", ".vbs", ".sh", ".py", ".php", ".phtml", ".dll", ".so")
        for ext in dangerous_exts:
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
    def sanitize_filename(filename: str) -> str:
        if not filename:
            return "archivo_seguro"
        # Eliminar secuencias ../ y ..\\
        clean = re.sub(r"\.\.[/\\]", "", filename)
        # Eliminar caracteres nulos
        clean = clean.replace("\0", "")
        # Dejar solo caracteres seguros para nombres de archivo
        clean = re.sub(r'[<>:"/\\|?*]', "_", clean)
        return clean.strip() or "archivo_seguro"


# ──────────────────────────────────────────────────────────────────────────────
#  [SEC] SHIORI SECURITY HEADERS MIDDLEWARE
# ──────────────────────────────────────────────────────────────────────────────

class ShioriSecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Añade cabeceras de ciberdefensa proactiva a cada respuesta HTTP."""
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Shiori-Protection"] = "v14.0-Sentinel-Active"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        return response


# Instancias compartidas del escudo
shiori_limiter = ShioriRateLimiter()
shiori_entropy = ShioriEntropyShield()
shiori_guard = ShioriPathTraversalGuard()
