"""
╔══════════════════════════════════════════════════════════════════════════════╗
║        SHIORI SENTINEL v14.0 — AUDIT LOGGING & ALERTING SUBSYSTEM (M4)      ║
║        Registro Inmutable de Eventos Sensibles y Alertas en Tiempo Real      ║
╚══════════════════════════════════════════════════════════════════════════════╝
Proporciona:
  - Registro estructurado de eventos de autenticación, ciclo de vida de archivos y ciberdefensa.
  - Almacenamiento seguro en disco mediante rotación automática (RotatingFileHandler).
  - Buffer circular en memoria para auditoría forense en tiempo real desde la API.
  - Sanitización estricta para garantizar cero fugas de contraseñas, tokens o secretos.
  - Notificaciones inmediatas hacia Webhooks (Discord, Slack, Telegram) para eventos críticos.
"""
import os
import json
import logging
import threading
import urllib.request
import urllib.error
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from collections import deque
from pathlib import Path
from typing import Dict, Any, Optional, List

from .config import (
    SECURITY_WEBHOOK_URL,
    SECURITY_ALERT_LEVEL,
    AUDIT_LOG_FILE,
    ENABLE_AUDIT_FILE_LOG
)

# Niveles numéricos estándar para comparación de severidad
LEVEL_PRIORITIES = {
    "DEBUG": 10,
    "INFO": 20,
    "WARNING": 30,
    "ERROR": 40,
    "CRITICAL": 50,
}

# Palabras clave sensibles que NUNCA deben aparecer en texto claro en logs de auditoría
SENSITIVE_KEYS = {
    "password", "passwd", "pwd", "secret", "token", "totp_code",
    "code", "authorization", "cookie", "credentials", "session"
}

def sanitize_audit_payload(obj: Any) -> Any:
    """Sanitiza recursivamente cualquier estructura de datos eliminando secretos sensibles."""
    if isinstance(obj, dict):
        clean_dict = {}
        for k, v in obj.items():
            if str(k).lower() in SENSITIVE_KEYS or any(s in str(k).lower() for s in ("password", "secret", "token")):
                clean_dict[k] = "[REDACTED]"
            else:
                clean_dict[k] = sanitize_audit_payload(v)
        return clean_dict
    elif isinstance(obj, list):
        return [sanitize_audit_payload(item) for item in obj]
    elif isinstance(obj, tuple):
        return tuple(sanitize_audit_payload(item) for item in obj)
    return obj


class ShioriAuditLogger:
    """
    Motor central de auditoría de seguridad de Shiori Sentinel v14.
    """
    def __init__(self):
        self._lock = threading.Lock()
        self._buffer: deque = deque(maxlen=200)
        self.logger = logging.getLogger("shiori.audit")
        self.logger.setLevel(logging.INFO)
        self.logger.propagate = False

        # Configurar salida a consola/stdout con formato legible
        if not any(isinstance(h, logging.StreamHandler) for h in self.logger.handlers):
            stream_handler = logging.StreamHandler()
            stream_handler.setLevel(logging.INFO)
            stream_formatter = logging.Formatter("[AUDIT] %(message)s")
            stream_handler.setFormatter(stream_formatter)
            self.logger.addHandler(stream_handler)

        # Configurar archivo de log rotativo seguro si está habilitado
        if ENABLE_AUDIT_FILE_LOG:
            try:
                log_path = Path(AUDIT_LOG_FILE)
                log_path.parent.mkdir(parents=True, exist_ok=True)
                file_handler = RotatingFileHandler(
                    filename=str(log_path),
                    maxBytes=10 * 1024 * 1024,  # 10 MB por archivo
                    backupCount=5,               # Conservar 5 rotaciones históricas
                    encoding="utf-8"
                )
                file_handler.setLevel(logging.INFO)
                file_formatter = logging.Formatter(
                    "%(asctime)s [%(levelname)s] %(message)s",
                    datefmt="%Y-%m-%d %H:%M:%S"
                )
                file_handler.setFormatter(file_formatter)
                self.logger.addHandler(file_handler)
            except Exception as e:
                # Si no hay permisos en disco (p.ej. contenedor read-only), no romper el arranque
                self.logger.warning(f"No se pudo inicializar RotatingFileHandler en {AUDIT_LOG_FILE}: {e}")

    def log(
        self,
        event: str,
        level: str = "INFO",
        ip: str = "127.0.0.1",
        actor: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Registra un evento de seguridad estructurado y procesa alertas automáticas.
        """
        level_upper = level.upper().strip()
        if level_upper not in LEVEL_PRIORITIES:
            level_upper = "INFO"

        timestamp_iso = datetime.now(timezone.utc).isoformat()
        clean_details = sanitize_audit_payload(details or {})

        record = {
            "timestamp": timestamp_iso,
            "event": event,
            "level": level_upper,
            "ip": ip,
            "actor": actor or "anonymous",
            "details": clean_details
        }

        # Guardar en buffer en memoria (thread-safe)
        with self._lock:
            self._buffer.append(record)

        # Emitir log formateado
        details_str = json.dumps(clean_details, ensure_ascii=False) if clean_details else "{}"
        log_line = f"{timestamp_iso} | EVENT={event} | LEVEL={level_upper} | IP={ip} | ACTOR={actor or 'anonymous'} | DETAILS={details_str}"

        log_fn = getattr(self.logger, level_upper.lower(), self.logger.info)
        log_fn(log_line)

        # Evaluar emisión de alertas vía Webhook
        self._evaluate_webhook_alert(record)

        return record

    def _evaluate_webhook_alert(self, record: Dict[str, Any]) -> None:
        """Determina si el evento amerita despacho de alerta vía Webhook."""
        webhook_url = SECURITY_WEBHOOK_URL
        if not webhook_url:
            return

        record_priority = LEVEL_PRIORITIES.get(record["level"], 20)
        threshold_priority = LEVEL_PRIORITIES.get(SECURITY_ALERT_LEVEL, 50)

        # Se dispara si alcanza o supera el umbral configurado (por defecto CRITICAL)
        if record_priority >= threshold_priority:
            # Despachar en hilo de fondo para no bloquear la petición del usuario
            threading.Thread(
                target=self._send_webhook_notification,
                args=(webhook_url, record),
                daemon=True
            ).start()

    def _send_webhook_notification(self, webhook_url: str, record: Dict[str, Any]) -> bool:
        """Envía el payload HTTP POST al Webhook con tolerancia a fallos."""
        try:
            event = record["event"]
            level = record["level"]
            ip = record["ip"]
            actor = record["actor"]
            details = record["details"]
            timestamp = record["timestamp"]

            # Formato compatible tanto con Discord, Slack como con receptores genéricos JSON
            is_critical = (level == "CRITICAL")
            emoji = "🚨" if is_critical else "⚠️"
            color = 15158332 if is_critical else 15105570  # Rojo o Ámbar

            formatted_details = "\n".join(f"• **{k}**: `{v}`" for k, v in details.items()) if details else "_Sin detalles adicionales_"

            payload = {
                "username": "Shiori Sentinel v14",
                "content": f"{emoji} **[ALERTA DE SEGURIDAD SHIORI]** Evento: `{event}` detectado desde IP `{ip}`",
                "event": event,
                "level": level,
                "ip": ip,
                "actor": actor,
                "timestamp": timestamp,
                "details": details,
                "embeds": [
                    {
                        "title": f"{emoji} Alerta de Ciberdefensa: {event}",
                        "description": f"Evento de seguridad registrado por Shiori Sentinel en la Nube Privada de Camila.",
                        "color": color,
                        "fields": [
                            {"name": "Severidad", "value": level, "inline": True},
                            {"name": "IP Origen", "value": f"`{ip}`", "inline": True},
                            {"name": "Actor", "value": f"`{actor}`", "inline": True},
                            {"name": "Fecha UTC", "value": timestamp, "inline": False},
                            {"name": "Detalles", "value": formatted_details, "inline": False}
                        ],
                        "footer": {"text": "Nube Privada de Camila • Shiori Defense Module v14"}
                    }
                ]
            }

            req_data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                webhook_url,
                data=req_data,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "ShioriSentinelAudit/14.0"
                },
                method="POST"
            )

            # Timeout acotado de 3.5 segundos para no consumir recursos del hilo
            with urllib.request.urlopen(req, timeout=3.5) as resp:
                return resp.status in (200, 204)
        except Exception as err:
            # La falla de un webhook externo NUNCA debe alterar la operación principal
            self.logger.warning(f"Error al despachar alerta a Webhook de seguridad ({webhook_url}): {err}")
            return False

    def get_recent_events(
        self,
        limit: int = 50,
        min_level: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Retorna los eventos más recientes del buffer en memoria filtrados por severidad."""
        with self._lock:
            items = list(self._buffer)

        if min_level:
            min_pri = LEVEL_PRIORITIES.get(min_level.upper().strip(), 0)
            items = [item for item in items if LEVEL_PRIORITIES.get(item["level"], 0) >= min_pri]

        return items[-limit:][::-1]  # Retornar más recientes primero


# Instancia global única del subsistema de auditoría Shiori
shiori_audit = ShioriAuditLogger()
