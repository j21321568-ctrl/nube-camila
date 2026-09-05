"""
Filtro de seguridad para logging de Uvicorn y FastAPI.
Redacta automáticamente tokens de sesión o efímeros presentes en parámetros de URL (query strings)
para evitar fugas de credenciales en logs de servidor, Render, Datadog o consolas.
"""
import logging
import re
from typing import Optional

# Patrón para detectar parámetros de token en URLs y textos de registro
# Captura tanto ?token=... como &token=...
TOKEN_PARAM_REGEX = re.compile(r"((?:[?&]|\b)token=)[^&\s\"']+", re.IGNORECASE)

class RedactTokenFilter(logging.Filter):
    """
    logging.Filter que intercepta LogRecords y reemplaza cualquier token en URLs
    por 'token=REDACTED'.
    """
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            # 1. Uvicorn access log coloca los datos de la petición en record.args:
            # record.args = (client_ip, method, full_path, http_version, status_code)
            if record.args:
                new_args = []
                for arg in record.args:
                    if isinstance(arg, str):
                        new_args.append(TOKEN_PARAM_REGEX.sub(r"\g<1>REDACTED", arg))
                    else:
                        new_args.append(arg)
                record.args = tuple(new_args)

            # 2. Si el mensaje ya es un string con la URL (p.ej. logs manuales o formateados)
            if isinstance(record.msg, str):
                record.msg = TOKEN_PARAM_REGEX.sub(r"\g<1>REDACTED", record.msg)
        except Exception:
            pass  # En caso de error inesperado de formateo, nunca interrumpir el logging
        return True

def setup_secure_logging() -> None:
    """
    Aplica el filtro de redacción a todos los loggers relevantes de Uvicorn y la aplicación.
    """
    redact_filter = RedactTokenFilter()
    target_loggers = [
        "uvicorn.access",
        "uvicorn",
        "uvicorn.error",
        "fastapi",
        "root"
    ]
    
    for name in target_loggers:
        logger = logging.getLogger(name if name != "root" else None)
        logger.addFilter(redact_filter)
        for handler in logger.handlers:
            handler.addFilter(redact_filter)
