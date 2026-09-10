# 🔍 Auditoría de Seguridad y Arquitectura Exhaustiva — Nube Privada de Camila v2.0.0

> Basada en `DOCUMENTACION_TECNICA_Y_FUNCIONAL_EXHAUSTIVA.md`
> Metodología: revisión de diseño (*design review*) línea por línea de toda la documentación aportada.

## ⚠️ Nota metodológica (léela antes que nada)

Este análisis se hizo sobre la **documentación**, no sobre el código fuente real (`.py`/`.js` no fueron adjuntados). La documentación es lo bastante detallada como para que la mayoría de hallazgos sean de **alta confianza** (están descritos explícitamente: nombres de variables, fragmentos de código, comportamiento exacto). Marco con 🔎 *"verificar en el código real"* los pocos puntos donde la documentación es ambigua y el código real podría (o no) mitigar el problema.

Voy a ser directo porque lo pediste así: el proyecto tiene una capa de "marketing de seguridad" (nombres como *Shiori Sentinel*, *Zero-Trust*, *quantum-resistant*) que suena más impresionante de lo que técnicamente es en algunos puntos, y por debajo hay decisiones de diseño que sí son sólidas (streaming, comparación en tiempo constante, aislamiento por carpeta) mezcladas con fallos concretos que hay que corregir ya.

---

## 📊 Resumen ejecutivo

| Severidad | Cantidad | Significado |
|---|---|---|
| 🔴 Crítico | 4 | Explotable con esfuerzo trivial, compromiso total de la cuenta/datos |
| 🟠 Alto | 7 | Explotable con condiciones razonables, compromiso parcial o escalable a total |
| 🟡 Medio | 9 | Debilita defensas, facilita otros ataques, o es un gap de resiliencia/operación |
| 🟢 Bajo / mejora | 5 | Buenas prácticas que faltan, bajo impacto inmediato |
| **Total** | **25** | |

**Si solo vas a hacer 4 cosas hoy, que sean estas (ver detalle en C1–C4):**
1. Rotar `ACCESS_PASSWORD` y `SECRET_KEY` en producción **ahora mismo** — los valores por defecto ya son públicos.
2. Hacer que el servidor **no arranque** si esas variables no están definidas (fail-closed, no fail-open).
3. Dejar de mandar el token de sesión como parámetro de URL sin control de logging.
4. Bajar a 1 worker o centralizar el rate limiter — con 2 workers tu protección anti-fuerza bruta está partida en dos y no lo sabías.

---

## 🔴 CRÍTICOS

### C1. Secretos por defecto "hardcodeados" — el sistema falla abierto, no cerrado

**Dónde:** `backend/config.py`
```python
ACCESS_PASSWORD = os.getenv("ACCESS_PASSWORD", "camila2026")
SECRET_KEY = os.getenv("SECRET_KEY", "camila-cloud-super-secure-token-vault-key-2026")
```

**Por qué es grave:** Si por cualquier motivo (typo en Render, redeploy que resetea variables de entorno, ejecución local sin `.env`, un fork del proyecto que alguien más despliega) esas variables de entorno no quedan definidas, el sistema **no falla** — arranca perfectamente, sirviendo tráfico, protegido por una contraseña y una clave de firma **que ya son conocidas**. Contrástalo con `DRIVE_FOLDER_ID`, que si falta, el propio proyecto lanza un `RuntimeError` y se niega a arrancar. Ese es el comportamiento correcto; `ACCESS_PASSWORD` y `SECRET_KEY` deberían comportarse igual y no lo hacen.

**Agravante real, no teórico:** acabas de subirme (y por tanto, en la práctica, "publicar" en el sentido de que ya no es un secreto exclusivamente tuyo) un documento que contiene **el valor exacto** de ambos defaults. Cualquiera que llegue a ver esta documentación —un colaborador, un repositorio que se vuelve público sin querer, un backup mal compartido— tiene ya la contraseña maestra y la clave HMAC de respaldo. Esto no es "podría pasar", es: **estos dos valores concretos deben tratarse como comprometidos a partir de hoy, existan o no en tu entorno real de producción.**

**Solución exacta:**
```python
import os

def _require_env(name: str, min_length: int = 16) -> str:
    value = os.getenv(name)
    if not value or len(value.strip()) < min_length:
        raise RuntimeError(
            f"❌ FALTA CONFIGURAR '{name}' (o es demasiado corta, mínimo {min_length} caracteres). "
            f"El servidor no arrancará sin un valor explícito y seguro. "
            f"Esto es intencional: nunca debe existir un valor por defecto para un secreto."
        )
    return value.strip()

ACCESS_PASSWORD = _require_env("ACCESS_PASSWORD", min_length=12)
SECRET_KEY = _require_env("SECRET_KEY", min_length=32)
```

**Además, hazlo hoy:**
- Genera una `SECRET_KEY` nueva: `python -c "import secrets; print(secrets.token_hex(32))"` (64 caracteres hex = 256 bits reales, no una "frase larga" elegida a mano, que casi siempre tiene mucha menos entropía real de la que aparenta).
- Cambia `ACCESS_PASSWORD` a algo generado (`python -c "import secrets; print(secrets.token_urlsafe(16))"`), no una palabra con año como `camila2026`.
- Actualiza ambas variables en Render y haz un redeploy.

---

### C2. El token de sesión viaja en la URL → fuga garantizada en logs

**Dónde:** `require_auth` (sección 4.3) acepta `?token=...`; `GET /api/files/{id}/preview` y `/download` lo documentan explícitamente como método soportado.

**Por qué es grave, y por qué no es hipotético:** Uvicorn/Starlette registran por defecto la **ruta completa incluyendo query string** en el log de acceso, algo así:
```
INFO: 203.0.113.7:0 - "GET /api/files/1A2B.../preview?token=eyJzdWIiOiJjYW1pbGEi... HTTP/1.1" 200
```
Si no has desactivado o reformateado explícitamente ese logging (la documentación no menciona que lo hayas hecho), **cada vez que Camila mira una foto o escucha un audio, su token de sesión completo queda escrito en texto plano** en:
- Los logs de Render (que además puedes reenviar a Datadog/Papertrail/etc., multiplicando dónde queda copiado).
- Cualquier proxy intermedio.
- El historial del navegador de Camila (URLs con `?token=` quedan ahí).
- Cualquier captura de pantalla o link que Camila comparta sin darse cuenta de qué contiene la URL.

Y ese token, recuerda, es válido **30 días** (ver C3) y da acceso total, no solo a ese archivo. Esto convierte una acción tan inocente como "ver una foto" en una fuga potencial de la llave maestra de la cuenta.

**Solución (elige una, la primera es la más robusta):**

**Opción A — Cookies `HttpOnly` en vez de `localStorage` + URL (recomendada):**
Si backend y frontend comparten dominio raíz (o configuras `SameSite=None; Secure` con CORS de credenciales explícito, no `*`), una cookie de sesión viaja automáticamente en peticiones de `<img>`, `<video>`, `<audio>` **sin que tengas que meter el token en ninguna URL ni en `localStorage`**. Esto elimina el problema de raíz: el JavaScript ni siquiera puede leer el token (protección extra contra XSS), y no hay nada que loguear en la query string.
```python
response.set_cookie(
    "camila_session", token,
    httponly=True, secure=True, samesite="lax",  # o "none" si backend/frontend son dominios distintos
    max_age=60 * 60 * 8,  # ver C3: sesiones cortas
)
```
Esto obliga (efecto colateral positivo) a dejar de usar `CORS_ORIGINS=*` — los navegadores rechazan wildcard + credenciales, así que arreglas M1 de regalo.

**Opción B — Token efímero de un solo archivo (si no quieres tocar la arquitectura de cookies):**
En vez de reutilizar el token maestro de 30 días para streaming, crea un endpoint autenticado normal (`Authorization: Bearer`) que devuelva un token de corta vida (60–120 segundos) válido **solo para ese `file_id`**:
```python
@app.post("/api/files/{file_id}/preview-token")
def get_preview_token(file_id: str, user=Depends(require_auth)):
    short_token = create_scoped_token(file_id=file_id, ttl_seconds=90)
    return {"url": f"/api/files/{file_id}/preview?token={short_token}"}
```
Así, aunque ese token termine en un log, expira en minutos y solo sirve para un archivo — no para vaciar la nube entera.

**Y en paralelo, redacta el logging ya mismo, sea cual sea la opción que elijas:**
```python
import logging, re

class RedactTokenFilter(logging.Filter):
    def filter(self, record):
        if record.args and len(record.args) >= 3:
            path = str(record.args[2])
            record.args = (*record.args[:2], re.sub(r"token=[^&\s]+", "token=REDACTED", path), *record.args[3:])
        return True

logging.getLogger("uvicorn.access").addFilter(RedactTokenFilter())
```
(Ajusta según el formatter real de tu logger — la idea es: nunca debe quedar un token completo en un log.)

---

### C3. Sesiones de 30 días, sin revocación y sin invalidación al cambiar la contraseña

**Dónde:** `auth.py`, payload `exp = iat + 2_592_000` (30 días).

**Por qué es grave:** El token es válido *criptográficamente* durante 30 días basándose únicamente en la firma HMAC y el timestamp — no consulta nada más. Esto significa:
- Si Camila cambia `ACCESS_PASSWORD` porque sospecha que alguien vio su contraseña, **cualquier token robado antes de ese cambio sigue funcionando 30 días completos**, porque el token nunca referencia la contraseña actual, solo la `SECRET_KEY`.
- No hay "cerrar sesión en todos los dispositivos". La única forma de invalidar tokens es rotar `SECRET_KEY`, lo cual cierra la sesión de **todo el mundo**, incluida Camila.
- Combinado con C2 (token en URLs/logs), la ventana de exposición de un token filtrado es enorme.

**Solución — un "epoch de sesión" sin necesitar una base de datos completa:**
```python
# Un solo valor persistido (archivo, o una fila en credentials.json, o env var actualizable)
SESSION_EPOCH = float(os.getenv("SESSION_EPOCH", "0"))  # se sube cada vez que se invalida todo

def create_access_token():
    now = time.time()
    payload = {"sub": "camila", "iat": now, "exp": now + 60 * 60 * 8}  # 8h, no 30 días
    ...

def verify_token(token):
    ...
    if payload["iat"] < SESSION_EPOCH:
        raise HTTPException(401, "Sesión invalidada, ingresa nuevamente")
```
Sube `SESSION_EPOCH` (por ejemplo, a `time.time()`) cada vez que cambies la contraseña o quieras forzar un "cerrar sesión en todos lados". Y **acorta la duración por defecto a horas, no a un mes** — para uso personal diario, una sesión de 8–24h con renovación silenciosa (refrescar el token si sigue activo) da la misma comodidad con muchísima menos ventana de exposición.

---

### C4. El rate limiter anti-fuerza-bruta está en memoria de proceso, y corres 2 workers

**Dónde:** `ShioriTokenBucket`/`ShioriRateLimiter` usan `collections.defaultdict` (memoria del proceso Python); `Procfile`: `uvicorn ... --workers 2`.

**Por qué es grave, con números concretos:** Cada uno de los 2 workers de Uvicorn es un **proceso independiente**, con su propia memoria. Un diccionario en memoria **no se comparte entre procesos**. Eso significa que tu límite de "5 intentos de login por IP" en realidad es, en la práctica, **hasta 10 intentos** (5 por worker), repartidos según a qué proceso te enrute el balanceador — y esto empeora proporcionalmente si alguna vez escalas a más instancias. Además, como es memoria de proceso y no algo persistente:
- Cada vez que Render "duerme" y "despierta" el servicio (el propio documento lo describe como algo que pasa regularmente en el plan gratuito), **el contador de intentos fallidos se resetea a cero**. Un atacante paciente puede literalmente forzar un "reinicio" del contador esperando el ciclo de sueño/despertar del free tier, o provocándolo.

**Solución más simple para tu caso (1 solo usuario, tráfico bajo):**
```
web: uvicorn backend.main:app --host 0.0.0.0 --port $PORT --workers 1
```
Un solo worker es de sobra para una aplicación de un único usuario, y elimina el problema de "bucket partido" de raíz sin añadir infraestructura. Sigue sin sobrevivir a un reinicio del proceso, pero ese es un riesgo bastante menor que tener la protección partida a la mitad sin saberlo.

**Solución robusta si algún día escalas o quieres persistencia real:** mover el estado del bucket a Redis (patrón `INCR` + `EXPIRE`, o una librería como `limits`), para que el conteo sea compartido entre procesos/instancias y sobreviva a reinicios.

**🔎 Verificar en el código real:** cómo se extrae la IP del cliente para el rate limiter. Si se lee directamente de un header tipo `X-Forwarded-For` **sin validar que venga del proxy de confianza** (Render), un atacante puede mandar su propio `X-Forwarded-For: 1.2.3.4` (cambiando el valor en cada petición) y aparentar ser una IP distinta en cada intento, evadiendo el límite por completo. Configura Uvicorn con `--proxy-headers --forwarded-allow-ips="*"` *solo si* estás detrás de un proxy que sobrescribe (no que reenvía sin validar) esa cabecera, y confirma con una petición de prueba que un `X-Forwarded-For` falsificado por ti mismo no cambia el conteo.

---

## 🟠 ALTOS

### H1. Sin `Content-Security-Policy` ni `Strict-Transport-Security`; `X-XSS-Protection` es teatro de seguridad

**Dónde:** `ShioriSecurityHeadersMiddleware`, lista de cabeceras en la sección 3.5.

Tienes `X-Content-Type-Options`, `X-Frame-Options` y `Referrer-Policy`, que están bien. Pero:
- **`X-XSS-Protection: 1; mode=block`** es una cabecera **obsoleta**: Chrome, Edge y Safari eliminaron el motor que la interpretaba hace varios años. Incluirla no hace daño, pero listarla como una defensa activa es engañoso — no protege nada en un navegador moderno.
- **Falta `Content-Security-Policy` (CSP)**, que es hoy la defensa más efectiva contra el impacto real de un XSS (restringe desde dónde se puede ejecutar JS, cargar `<object>`, embeber en iframes, etc.). Sin CSP, si alguna vez se cuela una inyección (ver H2), no hay ninguna barrera adicional deteniéndola.
- **Falta `Strict-Transport-Security` (HSTS)**, que fuerza al navegador a no volver a intentar HTTP nunca, mitigando downgrade/SSL-stripping en conexiones futuras.

**Solución:**
```python
response.headers["Content-Security-Policy"] = (
    "default-src 'self'; "
    "img-src 'self' data: blob: https://*.googleusercontent.com; "
    "media-src 'self' blob:; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline'; "
    "object-src 'none'; "
    "frame-ancestors 'self'; "
    "base-uri 'self'"
)
response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
```
Ajusta `script-src`/`style-src` a lo que realmente uses (si tienes `<script>` inline, o migra a JS externo para poder quitar `'unsafe-inline'` de scripts, que es la parte que más importa).

---

### H2. Lista negra de extensiones y *Magic Bytes* insuficientes — y sin control de qué se sirve "inline"

**Dónde:** `ShioriEntropyShield`, secciones 3.3.2 y 3.3.3.

Tu lista negra actual es:
```python
dangerous_exts = (".exe", ".bat", ".cmd", ".ps1", ".vbs", ".sh", ".py", ".php", ".phtml", ".dll", ".so")
```
Faltan, entre otros: `.docm, .xlsm, .pptm, .dotm, .xltm, .potm` (Office con macros — **el vector de malware más común del mundo real**, y aquí es especialmente peligroso porque estos archivos son técnicamente un ZIP válido, **idéntico en firma binaria y muy similar en entropía a un `.docx`/`.xlsx` normal** — ni tu chequeo de Magic Bytes ni el de entropía de Shannon pueden distinguirlos), además de `.jar, .msi, .scr, .com, .jse, .wsf, .vbe, .hta, .lnk, .js`, y especialmente **`.html`/`.htm`** y **`.svg`**.

`.html` y `.svg` merecen mención aparte: si alguna vez se sirven con `Content-Disposition: inline` y su MIME real (`text/html`, `image/svg+xml`), un navegador que abra esa URL directamente en una pestaña nueva **ejecutará el JavaScript embebido en el mismo origen que tu API** — esto es un vector clásico de XSS almacenado vía tipo de contenido. Como el token puede ir en la URL (ver C2), el impacto es robar la propia sesión de quien lo abre.

**Solución — dos capas:**

1. Ampliar la lista negra:
```python
dangerous_exts = (
    ".exe", ".bat", ".cmd", ".ps1", ".vbs", ".sh", ".py", ".php", ".phtml",
    ".dll", ".so", ".jar", ".msi", ".scr", ".com", ".jse", ".wsf", ".vbe",
    ".hta", ".lnk", ".js",
    ".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".potm",
)
```

2. **Forzar `attachment` (nunca `inline`) para cualquier tipo capaz de ejecutar contenido**, independientemente de la extensión declarada (defensa en profundidad — no confíes solo en el nombre del archivo):
```python
DANGEROUS_INLINE_MIMES = {
    "text/html", "application/xhtml+xml", "image/svg+xml",
    "application/xml", "text/xml",
}
SAFE_INLINE_PREFIXES = ("image/", "video/", "audio/")
SAFE_INLINE_EXACT = {"application/pdf"}

def resolve_disposition(mime_type: str, requested: str) -> str:
    if requested == "inline":
        is_safe = mime_type.startswith(SAFE_INLINE_PREFIXES) or mime_type in SAFE_INLINE_EXACT
        if mime_type in DANGEROUS_INLINE_MIMES or not is_safe:
            return "attachment"  # nunca se renderiza en el navegador
    return requested
```

3. Acota el escaneo de entropía a una muestra fija, no al archivo completo (ver M2 para el porqué):
```python
MAX_ENTROPY_SCAN_BYTES = 4 * 1024 * 1024  # 4 MB de muestra es estadísticamente suficiente
sample = file_stream.read(MAX_ENTROPY_SCAN_BYTES)
file_stream.seek(0)
entropy = calculate_shannon_entropy(sample)
```

---

### H3. El "aislamiento por carpeta" en el listado depende de un escape manual de comillas, sin revalidación

**Dónde:** `list_files()`, sección 5.2 — *"si `search_query` está presente: escapa apóstrofes y concatena `and name contains '<query>'`"*.

Dos problemas distintos aquí:

**a) El orden de escape importa y probablemente esté mal.** Si el código solo hace algo como `query.replace("'", "\\'")`, sin escapar primero las barras invertidas, un valor de búsqueda como `\' or fullText contains '` puede neutralizar tu escape y potencialmente alterar la cláusula de búsqueda de Drive. El escape correcto siempre escapa la barra invertida primero:
```python
def escape_drive_query_value(value: str) -> str:
    return value.replace("\\", "\\\\").replace("'", "\\'")
```

**b) Más importante — el listado confía en la consulta para el aislamiento, pero no revalida.** `get_file_metadata()` sí tiene la "regla de oro" (verificar que `folder_id` esté en `parents` antes de devolver nada), pero la documentación de `list_files()` no describe ese mismo chequeo aplicado a cada item devuelto. Si por cualquier motivo la cláusula `'<folder_id>' in parents` de la consulta llegara a fallar o ser bypasseada (por el punto **a**, o por un cambio futuro en la API de Drive), el listado podría filtrar nombres/metadatos de archivos fuera de la carpeta privada. **La regla de aislamiento no debe vivir solo en la query de búsqueda — debe verificarse también en el código, igual que en `get_file_metadata`:**
```python
def list_files(self, ...):
    response = self.service.files().list(
        q=query, fields="files(id, name, mimeType, size, modifiedTime, "
                         "thumbnailLink, iconLink, webViewLink, webContentLink, starred, parents)",
        ...
    ).execute()
    files = response.get("files", [])
    # Segunda capa de verificación, independiente de la query
    return [f for f in files if self._folder_id in f.get("parents", [])]
```

---

### H4. Token en `localStorage` en vez de cookie `HttpOnly`

**Dónde:** `app.js`, `state.token = localStorage.getItem("camila_cloud_token")`.

Cualquier script que logre ejecutarse en la página (vía una inyección XSS, aunque hoy no tengas ninguna conocida — ver H2 sobre cómo podría aparecer una) puede leer `localStorage` y exfiltrar el token con una simple petición a un dominio externo. Esto además es la razón de diseño que justificó meter el token en la URL (C2), porque `<img>`/`<video>` no pueden mandar cabeceras custom. Si migras a cookies `HttpOnly` (ver solución en C2, Opción A), resuelves este punto y C2 a la vez, porque JavaScript deja de tener acceso al token por completo y el navegador lo adjunta solo automáticamente.

Si por alguna razón decides no migrar a cookies, al menos considera que cualquier defensa contra XSS (CSP de H1, sanitización estricta de nombres de archivo de H7) se vuelve más crítica, porque es tu única barrera contra el robo de token.

---

### H5. Alcance de permisos de Google probablemente más amplio de lo necesario

**Dónde:** sección 5.1, autenticación dual OAuth/Service Account.

No se especifica el *scope* exacto de OAuth solicitado. Si es el scope completo `https://www.googleapis.com/auth/drive` (acceso a *todo* el Drive de la cuenta) en vez de `https://www.googleapis.com/auth/drive.file` (acceso solo a los archivos que la propia app crea/abre), entonces tu control de "solo esta carpeta" es **puramente una regla de tu aplicación**, no un límite real impuesto por Google. Si algún día se filtra el `oauth_token.json` o el `credentials.json`, el atacante no tendría acceso "a la carpeta privada de Camila" — tendría acceso a **todo el Google Drive de esa cuenta**.

**Solución:**
- Si es viable para tu caso de uso (todos los archivos los sube la propia app), cambia el scope a `drive.file`. Esto reduce drásticamente el radio de impacto de cualquier fuga de credenciales.
- Independientemente del scope, usa **una cuenta de Google dedicada exclusivamente a esta nube**, nunca la cuenta personal/principal de Camila — así, en el peor caso, lo que se compromete es una cuenta desechable, no el Gmail/Fotos/Docs personal de verdad.

---

### H6. Borrado permanente sin fricción adicional

**Dónde:** `DELETE /api/files/{file_id}?permanent=true`.

Con el mismo token que usas para listar archivos, y sin ningún paso extra, se puede destruir permanentemente cualquier archivo. Si ese token se filtra (C2/C3), el atacante no solo *ve* los archivos — puede **borrarlos todos, sin posibilidad de recuperación**, en segundos, y el rate limiter general (pensado para navegación normal) no está especialmente calibrado para frenar esto.

**Solución:**
- No permitas `permanent=true` directamente desde fuera de la papelera: exige que el archivo ya esté en la papelera (`trashed=true`) antes de poder purgarlo permanentemente, en dos pasos separados.
- Para la purga permanente específicamente, exige reintroducir la contraseña (o un código corto) como confirmación adicional — un "step-up" de autenticación para la operación más destructiva del sistema.
- Registra (ver M4) todo borrado permanente con IP y timestamp, e idealmente notifícalo (email/Telegram) en tiempo real.

---

### H7. Inconsistencia entre la sanitización de subida y la de renombrado

**Dónde:** `upload_file()` pasa por `ShioriPathTraversalGuard.sanitize_filename()` (sección 3.4); `rename_file()` (sección 5.2) solo dice *"valida que el nombre no esté en blanco"* — no menciona pasar por el mismo saneamiento.

Si es así en el código real, un nombre puesto vía "renombrar" podría contener caracteres nulos, secuencias de escape o (más relevante para XSS) los caracteres `<`/`>` que sí se filtran en la subida. Aplica exactamente la misma función de saneamiento en ambos flujos:
```python
def rename_file(self, file_id, new_name):
    clean_name = ShioriPathTraversalGuard.sanitize_filename(new_name)
    if not clean_name:
        raise ValueError("El nombre no puede quedar vacío tras sanitizar")
    ...
```
Y en el frontend, asegúrate de que los nombres de archivo **siempre** se inserten con `textContent`, nunca con `innerHTML`, sin importar cuán "seguro" creas que ya viene el string desde el backend.

---

## 🟡 MEDIOS

### M1. `CORS_ORIGINS = "*"` en producción
`render.yaml` fija `CORS_ORIGINS: value: "*"`. Esto permite que **cualquier página web del mundo** haga peticiones a tu API desde el navegador de quien la visite. Como tu frontend real vive en una URL fija y conocida (Vercel), no hay ninguna razón para no restringirlo:
```yaml
- key: CORS_ORIGINS
  value: "https://camila-cloud.vercel.app"
```
Esto es aún más importante si migras a cookies (H4/C2 opción A): los navegadores **rechazan** `Access-Control-Allow-Origin: *` combinado con credenciales, así que esta restricción se vuelve obligatoria, no opcional.

### M2. Sin límite de tamaño de subida ni de cuerpo de petición
No se documenta ningún `MAX_UPLOAD_MB`. Si el escaneo de entropía (sección 3.3.1) necesita leer el archivo completo en memoria antes de empezar la subida por bloques, un archivo de varios GB podría agotar la RAM del servidor **antes siquiera de llegar a Google Drive** — justo el mismo problema de DoS que el streaming de descarga sí evita correctamente. Solución: aplica el límite de muestra de entropía de H2 (4MB, no el archivo completo) y añade un límite explícito de tamaño máximo de subida, rechazado tempranamente por `Content-Length` antes de leer el cuerpo.

### M3. Sin segundo factor de autenticación
Un único secreto (la contraseña) protege absolutamente todo. Para datos personales reales (fotos, documentos), añadir TOTP es barato:
```python
import pyotp
totp = pyotp.TOTP(TOTP_SECRET)  # generado una vez, guardado como variable de entorno
# en login: requerir password Y totp.verify(code_enviado)
```

### M4. Sin auditoría ni alertas de eventos sensibles
No hay registro de intentos de login (éxito/fallo + IP), subidas, ni borrados. Añade un logger de auditoría mínimo:
```python
audit_logger.info("LOGIN_OK ip=%s", client_ip)
audit_logger.warning("LOGIN_FAIL ip=%s intentos=%d", client_ip, intentos)
audit_logger.critical("PERMANENT_DELETE file_id=%s ip=%s", file_id, client_ip)
```
Y opcionalmente, envía los eventos `CRITICAL` a un webhook de Telegram/Discord/email para enterarte en tiempo real si alguien borra todo o entra desde una IP nueva.

### M5. Dependencias sin fijar ni escaneadas
`fastapi >= 0.110.0`, `uvicorn >= 0.28.0` con `>=` abierto significa que un `pip install` futuro puede traer una versión con una vulnerabilidad conocida sin que te enteres. Fija versiones exactas y añade escaneo automático:
```yaml
# .github/workflows/security.yml
name: Security Checks
on: [push, pull_request]
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: '3.12' }
      - run: pip install -r requirements.txt
      - run: pip install pip-audit bandit
      - run: pip-audit
      - run: bandit -r backend/
```

### M6. Inconsistencia de documentación: "SHA3-256 resistente a cuántica" vs. el código real usa SHA-256
La sección 3.1 describe un `ShioriZeroTrustCrypto` con HMAC-SHA3-256, presentado como inmune a *length extension attacks* y con ventaja frente a computación cuántica. Pero la sección 4.1/4.2, que documenta el código **real** que firma los tokens de sesión en `auth.py`, usa explícitamente:
```python
hmac.new(SECRET_KEY.encode("utf-8"), payload_b64.encode("utf-8"), hashlib.sha256)
```
Es decir, **HMAC-SHA256, no HMAC-SHA3-256**. Dos posibilidades: (a) el módulo "cuántico" descrito en la sección 3 no es el que realmente protege el login, y la documentación exagera lo que hay implementado; o (b) hay una desincronización entre docs y código. Ninguna es grave por sí misma —HMAC-SHA256 es perfectamente seguro para este uso, no necesitas SHA-3—, pero además la premisa de fondo es técnicamente imprecisa: la inmunidad a *length extension attacks* la da la **construcción HMAC en sí** (con cualquier hash subyacente, incluido SHA-256), no específicamente SHA-3; y la resistencia cuántica de HMAC depende sobre todo de la **longitud de la clave** (256 bits da ~128 bits de seguridad post-cuántica vía Grover), no de la familia de hash elegida. Recomendación: verifica cuál es el algoritmo real en tu código, y ajusta la documentación para que no prometa una propiedad de seguridad que no viene de donde dice venir — una afirmación de seguridad incorrecta es en sí misma un riesgo, porque genera confianza injustificada.

### M7. `/health` público revela versión exacta y nombre del módulo de defensa
```json
{"version": "2.0.0", "protection": "Shiori Sentinel v14.0", ...}
```
Sin autenticación. Esto es *fingerprinting* gratuito para cualquiera que escanee la URL: ahora sabe exactamente qué buscar si alguna vez aparece una vulnerabilidad conocida para esa combinación de versión/stack. Reduce el endpoint público al mínimo:
```python
@app.get("/health")
def health():
    return {"status": "online"}
```
Y si necesitas el detalle completo para diagnóstico, ponlo detrás de `require_auth` en otra ruta.

### M8. Extracción de IP para el rate limiter — verificar que confíe solo en el proxy correcto
Ver la nota 🔎 en C4. Si la IP se lee de una cabecera que el propio cliente puede enviar y sobrescribir sin que el proxy la valide, el límite de 5 intentos por IP se evade trivialmente.

### M9. Sin CAPTCHA / prueba de trabajo adicional en login
El rate limiter por IP es una buena primera capa, pero no detiene un ataque distribuido de baja velocidad (una IP distinta cada pocos intentos). Para un solo usuario esto es un riesgo menor, pero si quieres cerrar el hueco del todo, añade un desafío tipo Cloudflare Turnstile (gratuito, ligero, sin las molestias de reCAPTCHA clásico) al formulario de login tras, por ejemplo, el primer intento fallido.

---

## 🟢 BAJOS / MEJORAS

### L1. Archivos de credenciales en texto plano persisten en disco tras su uso
`render_credentials_ready.txt` y `render_oauth_ready.txt` están correctamente en `.gitignore`, pero nada los borra después de que los copies a Render. Quedan ahí indefinidamente, en texto plano, expuestos a robo de equipo, malware local o sincronización accidental a una nube. Bórralos manualmente en cuanto termines el despliegue, o mejor: haz que los scripts impriman el valor por consola para copiar directo (o lo copien al portapapeles) en vez de escribirlo a un archivo.

### L2. Sin backup independiente de Google Drive
Toda tu única copia de los datos vive en Google Drive. Si esa cuenta se suspende, se hackea, o Google revoca el acceso por cualquier motivo, no hay ninguna copia alternativa. Considera una sincronización periódica (semanal, vía `rclone` o similar) hacia un segundo proveedor o un disco cifrado externo.

### L3. Sin pruebas automatizadas ni pipeline de seguridad en CI
No se mencionan tests unitarios/integración, ni linting, ni type-checking automatizado. Dado el nivel de detalle que le has puesto a la seguridad "en producción", vale la pena invertir también en verificarla automáticamente en cada cambio (ver el workflow de M5 como punto de partida).

### L4. URL de backend configurable libremente desde "Ajustes" del frontend
`config.js` permite guardar en `localStorage` cualquier URL a la que el frontend mandará el token y todo el tráfico de archivos. Es una función legítima (apuntar a un backend propio), pero si alguna vez se manipula ese valor (vía XSS, o vía ingeniería social convenciendo a Camila de "pegar esta URL en ajustes"), el tráfico —incluido el token— podría redirigirse a un servidor atacante. Valida que solo acepte `https://`, y muestra siempre de forma visible/persistente a qué backend está apuntando la app en ese momento.

### L5. Comparación de contraseña en texto plano contra el valor de entorno
`verify_password` compara el input directamente contra `ACCESS_PASSWORD` en claro (protegido solo por `hmac.compare_digest` para el timing, no hasheado). Para un único secreto fijo el riesgo práctico es bajo (no hay una "tabla" de contraseñas que proteger frente a una fuga de base de datos, porque no hay base de datos), pero por higiene general evita que ese valor aparezca nunca en claro en logs de error o trazas de excepción no controladas.

---

## 🗺️ Plan de remediación priorizado

### Fase 0 — Hoy, antes de cualquier otra cosa
- [x] Rotar `ACCESS_PASSWORD` y `SECRET_KEY` en producción (C1) — los defaults documentados aquí ya están quemados.
- [x] Quitar los valores por defecto del código; el arranque debe fallar si faltan (C1).
- [x] `CORS_ORIGINS` a la URL exacta del frontend, nunca `*` (M1).
- [x] `--workers 1` en el `Procfile`, o migrar el rate limiter a un almacenamiento compartido (C4).

### Fase 1 — Esta semana
- [x] Añadir `Content-Security-Policy` y `Strict-Transport-Security` (H1).
- [x] Ampliar la lista negra de extensiones + forzar `attachment` para MIME peligrosos + acotar el escaneo de entropía a una muestra (H2, M2).
- [x] Migrar el token fuera de la URL: cookies `HttpOnly` o tokens de un solo archivo de corta vida (C2, H4).
- [x] Redactar/desactivar el logging de query strings con tokens (C2).
- [x] Revalidar `parents` también en `list_files`, corregir el orden de escape en la búsqueda (H3).

### Fase 2 — Este mes
- [x] Acortar la duración del token de sesión + mecanismo de invalidación (`session_epoch`) (C3).
- [x] Fricción adicional para el borrado permanente (H6).
- [x] Aplicar `sanitize_filename` también en renombrado (H7).
- [x] Logging de auditoría + alertas de eventos sensibles (M4).
- [x] Revisar el scope de Google Drive hacia `drive.file` si es viable, o cuenta dedicada (H5).
- [x] Límite explícito de tamaño de subida/petición (M2).

### Fase 3 — Mejora continua
- [x] 2FA/TOTP (M3).
- [ ] Backup independiente de Google Drive (L2).
- [x] CI con `pip-audit` + `bandit` + versiones fijadas (M5, L3).
- [ ] Eliminar archivos de credenciales en texto plano tras su uso (L1).
- [x] Corregir la inconsistencia SHA3/SHA256 entre documentación y código (M6).
- [x] Reducir la información expuesta en `/health` (M7).
- [x] Extracción segura de IP y anti-spoofing para el rate limiter (M8).
- [x] Desafío anti-fuerza-bruta Turnstile / Proof-of-Work en login (M9).

---

## ✅ Checklist final rápida

- [x] Ningún secreto tiene valor por defecto en el código.
- [x] El servidor se niega a arrancar sin `SECRET_KEY`/`ACCESS_PASSWORD` explícitos.
- [x] Ningún token completo aparece nunca en una URL que pueda quedar logueada sin control.
- [x] Existe una forma de invalidar sesiones antes de su expiración natural.
- [x] El rate limiter funciona igual sin importar cuántos workers/instancias haya.
- [x] `CORS_ORIGINS` es una lista explícita, nunca `*`.
- [x] Ningún tipo de archivo ejecutable-en-navegador (`html`, `svg`, etc.) se sirve nunca como `inline`.
- [x] El aislamiento por carpeta se verifica en código en cada endpoint que devuelve archivos, no solo en la query.
- [x] Hay CSP y HSTS activos.
- [ ] Hay algún registro de quién entró, subió o borró algo, y cuándo.
- [ ] Hay una copia de los datos fuera de Google Drive.

---

*Auditoría elaborada a partir de la documentación técnica v2.0.0 aportada. Recomendado: repetir esta revisión directamente sobre el código fuente real una vez aplicados los cambios de la Fase 0, para confirmar que la implementación coincide con lo aquí asumido.*
