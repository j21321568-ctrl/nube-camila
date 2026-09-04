# 💖 Nube Privada de Camila ✨
*(Suite Privada de Almacenamiento en la Nube con Google Drive API v3 + FastAPI + Interfaz Ultra-Premium)*

Una plataforma personal de almacenamiento en la nube, privada, cifrada y diseñada a medida para **Camila**, con estética *Obsidian & Rose-Lavender Glassmorphism*, reproductor multimedia integrado, subida por portapapeles y arquitectura lista para producción en **Render** (Backend) y **Vercel / GitHub Pages** (Frontend).

---

## 🌟 Características de Vanguardia

- 🔐 **Bóveda con Seguridad Real**: Autenticación con tokens criptográficos (`HMAC-SHA256`) verificados en cada petición al backend (no solo ocultar elementos en JavaScript).
- 🌸 **Diseño Personalizado para Camila**: Saludo dinámico según la hora del día (*"Buenos días, Camila ☀️"*, *"Buenas tardes, Camila 🌸"*, *"Buenas noches, Camila ✨"*), diseño en modo oscuro de lujo y micro-interacciones suaves.
- ⚡ **Subida por Portapapeles (`Ctrl + V`)**: Camila puede capturar la pantalla y presionar `Ctrl + V` para subir la imagen a su nube al instante sin guardarla en disco.
- 📂 **Drag & Drop Inteligente**: Arrastra archivos desde el explorador y observa la barra de progreso en tiempo real con porcentaje.
- 💖 **Favoritos Nativos**: Guarda fotos, canciones o recuerdos favoritos; se sincronizan directamente con el atributo `starred` de Google Drive.
- 🎬 **Visor Multimedia Integrado (In-App Studio)**:
  - 📸 *Lightbox* para imágenes con zoom y carrusel.
  - 🎵 Reproductor de audio integrado (canciones, notas de voz).
  - 🎥 Reproductor de video nativo (`.mp4`, `.mov`, `.webm`).
  - 📄 Visor directo de documentos PDF y archivos de código/texto.
- ☕ **Detector de "Cold-Start" de Render**: Si el servidor gratuito de Render está en reposo, la aplicación le muestra un aviso cariñoso con animación mientras despierta (sin dar errores raros).
- ☁️ **Desacoplado para Producción**: El backend soporta credenciales de Google Drive mediante **Variables de Entorno** (`GOOGLE_CREDENTIALS_JSON`), garantizando que tus claves nunca se filtren en GitHub.

---

## 🚀 Inicio Rápido (En tu Computadora)

### Opción 1: Un solo clic
Haz doble clic en **`run.bat`**. Abrirá tu navegador en `http://127.0.0.1:8000` con el servidor activo.

### Opción 2: Desde la terminal
```bash
python main.py
```
O con Uvicorn:
```bash
uvicorn backend.main:app --reload --port 8000
```

> **Contraseña de acceso predeterminada**: `camila2026` (puedes cambiarla en el archivo `.env`).

---

## 🌐 Guía de Despliegue a Producción (Paso a Paso)

### 1. Despliegue del Backend en Render (Gratuito)

1. **Prepara las credenciales en una línea**:
   Ejecuta en tu terminal:
   ```bash
   python export_credentials.py
   ```
   Esto generará un archivo llamado `render_credentials_ready.txt` que contiene tu `credentials.json` en una sola línea compacta.

2. **Sube tu código a GitHub**:
   Crea un repositorio en GitHub y sube tu proyecto. El archivo `.gitignore` ya está configurado para **proteger y no subir** `credentials.json` ni `.env`.

3. **Crea el Servicio en Render**:
   - Inicia sesión en [render.com](https://render.com) y haz clic en **New +** > **Web Service**.
   - Conecta tu repositorio de GitHub.
   - Configura los campos:
     - **Name**: `camila-cloud-backend` (o el nombre que prefieras).
     - **Environment**: `Python 3`.
     - **Build Command**: `pip install -r requirements.txt`
     - **Start Command**: `uvicorn backend.main:app --host 0.0.0.0 --port $PORT`
   - En la sección **Environment Variables**, añade:
     - `ACCESS_PASSWORD`: Tu contraseña secreta (ej. `camila2026`).
     - `DRIVE_FOLDER_ID`: `1JNTRutM6sp-c9dstsSuITgpTMzEc4WSm` (el ID de tu carpeta).
     - `GOOGLE_CREDENTIALS_JSON`: Copia y pega la línea de la Opción 1 de `render_credentials_ready.txt`.
     - `SECRET_KEY`: Cualquier frase larga o contraseña aleatoria para firmar sesiones.
     - `CORS_ORIGINS`: `*`
   - Haz clic en **Create Web Service**.
   - Render te dará una URL pública como: `https://camila-cloud-backend.onrender.com`.

---

### 2. Despliegue del Frontend en Vercel o GitHub Pages

#### Opción A: Vercel (Recomendado)
1. Abre `frontend/config.js` y coloca la URL que te dio Render:
   ```javascript
   PRODUCTION_BACKEND_URL: "https://tu-backend.onrender.com",
   ```
2. Sube la carpeta `frontend/` a Vercel (puedes arrastrar la carpeta en vercel.com o conectarla con tu repositorio de GitHub indicando `frontend` como *Root Directory*).
3. ¡Listo! Vercel te dará una URL rápida y segura como `https://camila-cloud.vercel.app`.

#### Opción B: Cambiar la URL desde la misma interfaz
El frontend cuenta con un botón de **Ajustes de Servidor** en la pantalla de bienvenida y en la barra superior. Camila o tú pueden escribir la URL de Render allí, probar la conexión con el botón **"Probar Conexión"**, y se guardará automáticamente en el navegador.

---

## 🛠️ Estructura del Proyecto

```
c:\Cloud\
│
├── backend/
│   ├── config.py             # Detección de credenciales y variables de entorno
│   ├── auth.py               # Tokens criptográficos HMAC-SHA256 y seguridad
│   ├── drive_manager.py      # Operaciones completas de Google Drive v3
│   └── main.py               # API REST con FastAPI, CORS y streaming
│
├── frontend/
│   ├── index.html            # Interfaz SPA de alta fidelidad
│   ├── style.css             # Glassmorphism Obsidian & Rose-Lavender
│   ├── config.js             # Detección de URL (Local / Render)
│   ├── app.js                # Lógica reactiva, Drag & Drop, Ctrl+V, Modales
│   └── vercel.json           # Configuración de despliegue para Vercel
│
├── .env                      # Variables de entorno locales
├── .gitignore                # Protección de archivos sensibles
├── credentials.json          # Llave de la Cuenta de Servicio de Google
├── Folder-ID.txt             # ID de la carpeta en Google Drive
├── requirements.txt          # Dependencias Python
├── export_credentials.py     # Utilidad para preparar variables de Render
├── run.bat                   # Lanzador en un clic para Windows
└── Procfile / render.yaml    # Configuración de despliegue en la nube
```

---

## 🔒 Privacidad y Seguridad

- Las credenciales de Google Service Account permanecen aisladas en el servidor y nunca se exponen al navegador.
- Las imágenes y videos se transmiten mediante streaming seguro desde el backend, evitando compartir públicamente la carpeta de Google Drive.
- La protección contra ataques de temporización (`hmac.compare_digest`) y la expiración automática de tokens protegen el acceso ante accesos no autorizados.
