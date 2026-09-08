/**
 * Configuración Dinámica de la Nube Privada de Camila
 * Permite cambiar la URL del backend automáticamente según el entorno:
 * - En Local: Se conecta al servidor local (FastAPI en el mismo puerto o 8000)
 * - En Vercel / GitHub Pages: Se conecta al backend desplegado en Render / Railway
 */

const CONFIG = {
    // Nombre y versión de la aplicación
    APP_NAME: "Camila's Cloud",
    VERSION: "2.0.0",

    // URL por defecto para producción (cámbiala por la que te dé Render)
    // Ejemplo: "https://camila-nube-backend.onrender.com"
    PRODUCTION_BACKEND_URL: "https://nube-camila.onrender.com/",

    /**
     * Resuelve la URL base del Backend
     */
    getBaseUrl() {
        // 1. Si el usuario guardó una URL personalizada en el navegador
        const savedUrl = localStorage.getItem("camila_cloud_backend_url");
        if (savedUrl && savedUrl.trim()) {
            return savedUrl.trim().replace(/\/+$/, "");
        }

        const host = window.location.hostname;
        const port = window.location.port;

        // 2. Si se ejecuta en localhost o 127.0.0.1
        if (host === "localhost" || host === "127.0.0.1" || window.location.protocol === "file:") {
            // Si el frontend se sirve desde otro puerto (ej. Live Server en 5500), conectar a 8000
            if (port && port !== "8000") {
                return "http://127.0.0.1:8000";
            }
            // Si se sirve desde el mismo FastAPI (puerto 8000)
            return "";
        }

        // 3. Si está desplegado en Vercel, GitHub Pages u otro host público
        return this.PRODUCTION_BACKEND_URL.replace(/\/+$/, "");
    },

    /**
     * Construye una URL completa hacia un endpoint de la API
     */
    apiUrl(endpoint) {
        const base = this.getBaseUrl();
        const cleanEndpoint = endpoint.startsWith("/") ? endpoint : `/${endpoint}`;
        return `${base}${cleanEndpoint}`;
    },

    /**
     * Guarda una nueva URL de backend en localStorage
     */
    setBackendUrl(url) {
        if (!url) {
            localStorage.removeItem("camila_cloud_backend_url");
        } else {
            localStorage.setItem("camila_cloud_backend_url", url.trim().replace(/\/+$/, ""));
        }
    }
};

window.CONFIG = CONFIG;
