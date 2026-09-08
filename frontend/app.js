/**
 * Lógica Principal de la Nube Privada de Camila ✨
 * Maneja autenticación segura, operaciones de Google Drive,
 * drag-and-drop, pegado con Ctrl+V, visor multimedia y alertas de Render.
 */

(function () {
    // ----------------- Estado de la Aplicación -----------------
    const state = {
        // H4: Nunca almacenar el token en localStorage (protección contra robo vía XSS)
        token: null,
        isAuthenticated: false,
        files: [],
        filteredFiles: [],
        activeCategory: "all",
        searchQuery: "",
        sortBy: "newest",
        viewMode: localStorage.getItem("camila_cloud_view") || "grid",
        currentPreviewIndex: -1,
        activeFileForAction: null,
        coldStartTimer: null,
        twoFactorActive: false,
        pending2FaSecret: null
    };

    // ----------------- Referencias del DOM -----------------
    const dom = {
        // Pantallas
        lockScreen: document.getElementById("lockScreen"),
        appContainer: document.getElementById("appContainer"),
        coldStartBanner: document.getElementById("coldStartBanner"),

        // Login
        loginForm: document.getElementById("loginForm"),
        passwordInput: document.getElementById("passwordInput"),
        togglePasswordBtn: document.getElementById("togglePasswordBtn"),
        loginError: document.getElementById("loginError"),
        loginErrorText: document.getElementById("loginErrorText"),
        unlockBtn: document.getElementById("unlockBtn"),
        loginChallengeContainer: document.getElementById("loginChallengeContainer"),
        turnstileWidgetWrap: document.getElementById("turnstileWidgetWrap"),
        turnstileWidget: document.getElementById("turnstileWidget"),
        powStatusWrap: document.getElementById("powStatusWrap"),
        powStatusText: document.getElementById("powStatusText"),

        // Rescate 2FA
        show2FaRescueBtn: document.getElementById("show2FaRescueBtn"),
        login2FaForm: document.getElementById("login2FaForm"),
        totpRescueInput: document.getElementById("totpRescueInput"),
        login2FaError: document.getElementById("login2FaError"),
        login2FaErrorText: document.getElementById("login2FaErrorText"),
        unlock2FaBtn: document.getElementById("unlock2FaBtn"),
        backToPasswordBtn: document.getElementById("backToPasswordBtn"),

        // Navegación
        greetingText: document.getElementById("greetingText"),
        searchInput: document.getElementById("searchInput"),
        clearSearchBtn: document.getElementById("clearSearchBtn"),
        storageStatsBtn: document.getElementById("storageStatsBtn"),
        security2FaBtn: document.getElementById("security2FaBtn"),
        serverConfigBtn: document.getElementById("serverConfigBtn"),
        openServerSettingsBtn: document.getElementById("openServerSettingsBtn"),
        logoutBtn: document.getElementById("logoutBtn"),

        // Banner Dinámico 2FA
        setup2FaBanner: document.getElementById("setup2FaBanner"),
        open2FaSetupBtn: document.getElementById("open2FaSetupBtn"),
        dismiss2FaBannerBtn: document.getElementById("dismiss2FaBannerBtn"),

        // Filtros y Vista
        catPills: document.querySelectorAll(".cat-pill"),
        gridViewBtn: document.getElementById("gridViewBtn"),
        listViewBtn: document.getElementById("listViewBtn"),
        refreshBtn: document.getElementById("refreshBtn"),
        sortBySelect: document.getElementById("sortBySelect"),

        // Subida
        uploadTriggerBtn: document.getElementById("uploadTriggerBtn"),
        fileInput: document.getElementById("fileInput"),
        dropZone: document.getElementById("dropZone"),
        browseFilesBtn: document.getElementById("browseFilesBtn"),
        uploadProgressCard: document.getElementById("uploadProgressCard"),
        uploadProgressBar: document.getElementById("uploadProgressBar"),
        uploadProgressPercent: document.getElementById("uploadProgressPercent"),
        uploadingFileName: document.getElementById("uploadingFileName"),

        // Archivos
        filesCountDisplay: document.getElementById("filesCountDisplay"),
        filesGrid: document.getElementById("filesGrid"),
        filesListContainer: document.getElementById("filesListContainer"),
        filesTableBody: document.getElementById("filesTableBody"),
        emptyState: document.getElementById("emptyState"),
        emptyUploadBtn: document.getElementById("emptyUploadBtn"),

        // Modales
        previewModal: document.getElementById("previewModal"),
        previewIcon: document.getElementById("previewIcon"),
        previewTitle: document.getElementById("previewTitle"),
        previewContent: document.getElementById("previewContent"),
        previewMeta: document.getElementById("previewMeta"),
        previewDownloadBtn: document.getElementById("previewDownloadBtn"),
        closePreviewBtn: document.getElementById("closePreviewBtn"),

        renameModal: document.getElementById("renameModal"),
        renameForm: document.getElementById("renameForm"),
        renameInput: document.getElementById("renameInput"),
        cancelRenameBtn: document.getElementById("cancelRenameBtn"),
        closeRenameBtn: document.getElementById("closeRenameBtn"),

        deleteModal: document.getElementById("deleteModal"),
        deleteFileName: document.getElementById("deleteFileName"),
        confirmDeleteBtn: document.getElementById("confirmDeleteBtn"),
        cancelDeleteBtn: document.getElementById("cancelDeleteBtn"),
        closeDeleteBtn: document.getElementById("closeDeleteBtn"),

        statsModal: document.getElementById("statsModal"),
        statsTotalFiles: document.getElementById("statsTotalFiles"),
        statsTotalSize: document.getElementById("statsTotalSize"),
        statsTotalStarred: document.getElementById("statsTotalStarred"),
        statsBreakdownGrid: document.getElementById("statsBreakdownGrid"),
        revokeAllSessionsBtn: document.getElementById("revokeAllSessionsBtn"),
        closeStatsBtn: document.getElementById("closeStatsBtn"),

        serverModal: document.getElementById("serverModal"),
        serverConfigForm: document.getElementById("serverConfigForm"),
        serverUrlInput: document.getElementById("serverUrlInput"),
        testServerBtn: document.getElementById("testServerBtn"),
        testServerStatus: document.getElementById("testServerStatus"),
        resetServerUrlBtn: document.getElementById("resetServerUrlBtn"),
        closeServerBtn: document.getElementById("closeServerBtn"),

        // Modal 2FA
        twoFactorModal: document.getElementById("twoFactorModal"),
        close2FaModalBtn: document.getElementById("close2FaModalBtn"),
        twoFactorSetupView: document.getElementById("twoFactorSetupView"),
        twoFactorActiveView: document.getElementById("twoFactorActiveView"),
        twoFactorQrImg: document.getElementById("twoFactorQrImg"),
        twoFactorSecretText: document.getElementById("twoFactorSecretText"),
        copySecretBtn: document.getElementById("copySecretBtn"),
        confirm2FaForm: document.getElementById("confirm2FaForm"),
        confirm2FaInput: document.getElementById("confirm2FaInput"),
        confirm2FaError: document.getElementById("confirm2FaError"),
        confirm2FaErrorText: document.getElementById("confirm2FaErrorText"),
        save2FaBtn: document.getElementById("save2FaBtn"),
        disable2FaBtn: document.getElementById("disable2FaBtn"),

        toastContainer: document.getElementById("toastContainer")
    };

    // ----------------- Notificaciones Flotantes (Toasts) -----------------
    function showToast(message, type = "info") {
        const toast = document.createElement("div");
        toast.className = `toast ${type}`;

        let icon = "fa-info-circle";
        if (type === "success") icon = "fa-circle-check";
        if (type === "error") icon = "fa-circle-xmark";

        toast.innerHTML = `
            <i class="fa-solid ${icon}"></i>
            <span>${message}</span>
        `;

        dom.toastContainer.appendChild(toast);

        setTimeout(() => {
            toast.style.opacity = "0";
            toast.style.transform = "translateX(40px)";
            setTimeout(() => toast.remove(), 300);
        }, 4000);
    }

    // ----------------- Saludo Personalizado Dinámico -----------------
    function updateGreeting() {
        const hour = new Date().getHours();
        let greeting = "Hola, Camila ✨";

        if (hour >= 5 && hour < 12) {
            greeting = "Buenos días, Camila ☀️";
        } else if (hour >= 12 && hour < 20) {
            greeting = "Buenas tardes, Camila 🌸";
        } else {
            greeting = "Buenas noches, Camila ✨";
        }

        if (dom.greetingText) {
            dom.greetingText.textContent = greeting;
        }
    }

    // ----------------- Peticiones API con Detección de Render -----------------
    function startColdStartWatch() {
        clearTimeout(state.coldStartTimer);
        state.coldStartTimer = setTimeout(() => {
            if (dom.coldStartBanner) {
                dom.coldStartBanner.classList.remove("hidden");
            }
        }, 2500); // Si tarda más de 2.5s, Render probablemente está despertando
    }

    function stopColdStartWatch() {
        clearTimeout(state.coldStartTimer);
        if (dom.coldStartBanner) {
            dom.coldStartBanner.classList.add("hidden");
        }
    }

    async function apiFetch(endpoint, options = {}) {
        startColdStartWatch();

        const url = CONFIG.apiUrl(endpoint);
        const headers = options.headers || {};

        if (state.token) {
            headers["Authorization"] = `Bearer ${state.token}`;
            headers["X-Auth-Token"] = state.token;
        }

        try {
            const response = await fetch(url, { ...options, headers, credentials: "include" });
            stopColdStartWatch();

            if (response.status === 401) {
                // Token vencido o contraseña errónea
                if (state.isAuthenticated) {
                    logout("Tu sesión ha expirado. Por favor ingresa nuevamente.");
                }
                const errData = await response.json().catch(() => ({}));
                throw new Error(errData.detail || "No autorizado");
            }

            if (!response.ok) {
                const errData = await response.json().catch(() => ({}));
                throw new Error(errData.detail || `Error en el servidor (${response.status})`);
            }

            return await response.json();
        } catch (err) {
            stopColdStartWatch();
            throw err;
        }
    }

    // ----------------- Generador de Stream URL Seguro (Tokens Efímeros) -----------------
    async function getFileStreamUrl(fileId) {
        try {
            const data = await apiFetch(`/api/files/${fileId}/preview-token`, { method: "POST" });
            if (data && data.previewUrl) {
                return CONFIG.apiUrl(data.previewUrl);
            }
        } catch (err) {
            console.warn("Fallo al solicitar token efímero, recurriendo a cookie segura:", err);
        }
        return CONFIG.apiUrl(`/api/files/${fileId}/preview`);
    }

    // ----------------- Autenticación y Sesión (H4: HttpOnly Cookies) -----------------
    async function checkExistingSession() {
        // H4: Validación de sesión persistente delegada a la cookie HttpOnly 'camila_session'
        try {
            const data = await apiFetch("/api/auth/verify");
            if (data && data.valid) {
                state.isAuthenticated = true;
                state.twoFactorActive = !!data.twoFactorEnabled;
                showApp();
                loadFiles();
                check2FaStatus();
                return;
            }
        } catch (err) {
            // Sin sesión activa o cookie inválida
        }

        state.token = null;
        state.isAuthenticated = false;
        showLockScreen();
    }

    // ----------------- Motor de Desafío Anti-Bot y PoW (M9) -----------------
    let turnstileToken = null;

    async function solveProofOfWork(challenge, difficulty = 4) {
        const enc = new TextEncoder();
        let nonce = 0;
        const fullZeroBytes = Math.floor(difficulty / 2);
        const needNibble = (difficulty % 2 !== 0);

        while (true) {
            for (let i = 0; i < 400; i++) {
                const msg = enc.encode(`${challenge}:${nonce}`);
                const hashBuf = await crypto.subtle.digest("SHA-256", msg);
                const hashArr = new Uint8Array(hashBuf);

                let match = true;
                for (let b = 0; b < fullZeroBytes; b++) {
                    if (hashArr[b] !== 0) { match = false; break; }
                }
                if (match && needNibble) {
                    if ((hashArr[fullZeroBytes] >> 4) !== 0) match = false;
                }
                if (match) {
                    return String(nonce);
                }
                nonce++;
            }
            // Ceder microtarea para mantener fluidez en el navegador
            await new Promise(r => setTimeout(r, 0));
        }
    }

    async function handleLogin(e) {
        e.preventDefault();
        const password = dom.passwordInput.value;
        if (!password) return;

        dom.unlockBtn.disabled = true;
        dom.unlockBtn.innerHTML = `<span>Verificando...</span><div class="spinner-small"></div>`;
        dom.loginError.classList.add("hidden");

        const payload = { password };

        try {
            // 1. Comprobar si el backend exige resolver un desafío de seguridad (M9)
            let challengeInfo = null;
            try {
                const chRes = await fetch(CONFIG.apiUrl("/api/auth/challenge"), { credentials: "include" });
                if (chRes.ok) challengeInfo = await chRes.json();
            } catch (_) {}

            if (challengeInfo && challengeInfo.challenge_required) {
                dom.loginChallengeContainer.classList.remove("hidden");

                if (challengeInfo.turnstile_enabled && challengeInfo.turnstile_site_key) {
                    // Modo Cloudflare Turnstile
                    dom.turnstileWidgetWrap.classList.remove("hidden");
                    dom.powStatusWrap.classList.add("hidden");
                    if (!turnstileToken) {
                        throw new Error("Por favor completa la verificación de seguridad de Cloudflare.");
                    }
                    payload.turnstile_token = turnstileToken;
                } else if (challengeInfo.pow_challenge) {
                    // Modo Proof-of-Work criptográfico autónomo
                    dom.powStatusWrap.classList.remove("hidden");
                    dom.powStatusText.textContent = "Verificando entorno criptográfico seguro...";
                    const solvedNonce = await solveProofOfWork(
                        challengeInfo.pow_challenge,
                        challengeInfo.pow_difficulty || 4
                    );
                    payload.pow_challenge = challengeInfo.pow_challenge;
                    payload.pow_nonce = solvedNonce;
                }
            }

            const data = await apiFetch("/api/auth/login", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload)
            });

            // H4: El backend inyecta la cookie HttpOnly. El token se conserva solo en memoria durante la sesión activa.
            state.token = data.token || null;
            state.isAuthenticated = true;
            try { localStorage.removeItem("camila_cloud_token"); } catch (_) {}

            dom.loginChallengeContainer.classList.add("hidden");
            turnstileToken = null;

            showToast(`¡Bienvenida a tu nube, ${data.userName || "Camila"}! ✨`, "success");
            dom.passwordInput.value = "";
            showApp();
            loadFiles();
            check2FaStatus();
        } catch (err) {
            dom.loginErrorText.textContent = err.message || "Contraseña incorrecta";
            dom.loginError.classList.remove("hidden");
            dom.passwordInput.focus();
        } finally {
            dom.unlockBtn.disabled = false;
            dom.unlockBtn.innerHTML = `<span>Desbloquear Mi Nube</span><i class="fa-solid fa-arrow-right"></i>`;
        }
    }

    async function handle2FaLogin(e) {
        e.preventDefault();
        const code = (dom.totpRescueInput.value || "").trim();
        if (!code) return;

        dom.unlock2FaBtn.disabled = true;
        dom.unlock2FaBtn.innerHTML = `<span>Verificando 2FA...</span><div class="spinner-small"></div>`;
        dom.login2FaError.classList.add("hidden");

        try {
            const data = await apiFetch("/api/auth/login-2fa", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ totp_code: code })
            });

            state.token = data.token || null;
            state.isAuthenticated = true;
            try { localStorage.removeItem("camila_cloud_token"); } catch (_) {}

            showToast(`¡Acceso de respaldo concedido! Bienvenida ✨`, "success");
            dom.totpRescueInput.value = "";
            dom.login2FaForm.classList.add("hidden");
            dom.loginForm.classList.remove("hidden");
            showApp();
            loadFiles();
            check2FaStatus();
        } catch (err) {
            dom.login2FaErrorText.textContent = err.message || "Código 2FA incorrecto o expirado";
            dom.login2FaError.classList.remove("hidden");
            dom.totpRescueInput.focus();
        } finally {
            dom.unlock2FaBtn.disabled = false;
            dom.unlock2FaBtn.innerHTML = `<span>Verificar y Desbloquear</span><i class="fa-solid fa-arrow-right"></i>`;
        }
    }

    // ----------------- Gestión de 2FA en el Dashboard -----------------
    async function check2FaStatus() {
        if (!state.isAuthenticated) return;
        try {
            const data = await apiFetch("/api/auth/2fa/status");
            state.twoFactorActive = !!data.enabled;
            if (dom.setup2FaBanner) {
                const dismissed = sessionStorage.getItem("camila_2fa_banner_dismissed");
                if (!state.twoFactorActive && dismissed !== "true") {
                    dom.setup2FaBanner.classList.remove("hidden");
                } else {
                    dom.setup2FaBanner.classList.add("hidden");
                }
            }
        } catch (e) {
            console.warn("No se pudo verificar el estado de 2FA:", e);
        }
    }

    async function open2FaModal() {
        if (!state.isAuthenticated) return;
        dom.twoFactorModal.classList.remove("hidden");
        dom.confirm2FaError.classList.add("hidden");
        dom.confirm2FaInput.value = "";

        try {
            const statusData = await apiFetch("/api/auth/2fa/status");
            state.twoFactorActive = !!statusData.enabled;

            if (state.twoFactorActive) {
                dom.twoFactorSetupView.classList.add("hidden");
                dom.twoFactorActiveView.classList.remove("hidden");
            } else {
                dom.twoFactorActiveView.classList.add("hidden");
                dom.twoFactorSetupView.classList.remove("hidden");
                dom.twoFactorSecretText.textContent = "Generando clave segura...";
                dom.twoFactorQrImg.src = "";

                const setupData = await apiFetch("/api/auth/2fa/setup", { method: "POST" });
                state.pending2FaSecret = setupData.secret;
                dom.twoFactorSecretText.textContent = setupData.secret;
                dom.twoFactorQrImg.src = setupData.qr_code_svg;
            }
        } catch (err) {
            showToast(`Error al cargar 2FA: ${err.message}`, "error");
            dom.twoFactorModal.classList.add("hidden");
        }
    }

    function close2FaModal() {
        dom.twoFactorModal.classList.add("hidden");
        dom.confirm2FaError.classList.add("hidden");
        dom.confirm2FaInput.value = "";
    }

    async function handleConfirm2Fa(e) {
        e.preventDefault();
        const code = (dom.confirm2FaInput.value || "").trim();
        if (!code || !state.pending2FaSecret) return;

        dom.save2FaBtn.disabled = true;
        dom.save2FaBtn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Activando...`;
        dom.confirm2FaError.classList.add("hidden");

        try {
            const res = await apiFetch("/api/auth/2fa/confirm", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ secret: state.pending2FaSecret, code })
            });

            state.twoFactorActive = true;
            if (dom.setup2FaBanner) dom.setup2FaBanner.classList.add("hidden");
            showToast(res.message || "¡2FA activado con éxito! ✨", "success");
            dom.twoFactorSetupView.classList.add("hidden");
            dom.twoFactorActiveView.classList.remove("hidden");
        } catch (err) {
            dom.confirm2FaErrorText.textContent = err.message || "Código incorrecto o expirado";
            dom.confirm2FaError.classList.remove("hidden");
            dom.confirm2FaInput.focus();
        } finally {
            dom.save2FaBtn.disabled = false;
            dom.save2FaBtn.innerHTML = `<i class="fa-solid fa-check"></i> Confirmar y Activar 2FA`;
        }
    }

    async function handleDisable2Fa() {
        const pwd = prompt("Por seguridad, ingresa tu contraseña maestra para desactivar el 2FA:");
        if (!pwd) return;

        try {
            await apiFetch("/api/auth/2fa/disable", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ password: pwd })
            });
            state.twoFactorActive = false;
            showToast("Segundo factor de autenticación desactivado", "info");
            open2FaModal(); // Recargar a vista de configuración
            if (dom.setup2FaBanner) dom.setup2FaBanner.classList.remove("hidden");
        } catch (err) {
            showToast(err.message || "Contraseña incorrecta", "error");
        }
    }

    async function logout(message = "Sesión cerrada correctamente") {
        try {
            await fetch(CONFIG.apiUrl("/api/auth/logout"), { method: "POST", credentials: "include" }).catch(() => {});
        } catch (e) {}
        state.token = null;
        state.isAuthenticated = false;
        try { localStorage.removeItem("camila_cloud_token"); } catch (_) {}
        showLockScreen();
        showToast(message, "info");
    }

    function showLockScreen() {
        dom.appContainer.classList.add("hidden");
        dom.lockScreen.classList.remove("hidden");
        dom.passwordInput.focus();
    }

    function showApp() {
        dom.lockScreen.classList.add("hidden");
        dom.appContainer.classList.remove("hidden");
        updateGreeting();
        setViewMode(state.viewMode);
    }

    // ----------------- Gestión de Archivos -----------------
    async function loadFiles() {
        dom.filesCountDisplay.textContent = "Cargando archivos de Google Drive...";

        try {
            const data = await apiFetch("/api/files?category=all");
            state.files = data.files || [];
            applyFiltersAndRender();
        } catch (err) {
            showToast(`No se pudieron cargar los archivos: ${err.message}`, "error");
            dom.filesCountDisplay.textContent = "Error al conectar con la nube.";
        }
    }

    function applyFiltersAndRender() {
        let list = [...state.files];

        // 1. Filtrar por categoría
        if (state.activeCategory === "starred") {
            list = list.filter(f => f.starred);
        } else if (state.activeCategory !== "all") {
            list = list.filter(f => f.category === state.activeCategory);
        }

        // 2. Filtrar por término de búsqueda
        if (state.searchQuery.trim()) {
            const q = state.searchQuery.toLowerCase().trim();
            list = list.filter(f => f.name.toLowerCase().includes(q));
        }

        // 3. Ordenar
        switch (state.sortBy) {
            case "newest":
                list.sort((a, b) => new Date(b.modifiedTime || 0) - new Date(a.modifiedTime || 0));
                break;
            case "oldest":
                list.sort((a, b) => new Date(a.modifiedTime || 0) - new Date(b.modifiedTime || 0));
                break;
            case "name_asc":
                list.sort((a, b) => a.name.localeCompare(b.name));
                break;
            case "name_desc":
                list.sort((a, b) => b.name.localeCompare(a.name));
                break;
            case "size_desc":
                list.sort((a, b) => (parseInt(b.size) || 0) - (parseInt(a.size) || 0));
                break;
            case "size_asc":
                list.sort((a, b) => (parseInt(a.size) || 0) - (parseInt(b.size) || 0));
                break;
        }

        state.filteredFiles = list;
        renderFiles();
    }

    function getFileCategoryIcon(category, mimeType) {
        switch (category) {
            case "image":
                return { icon: "fa-image", color: "#f472b6", bg: "rgba(244, 114, 182, 0.15)" };
            case "video":
                return { icon: "fa-film", color: "#818cf8", bg: "rgba(129, 140, 248, 0.15)" };
            case "audio":
                return { icon: "fa-music", color: "#34d399", bg: "rgba(52, 211, 153, 0.15)" };
            case "pdf":
                return { icon: "fa-file-pdf", color: "#fb7185", bg: "rgba(251, 113, 133, 0.15)" };
            case "document":
                return { icon: "fa-file-word", color: "#38bdf8", bg: "rgba(56, 189, 248, 0.15)" };
            case "archive":
                return { icon: "fa-box-archive", color: "#fbbf24", bg: "rgba(251, 191, 36, 0.15)" };
            case "code":
                return { icon: "fa-code", color: "#a78bfa", bg: "rgba(167, 139, 250, 0.15)" };
            default:
                return { icon: "fa-file", color: "#94a3b8", bg: "rgba(148, 163, 184, 0.15)" };
        }
    }

    function renderFiles() {
        const count = state.filteredFiles.length;
        const total = state.files.length;

        dom.filesCountDisplay.textContent = `${count} ${count === 1 ? 'archivo encontrado' : 'archivos encontrados'} (${total} en total)`;

        if (count === 0) {
            dom.filesGrid.classList.add("hidden");
            dom.filesListContainer.classList.add("hidden");
            dom.emptyState.classList.remove("hidden");
            return;
        }

        dom.emptyState.classList.add("hidden");

        if (state.viewMode === "grid") {
            dom.filesGrid.classList.remove("hidden");
            dom.filesListContainer.classList.add("hidden");
            renderGridView();
        } else {
            dom.filesGrid.classList.add("hidden");
            dom.filesListContainer.classList.remove("hidden");
            renderListView();
        }
    }

    function renderGridView() {
        dom.filesGrid.innerHTML = "";

        state.filteredFiles.forEach((file, index) => {
            const card = document.createElement("div");
            card.className = "file-card";

            const { icon, color, bg } = getFileCategoryIcon(file.category, file.mimeType);

            // URL limpia de previsualización sin exponer token en parámetros (usa cookie HttpOnly)
            const previewUrl = CONFIG.apiUrl(`/api/files/${file.id}/preview`);

            // Estructura de plantilla base sin interpolar file.name en innerHTML (Regla H7)
            card.innerHTML = `
                <div class="card-preview" data-index="${index}">
                    ${file.category === "image"
                        ? `<img class="card-thumbnail-img" src="${previewUrl}" alt="" loading="lazy">`
                        : `<div class="card-icon-wrap" style="background: ${bg}; color: ${color};"><i class="fa-solid ${icon}"></i></div>`
                    }
                    <button class="card-star-btn ${file.starred ? 'starred' : ''}" data-id="${file.id}" title="${file.starred ? 'Quitar de favoritos' : 'Agregar a favoritos'}">
                        <i class="fa-${file.starred ? 'solid' : 'regular'} fa-heart"></i>
                    </button>
                </div>
                <div class="card-info">
                    <span class="card-filename"></span>
                    <div class="card-meta">
                        <span class="card-meta-size"></span>
                        <span class="card-meta-date"></span>
                    </div>
                </div>
                <div class="card-actions">
                    <button class="action-btn preview-btn" data-index="${index}" title="Previsualizar">
                        <i class="fa-solid fa-eye"></i>
                    </button>
                    <button class="action-btn download-btn" data-id="${file.id}" title="Descargar">
                        <i class="fa-solid fa-download"></i>
                    </button>
                    <button class="action-btn rename-btn" data-id="${file.id}" title="Renombrar">
                        <i class="fa-solid fa-pen-to-square"></i>
                    </button>
                    <button class="action-btn delete-btn" data-id="${file.id}" title="Eliminar">
                        <i class="fa-solid fa-trash-can"></i>
                    </button>
                </div>
            `;

            // INSERCIÓN ESTRICTA CON textContent Y PROPIEDADES DOM SEGURAS (Regla H7)
            const filenameEl = card.querySelector(".card-filename");
            if (filenameEl) {
                filenameEl.textContent = file.name;
                filenameEl.title = file.name;
            }

            const sizeEl = card.querySelector(".card-meta-size");
            if (sizeEl) sizeEl.textContent = file.formattedSize || "";

            const dateEl = card.querySelector(".card-meta-date");
            if (dateEl) dateEl.textContent = file.relativeDate || "";

            // Manejador seguro para fallos de miniatura (sin innerHTML dinámico con datos de usuario)
            const thumbImg = card.querySelector(".card-thumbnail-img");
            if (thumbImg) {
                thumbImg.alt = file.name;
                thumbImg.onerror = function () {
                    this.onerror = null;
                    const wrap = document.createElement("div");
                    wrap.className = "card-icon-wrap";
                    wrap.style.background = bg;
                    wrap.style.color = color;
                    const ic = document.createElement("i");
                    ic.className = `fa-solid ${icon}`;
                    wrap.appendChild(ic);
                    this.replaceWith(wrap);
                };
            }

            // Asignación de data-name mediante propiedad DOM segura
            card.querySelectorAll(".download-btn, .rename-btn, .delete-btn").forEach(btn => {
                btn.dataset.name = file.name;
            });

            dom.filesGrid.appendChild(card);
        });

        attachCardEventListeners();
    }

    function renderListView() {
        dom.filesTableBody.innerHTML = "";

        state.filteredFiles.forEach((file, index) => {
            const tr = document.createElement("tr");
            const { icon, color } = getFileCategoryIcon(file.category, file.mimeType);

            // Plantilla sin interpolar file.name dentro de innerHTML (Regla H7)
            tr.innerHTML = `
                <td style="text-align: center;">
                    <button class="card-star-btn ${file.starred ? 'starred' : ''}" data-id="${file.id}" style="position: static; width: 28px; height: 28px;" title="Favorito">
                        <i class="fa-${file.starred ? 'solid' : 'regular'} fa-heart"></i>
                    </button>
                </td>
                <td>
                    <div class="table-name-cell" data-index="${index}">
                        <i class="fa-solid ${icon} table-file-icon" style="color: ${color};"></i>
                        <span class="table-name-text"></span>
                    </div>
                </td>
                <td class="table-category-text"></td>
                <td class="table-size-text"></td>
                <td class="table-date-text"></td>
                <td>
                    <div class="table-actions-cell">
                        <button class="action-btn preview-btn" data-index="${index}" title="Previsualizar"><i class="fa-solid fa-eye"></i></button>
                        <button class="action-btn download-btn" data-id="${file.id}" title="Descargar"><i class="fa-solid fa-download"></i></button>
                        <button class="action-btn rename-btn" data-id="${file.id}" title="Renombrar"><i class="fa-solid fa-pen-to-square"></i></button>
                        <button class="action-btn delete-btn" data-id="${file.id}" title="Eliminar"><i class="fa-solid fa-trash-can"></i></button>
                    </div>
                </td>
            `;

            // INSERCIÓN ESTRICTA CON textContent (Regla H7)
            const nameSpan = tr.querySelector(".table-name-text");
            if (nameSpan) {
                nameSpan.textContent = file.name;
                nameSpan.title = file.name;
            }

            const catTd = tr.querySelector(".table-category-text");
            if (catTd) catTd.textContent = (file.category || "").toUpperCase();

            const sizeTd = tr.querySelector(".table-size-text");
            if (sizeTd) sizeTd.textContent = file.formattedSize || "";

            const dateTd = tr.querySelector(".table-date-text");
            if (dateTd) dateTd.textContent = file.relativeDate || "";

            tr.querySelectorAll(".download-btn, .rename-btn, .delete-btn").forEach(btn => {
                btn.dataset.name = file.name;
            });

            dom.filesTableBody.appendChild(tr);
        });

        attachCardEventListeners();
    }

    function attachCardEventListeners() {
        // Previsualización al hacer clic en miniatura o botón de ojo
        document.querySelectorAll(".card-preview, .preview-btn, .table-name-cell").forEach(el => {
            el.addEventListener("click", (e) => {
                if (e.target.closest(".card-star-btn")) return;
                const idx = parseInt(el.dataset.index);
                if (!isNaN(idx)) openPreview(idx);
            });
        });

        // Alternar Favorito
        document.querySelectorAll(".card-star-btn").forEach(btn => {
            btn.addEventListener("click", (e) => {
                e.stopPropagation();
                const fileId = btn.dataset.id;
                toggleStar(fileId, btn);
            });
        });

        // Descarga directa
        document.querySelectorAll(".download-btn").forEach(btn => {
            btn.addEventListener("click", (e) => {
                e.stopPropagation();
                const fileId = btn.dataset.id;
                downloadFile(fileId);
            });
        });

        // Renombrar
        document.querySelectorAll(".rename-btn").forEach(btn => {
            btn.addEventListener("click", (e) => {
                e.stopPropagation();
                openRenameModal(btn.dataset.id, btn.dataset.name);
            });
        });

        // Eliminar
        document.querySelectorAll(".delete-btn").forEach(btn => {
            btn.addEventListener("click", (e) => {
                e.stopPropagation();
                openDeleteModal(btn.dataset.id, btn.dataset.name);
            });
        });
    }

    // ----------------- Favorito (Starred) -----------------
    async function toggleStar(fileId, buttonEl) {
        const file = state.files.find(f => f.id === fileId);
        if (!file) return;

        const newStarred = !file.starred;
        // Actualización optimista de interfaz
        file.starred = newStarred;
        buttonEl.classList.toggle("starred", newStarred);
        buttonEl.innerHTML = `<i class="fa-${newStarred ? 'solid' : 'regular'} fa-heart"></i>`;

        try {
            await apiFetch(`/api/files/${fileId}/star`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ starred: newStarred })
            });
            showToast(newStarred ? "Añadido a favoritos ❤️" : "Quitado de favoritos", "info");
        } catch (err) {
            // Revertir en caso de error
            file.starred = !newStarred;
            buttonEl.classList.toggle("starred", !newStarred);
            showToast(`Error al actualizar favorito: ${err.message}`, "error");
        }
    }

    // ----------------- Descarga de Archivo Segura -----------------
    async function downloadFile(fileId) {
        showToast("Iniciando descarga segura...", "info");
        try {
            const data = await apiFetch(`/api/files/${fileId}/preview-token`, { method: "POST" });
            if (data && data.downloadUrl) {
                const a = document.createElement("a");
                a.href = CONFIG.apiUrl(data.downloadUrl);
                a.target = "_blank";
                document.body.appendChild(a);
                a.click();
                a.remove();
                return;
            }
        } catch (err) {
            console.warn("Fallo al solicitar token efímero de descarga, recurriendo a cookie segura:", err);
        }
        const url = CONFIG.apiUrl(`/api/files/${fileId}/download`);
        const a = document.createElement("a");
        a.href = url;
        a.target = "_blank";
        document.body.appendChild(a);
        a.click();
        a.remove();
    }

    // ----------------- Subida de Archivos con Progreso Real -----------------
    function uploadFiles(fileList) {
        if (!fileList || fileList.length === 0) return;

        const MAX_FILE_SIZE_BYTES = 100 * 1024 * 1024; // 100 MB límite (M2)
        const formData = new FormData();
        for (let i = 0; i < fileList.length; i++) {
            if (fileList[i].size > MAX_FILE_SIZE_BYTES) {
                showToast(`"${fileList[i].name}" supera el límite máximo permitido de 100 MB.`, "error");
                return;
            }
            formData.append("files", fileList[i]);
        }

        const uploadUrl = CONFIG.apiUrl("/api/upload");
        const xhr = new XMLHttpRequest();

        // Mostrar barra de progreso flotante
        dom.uploadProgressCard.classList.remove("hidden");
        dom.uploadProgressBar.style.width = "0%";
        dom.uploadProgressPercent.textContent = "0%";
        dom.uploadingFileName.textContent = `Subiendo ${fileList.length} ${fileList.length === 1 ? 'archivo' : 'archivos'} a Google Drive...`;

        xhr.upload.onprogress = function (e) {
            if (e.lengthComputable) {
                const percent = Math.round((e.loaded / e.total) * 100);
                dom.uploadProgressBar.style.width = `${percent}%`;
                dom.uploadProgressPercent.textContent = `${percent}%`;
            }
        };

        xhr.onload = function () {
            dom.uploadProgressCard.classList.add("hidden");
            if (xhr.status === 200) {
                try {
                    const res = JSON.parse(xhr.responseText);
                    if (res.errors && res.errors.length > 0) {
                        res.errors.forEach(err => showToast(`Error en ${err.filename}: ${err.error}`, "error"));
                    }
                    if (res.totalUploaded > 0) {
                        showToast(`¡Subida completada! (${res.totalUploaded} archivos)`, "success");
                    }
                    loadFiles();
                } catch {
                    showToast("Archivos subidos exitosamente ✨", "success");
                    loadFiles();
                }
            } else if (xhr.status === 413) {
                showToast("El tamaño de los archivos excede el límite permitido (100 MB)", "error");
            } else {
                showToast(`Error al subir archivos (${xhr.status})`, "error");
            }
        };

        xhr.onerror = function () {
            dom.uploadProgressCard.classList.add("hidden");
            showToast("Ocurrió un error de red al subir los archivos", "error");
        };

        xhr.open("POST", uploadUrl, true);
        if (state.token) {
            xhr.setRequestHeader("Authorization", `Bearer ${state.token}`);
            xhr.setRequestHeader("X-Auth-Token", state.token);
        }
        xhr.send(formData);
    }

    // ----------------- Subida desde Portapapeles (Ctrl + V) -----------------
    window.addEventListener("paste", (e) => {
        // No interceptar si el usuario está escribiendo en un input
        if (["INPUT", "TEXTAREA"].includes(document.activeElement.tagName)) return;
        if (!state.token) return;

        const items = (e.clipboardData || e.originalEvent.clipboardData).items;
        const filesToUpload = [];

        for (let i = 0; i < items.length; i++) {
            if (items[i].kind === "file") {
                const blob = items[i].getAsFile();
                if (blob) {
                    const timestamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-");
                    const ext = blob.type.split("/")[1] || "png";
                    const newFile = new File([blob], `Captura_Camila_${timestamp}.${ext}`, { type: blob.type });
                    filesToUpload.push(newFile);
                }
            }
        }

        if (filesToUpload.length > 0) {
            showToast(`Captura detectada en el portapapeles. Subiendo a tu nube...`, "info");
            uploadFiles(filesToUpload);
        }
    });

    // ----------------- Drag and Drop -----------------
    ["dragenter", "dragover"].forEach(eventName => {
        window.addEventListener(eventName, (e) => {
            e.preventDefault();
            e.stopPropagation();
            if (state.token) dom.dropZone.classList.add("drag-over");
        }, false);
    });

    ["dragleave", "drop"].forEach(eventName => {
        window.addEventListener(eventName, (e) => {
            e.preventDefault();
            e.stopPropagation();
            dom.dropZone.classList.remove("drag-over");
        }, false);
    });

    window.addEventListener("drop", (e) => {
        if (!state.token) return;
        const dt = e.dataTransfer;
        const files = dt.files;
        if (files && files.length > 0) {
            uploadFiles(files);
        }
    });

    // ----------------- Visor Multimedia (In-App Lightbox & Player Seguro) -----------------
    async function openPreview(index) {
        state.currentPreviewIndex = index;
        const file = state.filteredFiles[index];
        if (!file) return;

        const { icon, color } = getFileCategoryIcon(file.category, file.mimeType);
        dom.previewIcon.className = `fa-solid ${icon}`;
        dom.previewIcon.style.color = color;
        dom.previewTitle.textContent = file.name;
        dom.previewMeta.textContent = `${file.formattedSize} · Modificado: ${file.relativeDate}`;

        // Configurar botón de descarga dentro del visor
        dom.previewDownloadBtn.onclick = () => downloadFile(file.id);

        dom.previewContent.innerHTML = `
            <div style="text-align: center; padding: 40px;">
                <div class="spinner-small" style="margin: 0 auto 12px auto; width: 32px; height: 32px;"></div>
                <p style="color: var(--text-muted); font-size: 0.9rem;">Cargando visor seguro...</p>
            </div>
        `;
        dom.previewModal.classList.remove("hidden");

        // Obtener URL efímera acotada (120s) o utilizar cookie de sesión
        const previewStreamUrl = await getFileStreamUrl(file.id);
        dom.previewContent.innerHTML = "";

        if (file.category === "image") {
            const img = document.createElement("img");
            img.src = previewStreamUrl;
            img.alt = file.name;
            dom.previewContent.appendChild(img);
        } else if (file.category === "video") {
            const video = document.createElement("video");
            video.src = previewStreamUrl;
            video.controls = true;
            video.autoplay = true;
            dom.previewContent.appendChild(video);
        } else if (file.category === "audio") {
            const audioWrap = document.createElement("div");
            audioWrap.style.textAlign = "center";
            audioWrap.style.width = "100%";
            audioWrap.innerHTML = `
                <div style="font-size: 3rem; color: #34d399; margin-bottom: 20px;"><i class="fa-solid fa-music"></i></div>
                <audio controls autoplay style="width: 80%; max-width: 500px;" src="${previewStreamUrl}"></audio>
            `;
            dom.previewContent.appendChild(audioWrap);
        } else if (file.category === "pdf") {
            const iframe = document.createElement("iframe");
            iframe.src = previewStreamUrl;
            dom.previewContent.appendChild(iframe);
        } else if (file.category === "code" || file.mimeType.startsWith("text/")) {
            const pre = document.createElement("pre");
            pre.className = "preview-text-box";
            pre.textContent = "Cargando contenido...";
            dom.previewContent.appendChild(pre);

            fetch(previewStreamUrl, { credentials: "include" })
                .then(r => r.text())
                .then(txt => pre.textContent = txt)
                .catch(() => pre.textContent = "No se pudo cargar el archivo de texto.");
        } else {
            dom.previewContent.innerHTML = `
                <div style="text-align: center; padding: 40px;">
                    <div style="font-size: 3.5rem; color: var(--text-dim); margin-bottom: 16px;"><i class="fa-solid fa-file-arrow-down"></i></div>
                    <p style="color: var(--text-muted); margin-bottom: 20px;">Este tipo de archivo no admite previsualización directa.</p>
                    <button class="btn btn-primary" onclick="window.downloadFileFromModal('${file.id}')">Descargar para abrir</button>
                </div>
            `;
        }

        dom.previewModal.classList.remove("hidden");
    }

    window.downloadFileFromModal = function (id) {
        downloadFile(id);
    };

    function closePreview() {
        dom.previewModal.classList.add("hidden");
        dom.previewContent.innerHTML = "";
    }

    // ----------------- Modal Renombrar -----------------
    function openRenameModal(fileId, currentName) {
        state.activeFileForAction = fileId;
        dom.renameInput.value = currentName;
        dom.renameModal.classList.remove("hidden");
        dom.renameInput.focus();
        dom.renameInput.select();
    }

    function closeRenameModal() {
        dom.renameModal.classList.add("hidden");
        state.activeFileForAction = null;
    }

    async function handleRenameSubmit(e) {
        e.preventDefault();
        const fileId = state.activeFileForAction;
        const newName = dom.renameInput.value.trim();
        if (!fileId || !newName) return;

        try {
            await apiFetch(`/api/files/${fileId}/rename`, {
                method: "PATCH",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ name: newName })
            });

            showToast("Archivo renombrado exitosamente", "success");
            closeRenameModal();
            loadFiles();
        } catch (err) {
            showToast(`Error al renombrar: ${err.message}`, "error");
        }
    }

    // ----------------- Modal Eliminar -----------------
    function openDeleteModal(fileId, fileName) {
        state.activeFileForAction = fileId;
        dom.deleteFileName.textContent = fileName;
        dom.deleteModal.classList.remove("hidden");
    }

    function closeDeleteModal() {
        dom.deleteModal.classList.add("hidden");
        state.activeFileForAction = null;
    }

    async function handleConfirmDelete() {
        const fileId = state.activeFileForAction;
        if (!fileId) return;

        try {
            await apiFetch(`/api/files/${fileId}`, { method: "DELETE" });
            showToast("Archivo enviado a la papelera", "info");
            closeDeleteModal();
            loadFiles();
        } catch (err) {
            showToast(`Error al eliminar archivo: ${err.message}`, "error");
        }
    }

    // ----------------- Modal de Estadísticas -----------------
    async function openStatsModal() {
        dom.statsModal.classList.remove("hidden");
        dom.statsTotalFiles.textContent = "...";
        dom.statsTotalSize.textContent = "...";

        try {
            const data = await apiFetch("/api/stats");
            const stats = data.stats;

            dom.statsTotalFiles.textContent = stats.totalFiles;
            dom.statsTotalSize.textContent = stats.formattedTotalSize;
            dom.statsTotalStarred.textContent = stats.categories.starred || 0;

            const categoryLabels = {
                image: { name: "Fotos", icon: "fa-image", color: "#f472b6" },
                document: { name: "Documentos", icon: "fa-file-lines", color: "#38bdf8" },
                audio: { name: "Música / Audios", icon: "fa-music", color: "#34d399" },
                video: { name: "Videos", icon: "fa-video", color: "#818cf8" },
                pdf: { name: "PDFs", icon: "fa-file-pdf", color: "#fb7185" },
                archive: { name: "Archivos Comprimidos", icon: "fa-box-archive", color: "#fbbf24" },
                code: { name: "Código / Texto", icon: "fa-code", color: "#a78bfa" },
                other: { name: "Otros", icon: "fa-file", color: "#94a3b8" }
            };

            dom.statsBreakdownGrid.innerHTML = "";
            for (const [key, info] of Object.entries(categoryLabels)) {
                const count = stats.categories[key] || 0;
                const item = document.createElement("div");
                item.className = "breakdown-item";
                item.innerHTML = `
                    <div class="breakdown-item-name">
                        <i class="fa-solid ${info.icon}" style="color: ${info.color}"></i>
                        <span>${info.name}</span>
                    </div>
                    <span class="breakdown-item-count">${count}</span>
                `;
                dom.statsBreakdownGrid.appendChild(item);
            }
        } catch (err) {
            showToast(`Error al obtener estadísticas: ${err.message}`, "error");
        }
    }

    function closeStatsModal() {
        dom.statsModal.classList.add("hidden");
    }

    // ----------------- Modal de Ajustes de Servidor -----------------
    function openServerModal() {
        dom.serverUrlInput.value = localStorage.getItem("camila_cloud_backend_url") || "";
        dom.testServerStatus.textContent = "";
        dom.serverModal.classList.remove("hidden");
    }

    function closeServerModal() {
        dom.serverModal.classList.add("hidden");
    }

    async function handleTestServer() {
        const testUrl = dom.serverUrlInput.value.trim().replace(/\/+$/, "");
        const targetUrl = testUrl ? `${testUrl}/api/health` : CONFIG.apiUrl("/api/health");

        dom.testServerStatus.textContent = "Probando conexión...";
        dom.testServerStatus.style.color = "var(--text-muted)";

        const startTime = Date.now();
        try {
            const res = await fetch(targetUrl);
            const elapsed = Date.now() - startTime;
            if (res.ok) {
                dom.testServerStatus.textContent = `✅ En línea (${elapsed}ms)`;
                dom.testServerStatus.style.color = "var(--success-color)";
            } else {
                dom.testServerStatus.textContent = `❌ Respuesta con error ${res.status}`;
                dom.testServerStatus.style.color = "var(--danger-color)";
            }
        } catch {
            dom.testServerStatus.textContent = `❌ Servidor inaccesible (o despertando)`;
            dom.testServerStatus.style.color = "var(--danger-color)";
        }
    }

    function handleSaveServerUrl(e) {
        e.preventDefault();
        const url = dom.serverUrlInput.value.trim();
        CONFIG.setBackendUrl(url);
        showToast("Dirección de servidor actualizada", "success");
        closeServerModal();
        if (state.token) loadFiles();
    }

    function handleResetServerUrl() {
        CONFIG.setBackendUrl(null);
        dom.serverUrlInput.value = "";
        showToast("Se restauró la dirección predeterminada", "info");
    }

    // ----------------- Alternar Modo de Vista -----------------
    function setViewMode(mode) {
        state.viewMode = mode;
        localStorage.setItem("camila_cloud_view", mode);

        if (mode === "grid") {
            dom.gridViewBtn.classList.add("active");
            dom.listViewBtn.classList.remove("active");
        } else {
            dom.gridViewBtn.classList.remove("active");
            dom.listViewBtn.classList.add("active");
        }
        renderFiles();
    }

    // ----------------- Registro de Eventos -----------------
    function initEvents() {
        // Formulario de login
        dom.loginForm.addEventListener("submit", handleLogin);

        // Mostrar / Ocultar contraseña
        dom.togglePasswordBtn.addEventListener("click", () => {
            const isPassword = dom.passwordInput.type === "password";
            dom.passwordInput.type = isPassword ? "text" : "password";
            dom.togglePasswordBtn.innerHTML = `<i class="fa-solid fa-eye${isPassword ? '-slash' : ''}"></i>`;
        });

        // Logout
        dom.logoutBtn.addEventListener("click", () => logout());

        // Búsqueda en vivo
        dom.searchInput.addEventListener("input", (e) => {
            state.searchQuery = e.target.value;
            dom.clearSearchBtn.classList.toggle("hidden", !state.searchQuery);
            applyFiltersAndRender();
        });

        dom.clearSearchBtn.addEventListener("click", () => {
            dom.searchInput.value = "";
            state.searchQuery = "";
            dom.clearSearchBtn.classList.add("hidden");
            applyFiltersAndRender();
        });

        // Categorías
        dom.catPills.forEach(pill => {
            pill.addEventListener("click", () => {
                dom.catPills.forEach(p => p.classList.remove("active"));
                pill.classList.add("active");
                state.activeCategory = pill.dataset.category;
                applyFiltersAndRender();
            });
        });

        // Selector de orden
        dom.sortBySelect.addEventListener("change", (e) => {
            state.sortBy = e.target.value;
            applyFiltersAndRender();
        });

        // Alternadores de vista
        dom.gridViewBtn.addEventListener("click", () => setViewMode("grid"));
        dom.listViewBtn.addEventListener("click", () => setViewMode("list"));

        // Refrescar
        dom.refreshBtn.addEventListener("click", () => {
            dom.refreshBtn.innerHTML = `<i class="fa-solid fa-rotate-right fa-spin"></i>`;
            loadFiles().finally(() => {
                dom.refreshBtn.innerHTML = `<i class="fa-solid fa-rotate-right"></i>`;
            });
        });

        // Disparador de subida
        dom.uploadTriggerBtn.addEventListener("click", () => dom.fileInput.click());
        dom.browseFilesBtn.addEventListener("click", () => dom.fileInput.click());
        dom.emptyUploadBtn.addEventListener("click", () => dom.fileInput.click());

        dom.fileInput.addEventListener("change", (e) => {
            if (e.target.files && e.target.files.length > 0) {
                uploadFiles(e.target.files);
                dom.fileInput.value = ""; // Reset
            }
        });

        // Modales
        dom.closePreviewBtn.addEventListener("click", closePreview);
        dom.renameForm.addEventListener("submit", handleRenameSubmit);
        dom.cancelRenameBtn.addEventListener("click", closeRenameModal);
        dom.closeRenameBtn.addEventListener("click", closeRenameModal);

        dom.confirmDeleteBtn.addEventListener("click", handleConfirmDelete);
        dom.cancelDeleteBtn.addEventListener("click", closeDeleteModal);
        dom.closeDeleteBtn.addEventListener("click", closeDeleteModal);

        dom.storageStatsBtn.addEventListener("click", openStatsModal);
        dom.closeStatsBtn.addEventListener("click", closeStatsModal);

        if (dom.revokeAllSessionsBtn) {
            dom.revokeAllSessionsBtn.addEventListener("click", async () => {
                if (confirm("¿Estás segura de que deseas cerrar sesión en TODOS los dispositivos? Tendrás que ingresar tu contraseña nuevamente.")) {
                    try {
                        await apiFetch("/api/auth/revoke-all", { method: "POST" });
                        showToast("Se han invalidado todas las sesiones.", "success");
                    } catch (err) {
                        console.error("Error al revocar sesiones:", err);
                    }
                    logout("Has cerrado sesión en todos los dispositivos.");
                }
            });
        }

        dom.serverConfigBtn.addEventListener("click", openServerModal);
        dom.openServerSettingsBtn.addEventListener("click", openServerModal);
        dom.closeServerBtn.addEventListener("click", closeServerModal);
        dom.testServerBtn.addEventListener("click", handleTestServer);
        dom.serverConfigForm.addEventListener("submit", handleSaveServerUrl);
        dom.resetServerUrlBtn.addEventListener("click", handleResetServerUrl);

        // Eventos de 2FA y Acceso de Rescate
        if (dom.show2FaRescueBtn) {
            dom.show2FaRescueBtn.addEventListener("click", () => {
                dom.loginForm.classList.add("hidden");
                dom.login2FaForm.classList.remove("hidden");
                dom.login2FaError.classList.add("hidden");
                dom.totpRescueInput.focus();
            });
        }

        if (dom.backToPasswordBtn) {
            dom.backToPasswordBtn.addEventListener("click", () => {
                dom.login2FaForm.classList.add("hidden");
                dom.loginForm.classList.remove("hidden");
                dom.loginError.classList.add("hidden");
                dom.passwordInput.focus();
            });
        }

        if (dom.login2FaForm) {
            dom.login2FaForm.addEventListener("submit", handle2FaLogin);
        }

        if (dom.open2FaSetupBtn) {
            dom.open2FaSetupBtn.addEventListener("click", open2FaModal);
        }

        if (dom.dismiss2FaBannerBtn) {
            dom.dismiss2FaBannerBtn.addEventListener("click", () => {
                dom.setup2FaBanner.classList.add("hidden");
                sessionStorage.setItem("camila_2fa_banner_dismissed", "true");
            });
        }

        if (dom.security2FaBtn) {
            dom.security2FaBtn.addEventListener("click", open2FaModal);
        }

        if (dom.close2FaModalBtn) {
            dom.close2FaModalBtn.addEventListener("click", close2FaModal);
        }

        if (dom.confirm2FaForm) {
            dom.confirm2FaForm.addEventListener("submit", handleConfirm2Fa);
        }

        if (dom.disable2FaBtn) {
            dom.disable2FaBtn.addEventListener("click", handleDisable2Fa);
        }

        if (dom.copySecretBtn) {
            dom.copySecretBtn.addEventListener("click", () => {
                if (state.pending2FaSecret) {
                    navigator.clipboard.writeText(state.pending2FaSecret).then(() => {
                        dom.copySecretBtn.innerHTML = `<i class="fa-solid fa-check"></i> ¡Copiado!`;
                        setTimeout(() => {
                            dom.copySecretBtn.innerHTML = `<i class="fa-solid fa-copy"></i> Copiar`;
                        }, 2000);
                    }).catch(() => {
                        showToast("No se pudo copiar automáticamente al portapapeles", "info");
                    });
                }
            });
        }

        // Cerrar modales con tecla ESC
        window.addEventListener("keydown", (e) => {
            if (e.key === "Escape") {
                closePreview();
                closeRenameModal();
                closeDeleteModal();
                closeStatsModal();
                closeServerModal();
                close2FaModal();
            }
        });

        // Cerrar modales al hacer clic en el fondo
        [dom.previewModal, dom.renameModal, dom.deleteModal, dom.statsModal, dom.serverModal, dom.twoFactorModal].forEach(modal => {
            if (modal) {
                modal.addEventListener("click", (e) => {
                    if (e.target === modal) {
                        modal.classList.add("hidden");
                    }
                });
            }
        });
    }

    // ----------------- Malla de Ciberdefensa Shiori Sentinel (Fondo Dinámico) -----------------
    function initSentinelBackground() {
        const canvas = document.getElementById("sentinelCanvas");
        if (!canvas) return;
        const ctx = canvas.getContext("2d");

        let width = (canvas.width = window.innerWidth);
        let height = (canvas.height = window.innerHeight);

        const nodes = [];
        const nodeCount = Math.min(55, Math.max(25, Math.floor((width * height) / 25000)));

        for (let i = 0; i < nodeCount; i++) {
            nodes.push({
                x: Math.random() * width,
                y: Math.random() * height,
                vx: (Math.random() - 0.5) * 0.4,
                vy: (Math.random() - 0.5) * 0.4,
                radius: Math.random() * 1.8 + 1.2,
                color: Math.random() > 0.45 ? "rgba(192, 132, 252, " : "rgba(56, 189, 248, "
            });
        }

        function draw() {
            ctx.clearRect(0, 0, width, height);

            // Conexiones de malla de protección
            for (let i = 0; i < nodes.length; i++) {
                for (let j = i + 1; j < nodes.length; j++) {
                    const dx = nodes[i].x - nodes[j].x;
                    const dy = nodes[i].y - nodes[j].y;
                    const dist = Math.sqrt(dx * dx + dy * dy);

                    if (dist < 135) {
                        const alpha = (1 - dist / 135) * 0.22;
                        ctx.strokeStyle = `rgba(168, 85, 247, ${alpha})`;
                        ctx.lineWidth = 0.8;
                        ctx.beginPath();
                        ctx.moveTo(nodes[i].x, nodes[i].y);
                        ctx.lineTo(nodes[j].x, nodes[j].y);
                        ctx.stroke();
                    }
                }
            }

            // Nodos protectores
            for (const n of nodes) {
                n.x += n.vx;
                n.y += n.vy;

                if (n.x < 0 || n.x > width) n.vx *= -1;
                if (n.y < 0 || n.y > height) n.vy *= -1;

                ctx.fillStyle = n.color + "0.65)";
                ctx.beginPath();
                ctx.arc(n.x, n.y, n.radius, 0, Math.PI * 2);
                ctx.fill();
            }

            requestAnimationFrame(draw);
        }

        window.addEventListener("resize", () => {
            width = canvas.width = window.innerWidth;
            height = canvas.height = window.innerHeight;
        });

        draw();
    }

    // ----------------- Renovación Silenciosa Periódica (Silent Refresh) -----------------
    function startSilentRefreshTimer() {
        // Cada 30 minutos comprueba si el usuario sigue activo y renueva el token
        setInterval(async () => {
            if (state.isAuthenticated && !dom.appContainer.classList.contains("hidden")) {
                try {
                    const data = await apiFetch("/api/auth/refresh", { method: "POST" });
                    if (data && data.token) {
                        state.token = data.token;
                    }
                } catch (e) {
                    // Si la sesión fue revocada o falló, se cerrará naturalmente en el siguiente apiFetch
                }
            }
        }, 30 * 60 * 1000);
    }

    // ----------------- Inicialización -----------------
    function init() {
        // H4: Limpieza preventiva de tokens heredados en localStorage
        try { localStorage.removeItem("camila_cloud_token"); } catch (_) {}
        initSentinelBackground();
        initEvents();
        checkExistingSession();
        startSilentRefreshTimer();
    }

    init();
})();
