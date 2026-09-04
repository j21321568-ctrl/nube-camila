/**
 * Lógica Principal de la Nube Privada de Camila ✨
 * Maneja autenticación segura, operaciones de Google Drive,
 * drag-and-drop, pegado con Ctrl+V, visor multimedia y alertas de Render.
 */

(function () {
    // ----------------- Estado de la Aplicación -----------------
    const state = {
        token: localStorage.getItem("camila_cloud_token") || null,
        files: [],
        filteredFiles: [],
        activeCategory: "all",
        searchQuery: "",
        sortBy: "newest",
        viewMode: localStorage.getItem("camila_cloud_view") || "grid",
        currentPreviewIndex: -1,
        activeFileForAction: null,
        coldStartTimer: null
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

        // Navegación
        greetingText: document.getElementById("greetingText"),
        searchInput: document.getElementById("searchInput"),
        clearSearchBtn: document.getElementById("clearSearchBtn"),
        storageStatsBtn: document.getElementById("storageStatsBtn"),
        serverConfigBtn: document.getElementById("serverConfigBtn"),
        openServerSettingsBtn: document.getElementById("openServerSettingsBtn"),
        logoutBtn: document.getElementById("logoutBtn"),

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
        closeStatsBtn: document.getElementById("closeStatsBtn"),

        serverModal: document.getElementById("serverModal"),
        serverConfigForm: document.getElementById("serverConfigForm"),
        serverUrlInput: document.getElementById("serverUrlInput"),
        testServerBtn: document.getElementById("testServerBtn"),
        testServerStatus: document.getElementById("testServerStatus"),
        resetServerUrlBtn: document.getElementById("resetServerUrlBtn"),
        closeServerBtn: document.getElementById("closeServerBtn"),

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
            const response = await fetch(url, { ...options, headers });
            stopColdStartWatch();

            if (response.status === 401) {
                // Token vencido o contraseña errónea
                if (state.token) {
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

    // ----------------- Autenticación y Sesión -----------------
    async function checkExistingSession() {
        if (!state.token) {
            showLockScreen();
            return;
        }

        try {
            await apiFetch("/api/auth/verify");
            showApp();
            loadFiles();
        } catch (err) {
            state.token = null;
            localStorage.removeItem("camila_cloud_token");
            showLockScreen();
        }
    }

    async function handleLogin(e) {
        e.preventDefault();
        const password = dom.passwordInput.value;
        if (!password) return;

        dom.unlockBtn.disabled = true;
        dom.unlockBtn.innerHTML = `<span>Verificando...</span><div class="spinner-small"></div>`;
        dom.loginError.classList.add("hidden");

        try {
            const data = await apiFetch("/api/auth/login", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ password })
            });

            state.token = data.token;
            localStorage.setItem("camila_cloud_token", data.token);

            showToast(`¡Bienvenida a tu nube, ${data.userName || "Camila"}! ✨`, "success");
            dom.passwordInput.value = "";
            showApp();
            loadFiles();
        } catch (err) {
            dom.loginErrorText.textContent = err.message || "Contraseña incorrecta";
            dom.loginError.classList.remove("hidden");
            dom.passwordInput.focus();
        } finally {
            dom.unlockBtn.disabled = false;
            dom.unlockBtn.innerHTML = `<span>Desbloquear Mi Nube</span><i class="fa-solid fa-arrow-right"></i>`;
        }
    }

    function logout(message = "Sesión cerrada correctamente") {
        state.token = null;
        localStorage.removeItem("camila_cloud_token");
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

            // Generar URL de previsualización con token embebido
            const previewUrl = CONFIG.apiUrl(`/api/files/${file.id}/preview?token=${state.token}`);

            // Previsualización superior (miniatura si es imagen, o icono temático)
            let previewMarkup = "";
            if (file.category === "image") {
                previewMarkup = `<img class="card-thumbnail-img" src="${previewUrl}" alt="${file.name}" loading="lazy" onerror="this.onerror=null; this.parentElement.innerHTML='<div class=\\'card-icon-wrap\\' style=\\'background: ${bg}; color: ${color};\\'><i class=\\'fa-solid ${icon}\\'></i></div>'">`;
            } else {
                previewMarkup = `<div class="card-icon-wrap" style="background: ${bg}; color: ${color};"><i class="fa-solid ${icon}"></i></div>`;
            }

            card.innerHTML = `
                <div class="card-preview" data-index="${index}">
                    ${previewMarkup}
                    <button class="card-star-btn ${file.starred ? 'starred' : ''}" data-id="${file.id}" title="${file.starred ? 'Quitar de favoritos' : 'Agregar a favoritos'}">
                        <i class="fa-${file.starred ? 'solid' : 'regular'} fa-heart"></i>
                    </button>
                </div>
                <div class="card-info">
                    <span class="card-filename" title="${file.name}">${file.name}</span>
                    <div class="card-meta">
                        <span>${file.formattedSize}</span>
                        <span>${file.relativeDate}</span>
                    </div>
                </div>
                <div class="card-actions">
                    <button class="action-btn preview-btn" data-index="${index}" title="Previsualizar">
                        <i class="fa-solid fa-eye"></i>
                    </button>
                    <button class="action-btn download-btn" data-id="${file.id}" data-name="${file.name}" title="Descargar">
                        <i class="fa-solid fa-download"></i>
                    </button>
                    <button class="action-btn rename-btn" data-id="${file.id}" data-name="${file.name}" title="Renombrar">
                        <i class="fa-solid fa-pen-to-square"></i>
                    </button>
                    <button class="action-btn delete-btn" data-id="${file.id}" data-name="${file.name}" title="Eliminar">
                        <i class="fa-solid fa-trash-can"></i>
                    </button>
                </div>
            `;

            dom.filesGrid.appendChild(card);
        });

        attachCardEventListeners();
    }

    function renderListView() {
        dom.filesTableBody.innerHTML = "";

        state.filteredFiles.forEach((file, index) => {
            const tr = document.createElement("tr");
            const { icon, color } = getFileCategoryIcon(file.category, file.mimeType);

            tr.innerHTML = `
                <td style="text-align: center;">
                    <button class="card-star-btn ${file.starred ? 'starred' : ''}" data-id="${file.id}" style="position: static; width: 28px; height: 28px;" title="Favorito">
                        <i class="fa-${file.starred ? 'solid' : 'regular'} fa-heart"></i>
                    </button>
                </td>
                <td>
                    <div class="table-name-cell" data-index="${index}">
                        <i class="fa-solid ${icon} table-file-icon" style="color: ${color};"></i>
                        <span title="${file.name}">${file.name}</span>
                    </div>
                </td>
                <td>${file.category.toUpperCase()}</td>
                <td>${file.formattedSize}</td>
                <td>${file.relativeDate}</td>
                <td>
                    <div class="table-actions-cell">
                        <button class="action-btn preview-btn" data-index="${index}" title="Previsualizar"><i class="fa-solid fa-eye"></i></button>
                        <button class="action-btn download-btn" data-id="${file.id}" data-name="${file.name}" title="Descargar"><i class="fa-solid fa-download"></i></button>
                        <button class="action-btn rename-btn" data-id="${file.id}" data-name="${file.name}" title="Renombrar"><i class="fa-solid fa-pen-to-square"></i></button>
                        <button class="action-btn delete-btn" data-id="${file.id}" data-name="${file.name}" title="Eliminar"><i class="fa-solid fa-trash-can"></i></button>
                    </div>
                </td>
            `;

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

    // ----------------- Descarga de Archivo -----------------
    function downloadFile(fileId) {
        const url = CONFIG.apiUrl(`/api/files/${fileId}/download?token=${state.token}`);
        const a = document.createElement("a");
        a.href = url;
        a.target = "_blank";
        document.body.appendChild(a);
        a.click();
        a.remove();
        showToast("Iniciando descarga...", "info");
    }

    // ----------------- Subida de Archivos con Progreso Real -----------------
    function uploadFiles(fileList) {
        if (!fileList || fileList.length === 0) return;

        const formData = new FormData();
        for (let i = 0; i < fileList.length; i++) {
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
                    showToast(`¡Subida completada! (${res.totalUploaded} archivos)`, "success");
                    loadFiles();
                } catch {
                    showToast("Archivos subidos exitosamente ✨", "success");
                    loadFiles();
                }
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

    // ----------------- Visor Multimedia (In-App Lightbox & Player) -----------------
    function openPreview(index) {
        state.currentPreviewIndex = index;
        const file = state.filteredFiles[index];
        if (!file) return;

        const { icon, color } = getFileCategoryIcon(file.category, file.mimeType);
        dom.previewIcon.className = `fa-solid ${icon}`;
        dom.previewIcon.style.color = color;
        dom.previewTitle.textContent = file.name;
        dom.previewMeta.textContent = `${file.formattedSize} · Modificado: ${file.relativeDate}`;

        const previewStreamUrl = CONFIG.apiUrl(`/api/files/${file.id}/preview?token=${state.token}`);

        // Configurar botón de descarga dentro del visor
        dom.previewDownloadBtn.onclick = () => downloadFile(file.id);

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

            fetch(previewStreamUrl)
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

        dom.serverConfigBtn.addEventListener("click", openServerModal);
        dom.openServerSettingsBtn.addEventListener("click", openServerModal);
        dom.closeServerBtn.addEventListener("click", closeServerModal);
        dom.testServerBtn.addEventListener("click", handleTestServer);
        dom.serverConfigForm.addEventListener("submit", handleSaveServerUrl);
        dom.resetServerUrlBtn.addEventListener("click", handleResetServerUrl);

        // Cerrar modales con tecla ESC
        window.addEventListener("keydown", (e) => {
            if (e.key === "Escape") {
                closePreview();
                closeRenameModal();
                closeDeleteModal();
                closeStatsModal();
                closeServerModal();
            }
        });

        // Cerrar modales al hacer clic en el fondo
        [dom.previewModal, dom.renameModal, dom.deleteModal, dom.statsModal, dom.serverModal].forEach(modal => {
            modal.addEventListener("click", (e) => {
                if (e.target === modal) {
                    modal.classList.add("hidden");
                }
            });
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

    // ----------------- Inicialización -----------------
    function init() {
        initSentinelBackground();
        initEvents();
        checkExistingSession();
    }

    init();
})();
