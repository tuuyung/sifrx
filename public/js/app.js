// Fixed event codes keep credentials, DOM content and exception text out of logs.
const nativeFetch = window.fetch.bind(window);
let clientLogCount = 0;
let clientLogWindow = Date.now();
function logClientEvent(event) {
  if (Date.now() - clientLogWindow >= 60000) {
    clientLogWindow = Date.now();
    clientLogCount = 0;
  }
  if (clientLogCount++ >= 30) return;
  nativeFetch("/api/client-events", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ event }),
    keepalive: true
  }).catch(() => {});
}
window.addEventListener("error", () => logClientEvent("browser.error"));
window.addEventListener("unhandledrejection", () => logClientEvent("browser.rejection"));
window.fetch = async (...args) => {
  try {
    return await nativeFetch(...args);
  } catch (error) {
    logClientEvent("network.failed");
    throw error;
  }
};
document.addEventListener("DOMContentLoaded", () => logClientEvent("page.ready"));
document.addEventListener("click", (event) => {
  if (event.target.closest("button")) logClientEvent("ui.action");
  const profileMenu = document.getElementById("profileMenu");
  if (profileMenu && !profileMenu.contains(event.target)) profileMenu.open = false;
});
document.addEventListener("keydown", (event) => {
  const profileMenu = document.getElementById("profileMenu");
  if (event.key === "Escape" && profileMenu && profileMenu.open) {
    profileMenu.open = false;
    profileMenu.querySelector("summary").focus();
  }
});
document.addEventListener("DOMContentLoaded", () => {
  document.getElementById("profileMenu").addEventListener("toggle", (event) => {
    if (event.target.open) logClientEvent("ui.action");
  });
});

// ŞifrX Minimalist Frontend Controller
// Clear passwords retained by older versions; secrets now live only in memory.
sessionStorage.removeItem("sifrx_mp");
let appState = {
  token: sessionStorage.getItem("sifrx_token") || null,
  user: sessionStorage.getItem("sifrx_user") || null,
  masterPassword: null,
  itemType: "login",
  decryptedItems: {}
};
const downloadUrls = new Set();
let saveInProgress = false;
let saveGeneration = 0;
const MAX_FILE_BYTES = 1048576;

// DOM Yükləndikdə
document.addEventListener("DOMContentLoaded", async () => {
  if (appState.token && appState.user && appState.masterPassword) {
    try {
      const response = await fetch("/api/me", { headers: { Authorization: "Bearer " + appState.token } });
      if (response.ok) {
        showMainSection();
      } else {
        clearLocalSession();
        showAuthSection();
      }
    } catch (_) {
      showAuthSection();
      showAuthError("Əlaqə qurulmadı. Yenidən daxil olun.");
    }
  } else {
    clearLocalSession();
    showAuthSection();
  }
  if (document.getElementById("genLength")) generateNewPassword();
});

// AUTH TƏB DƏYİŞMƏSİ
function switchAuthTab(tab) {
  const tabLogin = document.getElementById("tabLogin");
  const tabRegister = document.getElementById("tabRegister");
  const loginForm = document.getElementById("loginForm");
  const registerForm = document.getElementById("registerForm");
  hideAuthMessages();

  if (tab === "login") {
    tabLogin.classList.add("active");
    tabRegister.classList.remove("active");
    loginForm.classList.remove("hidden");
    registerForm.classList.add("hidden");
  } else {
    tabRegister.classList.add("active");
    tabLogin.classList.remove("active");
    registerForm.classList.remove("hidden");
    loginForm.classList.add("hidden");
  }
}

function hideAuthMessages() {
  const err = document.getElementById("authError");
  const succ = document.getElementById("authSuccess");
  err.classList.add("hidden");
  succ.classList.add("hidden");
  err.innerText = "";
  succ.innerText = "";
}

function showAuthError(msg) {
  const err = document.getElementById("authError");
  err.innerText = msg;
  err.classList.remove("hidden");
}

function showAuthSuccess(msg) {
  const succ = document.getElementById("authSuccess");
  succ.innerText = msg;
  succ.classList.remove("hidden");
}

// GİRİŞ
async function handleLogin(e) {
  e.preventDefault();
  hideAuthMessages();

  const username = document.getElementById("loginUsername").value.trim();
  const password = document.getElementById("loginPassword").value;

  try {
    const res = await fetch("/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password, otp_code: document.getElementById("loginOtp").value.trim() })
    });
    const data = await res.json();

    if (!res.ok || !data.success) {
      if (data.requires_2fa) {
        document.getElementById("loginTwoFactor").classList.remove("hidden");
        document.getElementById("loginOtp").focus();
      }
      showAuthError(data.error || "Giriş uğursuz oldu.");
      return;
    }

    appState.token = data.token;
    appState.user = data.username;
    appState.masterPassword = password;

    sessionStorage.setItem("sifrx_token", data.token);
    sessionStorage.setItem("sifrx_user", data.username);

    document.getElementById("loginForm").reset();
    document.getElementById("loginTwoFactor").classList.add("hidden");
    showMainSection();
  } catch (err) {
    showAuthError("Əlaqə xətası: " + err.message);
  }
}

// QEYDİYYAT
async function handleRegister(e) {
  e.preventDefault();
  hideAuthMessages();

  const username = document.getElementById("regUsername").value.trim();
  const password = document.getElementById("regPassword").value;
  const confirmPassword = document.getElementById("regConfirmPassword").value;

  try {
    const res = await fetch("/api/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username,
        password,
        confirm_password: confirmPassword
      })
    });
    const data = await res.json();

    if (!res.ok || !data.success) {
      showAuthError(data.error || "Qeydiyyat uğursuz oldu.");
      return;
    }

    showAuthSuccess("Qeydiyyat uğurla tamamlandı. Daxil ola bilərsiniz.");
    document.getElementById("loginUsername").value = username;
    document.getElementById("loginPassword").value = password;
    switchAuthTab("login");
  } catch (err) {
    showAuthError("Əlaqə xətası: " + err.message);
  }
}

// ÇIXIŞ
async function handleLogout() {
  const token = appState.token;
  clearLocalSession();
  showAuthSection();
  if (token) {
    try {
      await fetch("/api/logout", {
        method: "POST",
        headers: { Authorization: "Bearer " + token }
      });
    } catch (_) {}
  }
}

function clearLocalSession() {
  saveGeneration++;
  saveInProgress = false;
  const saveButton = document.getElementById("btnSaveItem");
  if (saveButton) saveButton.disabled = false;
  for (const url of downloadUrls) URL.revokeObjectURL(url);
  downloadUrls.clear();
  appState.token = null;
  appState.user = null;
  appState.masterPassword = null;
  appState.decryptedItems = {};
  const container = document.getElementById("itemsContainer");
  if (container) container.replaceChildren();
  for (const id of ["loginForm", "registerForm", "itemForm"]) {
    const form = document.getElementById(id);
    if (form) form.reset();
  }

  sessionStorage.removeItem("sifrx_token");
  sessionStorage.removeItem("sifrx_user");
  sessionStorage.removeItem("sifrx_mp");
  const quota = document.getElementById("fileQuota");
  if (quota) quota.textContent = "Hesab limiti: 10 MiB və 50 fayl.";
  const status = document.getElementById("itemStatus");
  if (status) { status.textContent = ""; status.classList.add("hidden"); }
  if (document.getElementById("itemForm")) switchItemType("login");

}

function showAuthSection() {
  document.getElementById("profileMenu").open = false;
  document.getElementById("currentUserBadge").textContent = "";
  document.getElementById("authSection").classList.remove("hidden");
  document.getElementById("mainSection").classList.add("hidden");
  if (typeof resetSettingsPage === "function") resetSettingsPage();
}

function showMainSection() {
  document.getElementById("authSection").classList.add("hidden");
  document.getElementById("mainSection").classList.remove("hidden");
  document.getElementById("currentUserBadge").innerText = appState.user;
  if (document.getElementById("itemsContainer")) loadItems();
  if (typeof loadAccountSettings === "function") loadAccountSettings();
}

// ŞİFRƏ GENERATORU
function updateLengthDisplay(val) {
  document.getElementById("lengthDisplay").innerText = val;
}

async function generateNewPassword() {
  const length = parseInt(document.getElementById("genLength").value, 10);
  const uppercase = document.getElementById("genUpper").checked;
  const lowercase = document.getElementById("genLower").checked;
  const digits = document.getElementById("genDigits").checked;
  const symbols = document.getElementById("genSymbols").checked;

  try {
    const res = await fetch("/api/generate-password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ length, uppercase, lowercase, digits, symbols })
    });
    const data = await res.json();
    if (data.password) {
      document.getElementById("genResult").value = data.password;
    }
  } catch (_) {}
}

function copyGeneratedPassword() {
  const val = document.getElementById("genResult").value;
  if (!val) return;
  navigator.clipboard.writeText(val).catch(() => logClientEvent("clipboard.failed"));
}

function useGeneratedForLogin() {
  const val = document.getElementById("genResult").value;
  if (val) {
    document.getElementById("fieldLoginPassword").value = val;
  }
}

// MƏLUMAT TİPİ DƏYİŞMƏSİ (LOGIN / KART)
function switchItemType(type) {
  if (saveInProgress || !["login", "card", "file"].includes(type)) return;
  appState.itemType = type;
  for (const [kind, suffix] of [["login", "Login"], ["card", "Card"], ["file", "File"]]) {
    const active = kind === type;
    document.getElementById("btnType" + suffix).classList.toggle("active", active);
    const fields = document.getElementById(kind + "Fields");
    fields.classList.toggle("hidden", !active);
    fields.querySelectorAll("input, button").forEach(control => { control.disabled = !active; });
  }
}

function fileToBase64(bytes) {
  let binary = "";
  for (let offset = 0; offset < bytes.length; offset += 8192) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 8192));
  }
  return btoa(binary);
}

// MƏLUMATIN ŞİFRƏLƏNƏRƏK SAXLANILMASI
async function handleSaveItem(e) {
  e.preventDefault();
  if (saveInProgress || !appState.token) return;
  saveInProgress = true;
  const generation = ++saveGeneration;
  const token = appState.token;
  const password = appState.masterPassword;
  const itemType = appState.itemType;
  const saveButton = document.getElementById("btnSaveItem");
  saveButton.disabled = true;
  const statusEl = document.getElementById("itemStatus");
  statusEl.classList.add("hidden");

  let payload = {};
  if (itemType === "login") {
    payload = {
      title: document.getElementById("fieldLoginTitle").value.trim(),
      username: document.getElementById("fieldLoginUsername").value.trim(),
      password: document.getElementById("fieldLoginPassword").value,
      website: document.getElementById("fieldLoginWebsite").value.trim()
    };
  } else if (itemType === "card") {
    payload = {
      title: document.getElementById("fieldCardTitle").value.trim(),
      cardholder: document.getElementById("fieldCardHolder").value.trim(),
      cardNumber: document.getElementById("fieldCardNumber").value.trim(),
      expiry: document.getElementById("fieldCardExpiry").value.trim(),
      cvv: document.getElementById("fieldCardCvv").value.trim()
    };
  }

  try {
    let endpoint = "/api/items";
    let body = { type: itemType, master_password: password, data: payload };
    if (itemType === "file") {
      const files = document.getElementById("fieldFile").files;
      const file = files[0];
      if (files.length !== 1 || !/\.(txt|csv)$/i.test(file.name)) {
        throw new Error("Yalnız bir .txt və ya .csv faylı seçin.");
      }
      if (file.size > MAX_FILE_BYTES) throw new Error("Fayl həcmi 1 MiB-dan çox ola bilməz.");
      const bytes = new Uint8Array(await file.arrayBuffer());
      if (appState.token !== token) return;
      if (bytes.length > MAX_FILE_BYTES) throw new Error("Fayl həcmi 1 MiB-dan çox ola bilməz.");
      endpoint = "/api/files";
      body = { filename: file.name, content_base64: fileToBase64(bytes), master_password: password };
    }
    const res = await fetch(endpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: "Bearer " + token
      },
      body: JSON.stringify(body)
    });
    const data = await res.json().catch(() => ({ error: "Sorğu tamamlanmadı. Fayl və sorğu limitlərini yoxlayın." }));
    if (appState.token !== token) return;

    if (!res.ok || !data.success) {
      statusEl.className = "status-msg error";
      statusEl.innerText = data.error || "Xəta baş verdi.";
      statusEl.classList.remove("hidden");
      return;
    }

    // Formu sıfırla
    document.getElementById("itemForm").reset();
    statusEl.className = "status-msg success";
    statusEl.innerText = "Məlumat .sifrx formatında şifrələnərək saxlanıldı.";
    statusEl.classList.remove("hidden");
    setTimeout(() => { if (appState.token === token) statusEl.classList.add("hidden"); }, 3000);

    loadItems();
  } catch (err) {
    if (appState.token !== token) return;
    statusEl.className = "status-msg error";
    statusEl.innerText = "Şəbəkə xətası: " + err.message;
    statusEl.classList.remove("hidden");
  } finally {
    if (saveGeneration === generation) {
      saveInProgress = false;
      saveButton.disabled = false;
    }
  }
}

// ELEMENTLƏRİN SİYAHISI
function vaultElement(tag, className, text) {
  const node = document.createElement(tag);
  node.className = className;
  if (text !== undefined) node.textContent = String(text);
  return node;
}

function vaultButton(label, className, action) {
  const button = vaultElement("button", className, label);
  button.type = "button";
  button.addEventListener("click", action);
  return button;
}

function renderVaultItem(item) {
  const card = vaultElement("div", "item-card");
  const header = vaultElement("div", "item-header");
  const info = vaultElement("div", "item-info");
  const title = vaultElement("span", "item-title", item.title || "");
  title.title = item.title || "";
  info.append(vaultElement("span", "item-badge" + (item.type === "card" ? " card" : ""),
                          item.type === "file" ? "Fayl" : item.type === "card" ? "Kart" : "Login"),
              title);
  const actions = vaultElement("div", "item-actions");
  const decoded = appState.decryptedItems[item.id];
  if (item.type === "file") actions.append(vaultButton("Endir", "btn btn-sm btn-secondary", () => downloadFile(item.id)));
  actions.append(vaultButton(decoded ? "Gizlət" : "Bax", "btn btn-sm btn-secondary",
                            () => toggleDecryptItem(item.id)),
                 vaultButton("Sil", "btn btn-sm btn-danger", () => deleteItem(item.id)));
  header.append(info, actions);
  card.append(header);
  if (decoded) {
    const view = vaultElement("div", "decrypted-view");
    if (item.type === "file") {
      view.append(vaultElement("div", "file-help", `${decoded.filename} · ${decoded.size_bytes} bayt · ${decoded.encoding}`),
                  vaultElement("pre", "file-preview", decoded.preview));
      if (decoded.truncated) view.append(vaultElement("p", "file-help", "İlk 65536 simvol göstərilir. Tam faylı endirə bilərsiniz."));
      card.append(view);
      return card;
    }
    const fields = item.type === "card"
      ? [["Sahib:", "cardholder"], ["Kart №:", "cardNumber"], ["Bitmə:", "expiry"], ["CVV:", "cvv"]]
      : [["İstifadəçi:", "username"], ["Şifrə:", "password"], ["Qeyd / Sayt:", "website"]];
    for (const [label, key] of fields) {
      const value = String(decoded[key] || "");
      if (key === "website" && !value) continue;
      const row = vaultElement("div", "field-row");
      row.append(vaultElement("span", "field-label", label),
                 vaultElement("span", "field-val", value),
                 vaultButton("Kopyala", "btn btn-sm btn-secondary", () => copyText(value)));
      view.append(row);
    }
    card.append(view);
  }
  return card;
}

async function loadItems() {
  const container = document.getElementById("itemsContainer");
  if (!appState.token || !container) return;
  const token = appState.token;
  try {
    const res = await fetch("/api/items", {
      headers: { Authorization: "Bearer " + token }
    });
    const data = await res.json();
    if (appState.token !== token) return;
    if (!res.ok || !Array.isArray(data.items)) {
      container.replaceChildren(vaultElement("div", "empty-state", "Məlumatları yükləmək mümkün olmadı"));
      return;
    }
    const quota = document.getElementById("fileQuota");
    if (quota && data.upload_policy) {
      const policy = data.upload_policy;
      quota.textContent = `${(policy.used_bytes / 1048576).toFixed(2)} / 10 MiB · ${policy.count} / 50 fayl`;
    }
    container.replaceChildren(...(data.items.length
      ? data.items.map(renderVaultItem)
      : [vaultElement("div", "empty-state", "Saxlanılmış məlumat yoxdur")]));
  } catch (_) {
    if (appState.token === token) {
      container.replaceChildren(vaultElement("div", "empty-state", "Məlumatları yükləmək mümkün olmadı"));
    }
  }
}

// DEŞİFRƏLƏMƏ VƏ BAXIŞ
async function toggleDecryptItem(itemId) {
  if (appState.decryptedItems[itemId]) {
    delete appState.decryptedItems[itemId];
    loadItems();
    return;
  }

  const token = appState.token;
  try {
    const res = await fetch(`/api/items/${itemId}/decrypt`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: "Bearer " + token
      },
      body: JSON.stringify({ master_password: appState.masterPassword })
    });
    const data = await res.json();
    if (appState.token !== token) return;

    if (!res.ok || !data.success) {
      alert(data.error || "Deşifrələmə xətası.");
      return;
    }

    appState.decryptedItems[itemId] = data.item;
    loadItems();
  } catch (err) {
    if (appState.token === token) alert("Xəta: " + err.message);
  }
}

// ELEMENTİ SİLMƏK
async function deleteItem(itemId) {
  if (!confirm("Bu elementi silmək istədiyinizdən əminsiniz?")) return;

  const token = appState.token;
  try {
    const res = await fetch(`/api/items/${itemId}`, {
      method: "DELETE",
      headers: { Authorization: "Bearer " + token }
    });
    const data = await res.json();
    if (appState.token !== token) return;

    if (!res.ok || !data.success) {
      alert(data.error || "Silinmə xətası.");
      return;
    }

    delete appState.decryptedItems[itemId];
    loadItems();
  } catch (err) {
    if (appState.token === token) alert("Xəta: " + err.message);
  }
}

async function downloadFile(itemId) {
  const token = appState.token;
  if (!token) return;
  try {
    const response = await fetch(`/api/items/${encodeURIComponent(itemId)}/download`, {
      method: "POST", headers: { "Content-Type": "application/json", Authorization: "Bearer " + token },
      body: JSON.stringify({ master_password: appState.masterPassword })
    });
    if (!response.ok) {
      const data = await response.json().catch(() => ({}));
      if (appState.token === token) alert(data.error || "Faylı endirmək mümkün olmadı.");
      return;
    }
    const blob = await response.blob();
    if (appState.token !== token) return;
    const url = URL.createObjectURL(new Blob([blob], { type: "application/octet-stream" }));
    downloadUrls.add(url);
    const link = document.createElement("a");
    link.href = url;
    // Use the server's validated attachment name, including RFC 5987 Unicode.
    const disposition = response.headers.get("Content-Disposition") || "";
    const unicodeName = disposition.match(/filename\*=UTF-8''([^;]+)/i);
    const asciiName = disposition.match(/filename="([^"]+)"|filename=([^;]+)/i);
    link.download = unicodeName ? decodeURIComponent(unicodeName[1]) : asciiName ? (asciiName[1] || asciiName[2]).trim() : "fayl.txt";
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => { URL.revokeObjectURL(url); downloadUrls.delete(url); }, 1000);
  } catch (_) {
    if (appState.token === token) alert("Faylı endirmək mümkün olmadı.");
  }
}

// KÖMƏKÇİ FUNKSİYALAR
function copyText(txt) {
  if (!txt) return;
  navigator.clipboard.writeText(txt).catch(() => logClientEvent("clipboard.failed"));
}

