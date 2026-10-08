let twoFactorEnabled = false;
let twoFactorSetupPending = false;
let settingsBusy = false;
let setupTimer = null;

function settingsMessage(message, error = false) {
  const status = document.getElementById("settingsStatus");
  status.textContent = message;
  status.className = "status-msg " + (error ? "error" : "success");
}

async function settingsRequest(action, values) {
  const response = await fetch("/api/settings" + (action ? "/" + action : ""), {
    method: action ? "POST" : "GET",
    headers: { "Content-Type": "application/json", Authorization: "Bearer " + appState.token },
    ...(action ? { body: JSON.stringify(values) } : {})
  });
  const result = await response.json();
  if (response.status === 401) {
    clearLocalSession();
    showAuthSection();
    showAuthError("Sessiya bitib. Yenidən daxil olun.");
  }
  if (!response.ok) throw new Error(result.error || "Əməliyyat tamamlanmadı.");
  return result;
}

async function loadAccountSettings() {
  try {
    const result = await settingsRequest();
    twoFactorEnabled = result.two_factor_enabled;
    document.querySelectorAll(".two-factor-field").forEach((label) => {
      label.classList.toggle("hidden", !twoFactorEnabled);
      label.querySelector("input").required = twoFactorEnabled;
    });
    cancelTwoFactorSetup();
    document.getElementById("twoFactorButton").disabled = false;
  } catch (error) {
    settingsMessage(error.message, true);
  }
}

function cancelTwoFactorSetup() {
  clearTimeout(setupTimer);
  twoFactorSetupPending = false;
  document.getElementById("twoFactorSetup").classList.add("hidden");
  document.getElementById("cancelTwoFactor").classList.add("hidden");
  document.getElementById("twoFactorQr").removeAttribute("src");
  document.getElementById("twoFactorKey").value = "";
  document.getElementById("twoFactorCodeLabel").classList.toggle("hidden", !twoFactorEnabled);
  document.querySelector("#twoFactorForm [name=otp_code]").required = twoFactorEnabled;
  document.querySelector("#twoFactorForm [name=otp_code]").value = "";
  document.getElementById("twoFactorStatus").textContent = twoFactorEnabled ? "2FA aktivdir." : "2FA aktiv deyil.";
  document.getElementById("twoFactorButton").textContent = twoFactorEnabled ? "2FA söndür" : "2FA quraşdır";
}

function resetSettingsPage() {
  cancelTwoFactorSetup();
  document.querySelectorAll(".settings-page form").forEach((form) => form.reset());
  document.getElementById("recoveryCodes").textContent = "";
  document.getElementById("recoveryCodesSection").classList.add("hidden");
  document.getElementById("twoFactorForm").classList.remove("hidden");
  document.getElementById("settingsStatus").classList.add("hidden");
  document.getElementById("twoFactorButton").disabled = true;
  document.getElementById("passwordForm").closest("section").classList.remove("hidden");
  document.getElementById("deleteAccountForm").closest("section").classList.remove("hidden");
}

async function runSettingsOperation(event, operation) {
  event.preventDefault();
  if (settingsBusy) return;
  const form = event.target;
  const values = Object.fromEntries(new FormData(form));
  settingsBusy = true;
  const buttons = Array.from(document.querySelectorAll(".settings-page button"));
  const disabled = buttons.map((button) => button.disabled);
  buttons.forEach((button) => { button.disabled = true; });
  try {
    await operation(values, form);
  } catch (error) {
    settingsMessage(error.message || "Əlaqə xətası. Yenidən cəhd edin.", true);
  } finally {
    settingsBusy = false;
    buttons.forEach((button, index) => { button.disabled = disabled[index]; });
  }
}

function returnToLogin(message) {
  clearLocalSession();
  showAuthSection();
  showAuthSuccess(message);
}

function changeAccountPassword(event) {
  return runSettingsOperation(event, async (values) => {
    await settingsRequest("password", values);
    returnToLogin("Şifrə dəyişdirildi. Yeni şifrə ilə daxil olun.");
  });
}

function deleteAccount(event) {
  event.preventDefault();
  if (!confirm("Hesabınız və bütün vault məlumatlarınız həmişəlik silinsin?")) return;
  return runSettingsOperation(event, async (values) => {
    await settingsRequest("delete-account", values);
    returnToLogin("Hesabınız və vault məlumatlarınız silindi.");
  });
}

function submitTwoFactor(event) {
  return runSettingsOperation(event, async (values, form) => {
    if (twoFactorEnabled) {
      await settingsRequest("2fa-disable", values);
      returnToLogin("2FA söndürüldü. Yenidən daxil olun.");
    } else if (twoFactorSetupPending) {
      const result = await settingsRequest("2fa-enable", values);
      clearLocalSession();
      clearTimeout(setupTimer);
      form.reset();
      cancelTwoFactorSetup();
      form.classList.add("hidden");
      document.getElementById("recoveryCodes").textContent = result.recovery_codes.join("\n");
      document.getElementById("recoveryCodesSection").classList.remove("hidden");
      document.getElementById("passwordForm").closest("section").classList.add("hidden");
      document.getElementById("deleteAccountForm").closest("section").classList.add("hidden");
      settingsMessage("2FA aktivləşdirildi. Bərpa kodlarını saxlayın, sonra yenidən daxil olun.");
    } else {
      const result = await settingsRequest("2fa-setup", values);
      twoFactorSetupPending = true;
      document.getElementById("twoFactorQr").src = result.qr_code;
      document.getElementById("twoFactorKey").value = result.secret;
      document.getElementById("twoFactorSetup").classList.remove("hidden");
      document.getElementById("twoFactorCodeLabel").classList.remove("hidden");
      document.getElementById("cancelTwoFactor").classList.remove("hidden");
      document.getElementById("twoFactorButton").textContent = "Kodu təsdiqlə və 2FA aktivləşdir";
      form.elements.otp_code.required = true;
      form.elements.otp_code.focus();
      settingsMessage("QR kodu skan edin və tətbiqinizdəki kodu daxil edin.");
      setupTimer = setTimeout(() => {
        cancelTwoFactorSetup();
        settingsMessage("Quraşdırmanın vaxtı bitib. Yenidən başlayın.", true);
      }, result.expires_in * 1000);
    }
  });
}

function finishTwoFactorSetup() {
  returnToLogin("2FA aktivdir. Şifrəniz və authenticator kodu ilə daxil olun.");
}
