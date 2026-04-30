const USERNAME_CACHE_KEY = "__threat_guard_username__";
const BOUND_ATTR = "data-threat-guard-bound";
const FILLED_ATTR = "data-threat-guard-filled";
const AUTOFILL_PROMPT_ID = "__threat_guard_autofill_prompt__";

function sendMessage(message) {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage(message, (response) => {
      if (chrome.runtime.lastError) {
        resolve({
          ok: false,
          error: chrome.runtime.lastError.message,
        });
        return;
      }

      resolve(response);
    });
  });
}

function cacheUsername(username) {
  if (!username) return;
  try {
    sessionStorage.setItem(USERNAME_CACHE_KEY, username);
  } catch {
    // Ignore session storage issues on locked-down pages.
  }
}

function readCachedUsername() {
  try {
    return sessionStorage.getItem(USERNAME_CACHE_KEY) || "";
  } catch {
    return "";
  }
}

function candidateInputs(form) {
  return [...form.querySelectorAll("input")].filter((input) => {
    if (!(input instanceof HTMLInputElement)) return false;
    if (input.disabled || input.readOnly) return false;
    if (input.type === "hidden") return false;
    if (["submit", "button", "checkbox", "radio", "file"].includes(input.type)) {
      return false;
    }
    return true;
  });
}

function findPasswordField(form) {
  return form.querySelector('input[type="password"]');
}

function findUsernameField(form, passwordField = null) {
  const inputs = candidateInputs(form).filter((input) => input !== passwordField);
  const preferred = inputs.filter((input) => {
    const haystack = `${input.name} ${input.id} ${input.autocomplete}`.toLowerCase();
    return (
      input.type === "email" ||
      input.type === "text" ||
      haystack.includes("user") ||
      haystack.includes("email") ||
      haystack.includes("login") ||
      haystack.includes("identifier") ||
      haystack.includes("account")
    );
  });

  return preferred[0] || inputs[0] || null;
}

function fillField(field, value) {
  if (!field || !value) return;
  field.focus();
  field.value = value;
  field.dispatchEvent(new Event("input", { bubbles: true }));
  field.dispatchEvent(new Event("change", { bubbles: true }));
}

function extractCredential(form) {
  const passwordField = findPasswordField(form);
  if (!passwordField || !passwordField.value) {
    return null;
  }

  const usernameField = findUsernameField(form, passwordField);
  const username = usernameField?.value.trim() || readCachedUsername();
  return {
    username,
    password: passwordField.value,
    usernameField,
    passwordField,
  };
}

function hasFillablePasswordField() {
  for (const form of document.forms) {
    const passwordField = findPasswordField(form);
    if (passwordField && !passwordField.value) {
      return true;
    }
  }

  const lonePassword = document.querySelector('input[type="password"]');
  return lonePassword instanceof HTMLInputElement && !lonePassword.value;
}

function autofillPasscodeMessage() {
  const label = window.location.hostname || "this website";
  return `Enter your 6-digit Threat Guard passcode to autofill on ${label}.`;
}

function removeAutofillPrompt() {
  document.getElementById(AUTOFILL_PROMPT_ID)?.remove();
}

function requestVaultPasscode(errorMessage = "") {
  removeAutofillPrompt();

  return new Promise((resolve) => {
    const promptHost = document.body || document.documentElement;
    if (!promptHost) {
      resolve(null);
      return;
    }

    const overlay = document.createElement("div");
    overlay.id = AUTOFILL_PROMPT_ID;
    overlay.style.position = "fixed";
    overlay.style.right = "16px";
    overlay.style.bottom = "16px";
    overlay.style.width = "min(320px, calc(100vw - 32px))";
    overlay.style.padding = "16px";
    overlay.style.borderRadius = "16px";
    overlay.style.background = "linear-gradient(145deg, #1f2937, #111827)";
    overlay.style.border = "1px solid rgba(96,165,250,0.26)";
    overlay.style.boxShadow = "0 24px 60px rgba(15,23,42,0.35)";
    overlay.style.color = "#f8fafc";
    overlay.style.fontFamily = "system-ui, sans-serif";
    overlay.style.zIndex = "2147483647";
    overlay.style.display = "flex";
    overlay.style.flexDirection = "column";
    overlay.style.gap = "10px";

    const badge = document.createElement("div");
    badge.textContent = "Threat Guard Autofill";
    badge.style.fontSize = "11px";
    badge.style.fontWeight = "700";
    badge.style.textTransform = "uppercase";
    badge.style.letterSpacing = "0.08em";
    badge.style.color = "#93c5fd";

    const title = document.createElement("div");
    title.textContent = autofillPasscodeMessage();
    title.style.fontSize = "14px";
    title.style.lineHeight = "1.5";

    const inputWrap = document.createElement("div");
    inputWrap.style.position = "relative";

    const input = document.createElement("input");
    input.type = "password";
    input.inputMode = "numeric";
    input.maxLength = 6;
    input.placeholder = "6-digit passcode";
    input.style.width = "100%";
    input.style.padding = "10px 48px 10px 12px";
    input.style.borderRadius = "10px";
    input.style.border = "1px solid rgba(148,163,184,0.3)";
    input.style.background = "rgba(15,23,42,0.55)";
    input.style.color = "#f8fafc";
    input.style.outline = "none";

    const visibilityButton = document.createElement("button");
    visibilityButton.type = "button";
    visibilityButton.textContent = "Show";
    visibilityButton.style.position = "absolute";
    visibilityButton.style.right = "12px";
    visibilityButton.style.top = "50%";
    visibilityButton.style.transform = "translateY(-50%)";
    visibilityButton.style.border = "none";
    visibilityButton.style.background = "transparent";
    visibilityButton.style.color = "#93c5fd";
    visibilityButton.style.fontSize = "12px";
    visibilityButton.style.fontWeight = "700";
    visibilityButton.style.cursor = "pointer";
    visibilityButton.style.padding = "0";

    let passcodeVisible = false;
    const updatePasscodeVisibility = () => {
      input.type = passcodeVisible ? "text" : "password";
      visibilityButton.textContent = passcodeVisible ? "Hide" : "Show";
    };

    visibilityButton.addEventListener("click", () => {
      passcodeVisible = !passcodeVisible;
      updatePasscodeVisibility();
      input.focus();
    });
    updatePasscodeVisibility();
    inputWrap.append(input, visibilityButton);

    const error = document.createElement("div");
    error.textContent = errorMessage || "Threat Guard will only fill after you confirm.";
    error.style.fontSize = "12px";
    error.style.lineHeight = "1.5";
    error.style.color = errorMessage ? "#fca5a5" : "#cbd5e1";

    const actions = document.createElement("div");
    actions.style.display = "flex";
    actions.style.justifyContent = "flex-end";
    actions.style.gap = "8px";

    const cancelButton = document.createElement("button");
    cancelButton.type = "button";
    cancelButton.textContent = "Cancel";
    cancelButton.style.padding = "9px 12px";
    cancelButton.style.borderRadius = "10px";
    cancelButton.style.border = "1px solid rgba(148,163,184,0.24)";
    cancelButton.style.background = "transparent";
    cancelButton.style.color = "#e5e7eb";
    cancelButton.style.cursor = "pointer";

    const confirmButton = document.createElement("button");
    confirmButton.type = "button";
    confirmButton.textContent = "Fill Login";
    confirmButton.style.padding = "9px 12px";
    confirmButton.style.borderRadius = "10px";
    confirmButton.style.border = "none";
    confirmButton.style.background = "linear-gradient(180deg, #60a5fa, #2563eb)";
    confirmButton.style.color = "#ffffff";
    confirmButton.style.fontWeight = "700";
    confirmButton.style.cursor = "pointer";

    const closePrompt = (value) => {
      overlay.remove();
      resolve(value);
    };

    const confirmPasscode = () => {
      const trimmed = input.value.trim();
      if (!/^\d{6}$/.test(trimmed)) {
        error.textContent = "Enter the 6-digit Threat Guard passcode you created in Password Manager.";
        error.style.color = "#fca5a5";
        input.focus();
        return;
      }

      closePrompt(trimmed);
    };

    cancelButton.addEventListener("click", () => closePrompt(null));
    confirmButton.addEventListener("click", confirmPasscode);
    input.addEventListener("keydown", (event) => {
      if (event.key === "Enter") {
        event.preventDefault();
        confirmPasscode();
      }
      if (event.key === "Escape") {
        event.preventDefault();
        closePrompt(null);
      }
    });

    actions.append(cancelButton, confirmButton);
    overlay.append(badge, title, inputWrap, error, actions);
    promptHost.appendChild(overlay);
    input.focus();
  });
}

function isRetryablePasscodeError(message) {
  const normalized = String(message || "").toLowerCase();
  return normalized.includes("passcode") && normalized.includes("did not match");
}

async function autofillPage() {
  const availability = await sendMessage({
    type: "has-credentials",
    origin: window.location.origin,
  });

  if (!availability?.ok || !availability.hasCredentials) {
    return false;
  }

  let response = null;
  let retryMessage = "";
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const passcode = await requestVaultPasscode(retryMessage);
    if (!passcode) {
      return true;
    }

    response = await sendMessage({
      type: "get-credentials",
      origin: window.location.origin,
      passcode,
    });

    if (response?.ok) {
      break;
    }

    if (!isRetryablePasscodeError(response?.error)) {
      if (response?.error) {
        window.alert(response.error);
      }
      return true;
    }

    retryMessage = response?.error || "Threat Guard could not verify that passcode.";
  }

  if (!response?.ok || !response.credentials?.length) {
    return true;
  }

  const credential = response.credentials[0];
  let filled = false;

  for (const form of document.forms) {
    const passwordField = findPasswordField(form);
    if (!passwordField || passwordField.value) continue;

    const usernameField = findUsernameField(form, passwordField);
    if (usernameField && !usernameField.value) {
      fillField(usernameField, credential.username);
      cacheUsername(credential.username);
    }

    fillField(passwordField, credential.password);
    passwordField.setAttribute(FILLED_ATTR, "true");
    filled = true;
  }

  if (!filled) {
    const lonePassword = document.querySelector('input[type="password"]');
    if (lonePassword instanceof HTMLInputElement && !lonePassword.value) {
      fillField(lonePassword, credential.password);
      lonePassword.setAttribute(FILLED_ATTR, "true");
    }
  }

  return true;
}

function bindForm(form) {
  if (!(form instanceof HTMLFormElement) || form.getAttribute(BOUND_ATTR) === "true") {
    return;
  }

  form.setAttribute(BOUND_ATTR, "true");

  const passwordField = findPasswordField(form);
  const usernameField = findUsernameField(form, passwordField);

  if (!passwordField && usernameField) {
    form.addEventListener("submit", () => {
      const username = usernameField.value.trim();
      if (username) {
        cacheUsername(username);
      }
    });
    return;
  }

  if (!passwordField) {
    return;
  }

  form.addEventListener("submit", () => {
    const credential = extractCredential(form);
    if (!credential) return;

    if (credential.username) {
      cacheUsername(credential.username);
    }

    if (credential.passwordField.getAttribute(FILLED_ATTR) === "true") {
      return;
    }

    const label = window.location.hostname || "this website";
    const confirmed = window.confirm(
      `Save this login for ${label} to Threat Guard?`,
    );

    if (!confirmed) {
      return;
    }

    void sendMessage({
      type: "save-credential",
      origin: window.location.origin,
      siteLabel: document.title || window.location.hostname,
      username: credential.username,
      password: credential.password,
    });
  });
}

function scanPage() {
  for (const form of document.forms) {
    bindForm(form);
  }

  void maybeAutofillPage();
}

let observerTimer = null;
let lastAutofillAt = 0;
let autofillAttempted = false;
let autofillCheckInFlight = false;

async function maybeAutofillPage() {
  const now = Date.now();
  if (
    autofillAttempted ||
    autofillCheckInFlight ||
    !hasFillablePasswordField() ||
    now - lastAutofillAt <= 1500
  ) {
    return;
  }

  lastAutofillAt = now;
  autofillCheckInFlight = true;

  try {
    const handled = await autofillPage();
    if (handled) {
      autofillAttempted = true;
    }
  } finally {
    autofillCheckInFlight = false;
  }
}
const observer = new MutationObserver(() => {
  if (observerTimer) {
    clearTimeout(observerTimer);
  }
  observerTimer = window.setTimeout(() => {
    scanPage();
  }, 250);
});

observer.observe(document.documentElement, {
  childList: true,
  subtree: true,
});

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", scanPage, { once: true });
} else {
  scanPage();
}

window.addEventListener("load", scanPage, { once: true });
