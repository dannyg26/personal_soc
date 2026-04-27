const API_BASE = "http://127.0.0.1:38913";
const TOKEN_KEY = "threatGuardToken";
const PAIRED_AT_KEY = "threatGuardPairedAt";

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  (async () => {
    switch (message?.type) {
      case "get-status":
        sendResponse(await getStatus());
        break;
      case "pair":
        sendResponse(await pairThreatGuard(message.pairCode));
        break;
      case "clear-pairing":
        await chrome.storage.local.remove([TOKEN_KEY, PAIRED_AT_KEY]);
        sendResponse({ ok: true });
        break;
      case "has-credentials":
        sendResponse(await hasCredentials(message.origin));
        break;
      case "get-credentials":
        sendResponse(await getCredentials(message.origin, message.passcode));
        break;
      case "save-credential":
        sendResponse(
          await saveCredential({
            origin: message.origin,
            username: message.username,
            password: message.password,
            siteLabel: message.siteLabel,
          }),
        );
        break;
      default:
        sendResponse({ ok: false, error: "Unsupported Threat Guard action." });
        break;
    }
  })().catch((error) => {
    sendResponse({
      ok: false,
      error: error instanceof Error ? error.message : String(error),
    });
  });

  return true;
});

async function getStatus() {
  const stored = await chrome.storage.local.get([TOKEN_KEY, PAIRED_AT_KEY]);
  const desktopReachable = await pingDesktop();

  return {
    ok: true,
    paired: Boolean(stored[TOKEN_KEY]),
    desktopReachable,
    pairedAt: stored[PAIRED_AT_KEY] ?? null,
  };
}

async function pairThreatGuard(pairCode) {
  if (!pairCode?.trim()) {
    return { ok: false, error: "Paste the pair code from Threat Guard first." };
  }

  const response = await fetch(`${API_BASE}/api/pair`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ pairCode: pairCode.trim() }),
  });

  const body = await readJson(response);
  if (!response.ok) {
    return {
      ok: false,
      error: body?.error ?? "Threat Guard rejected the pairing request.",
    };
  }

  await chrome.storage.local.set({
    [TOKEN_KEY]: body.token,
    [PAIRED_AT_KEY]: new Date().toISOString(),
  });

  return { ok: true };
}

async function getCredentials(origin, passcode) {
  if (!origin) {
    return { ok: false, error: "Missing website origin." };
  }

  const headers = passcode?.trim()
    ? { "X-Threat-Guard-Vault-Passcode": passcode.trim() }
    : undefined;

  const response = await authenticatedRequest(`/api/credentials?origin=${encodeURIComponent(origin)}`, {
    headers,
  });

  if (!response.ok) {
    return response;
  }

  return {
    ok: true,
    credentials: response.body.credentials ?? [],
  };
}

async function hasCredentials(origin) {
  if (!origin) {
    return { ok: false, error: "Missing website origin." };
  }

  const response = await authenticatedRequest(
    `/api/credentials/availability?origin=${encodeURIComponent(origin)}`,
  );

  if (!response.ok) {
    return response;
  }

  return {
    ok: true,
    hasCredentials: Boolean(response.body.hasCredentials),
  };
}

async function saveCredential(payload) {
  if (!payload?.origin || !payload?.password) {
    return { ok: false, error: "Missing credential fields." };
  }

  const response = await authenticatedRequest("/api/credentials", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    return response;
  }

  return { ok: true, credential: response.body.credential };
}

async function authenticatedRequest(path, init = {}) {
  const stored = await chrome.storage.local.get([TOKEN_KEY]);
  const token = stored[TOKEN_KEY];

  if (!token) {
    return {
      ok: false,
      error: "This extension is not paired with Threat Guard yet.",
    };
  }

  const headers = new Headers(init.headers || {});
  headers.set("Authorization", `Bearer ${token}`);

  const response = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers,
  });

  const body = await readJson(response);
  if (!response.ok) {
    return {
      ok: false,
      error: body?.error ?? "Threat Guard returned an unexpected error.",
    };
  }

  return { ok: true, body };
}

async function pingDesktop() {
  try {
    const response = await fetch(`${API_BASE}/health`);
    return response.ok;
  } catch {
    return false;
  }
}

async function readJson(response) {
  try {
    return await response.json();
  } catch {
    return null;
  }
}
