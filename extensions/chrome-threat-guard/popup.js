const statusEl = document.getElementById("status");
const pairForm = document.getElementById("pair-form");
const pairCodeInput = document.getElementById("pair-code");
const messageEl = document.getElementById("message");
const forgetButton = document.getElementById("forget-button");

pairForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  setMessage("Connecting to Threat Guard...");

  const pairCode = pairCodeInput.value.trim();
  const result = await sendMessage({ type: "pair", pairCode });

  if (!result?.ok) {
    setMessage(result?.error || "Threat Guard rejected the pair code.");
    await refreshStatus();
    return;
  }

  pairCodeInput.value = "";
  setMessage("Browser extension paired successfully.");
  await refreshStatus();
});

forgetButton.addEventListener("click", async () => {
  await sendMessage({ type: "clear-pairing" });
  setMessage("Saved browser pairing cleared.");
  await refreshStatus();
});

void refreshStatus();

async function refreshStatus() {
  const status = await sendMessage({ type: "get-status" });
  if (!status?.ok) {
    statusEl.textContent = "Threat Guard status unavailable.";
    return;
  }

  if (!status.desktopReachable) {
    statusEl.textContent = "Desktop app not reachable. Start Threat Guard first.";
    return;
  }

  if (status.paired) {
    const pairedAt = status.pairedAt
      ? new Date(status.pairedAt).toLocaleString()
      : "unknown time";
    statusEl.textContent = `Connected to Threat Guard. Paired ${pairedAt}.`;
  } else {
    statusEl.textContent = "Desktop app found. Paste the pair code from Threat Guard to connect.";
  }
}

function setMessage(message) {
  messageEl.textContent = message;
}

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
