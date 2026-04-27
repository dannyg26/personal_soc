import { useEffect, useState } from "react";
import {
  AlertTriangle,
  Copy,
  Eye,
  EyeOff,
  Globe,
  Key,
  Lock,
  Pencil,
  RefreshCw,
  ShieldCheck,
  Trash2,
  Unlock,
} from "lucide-react";
import {
  checkPassword,
  deletePasswordCredential,
  getBrowserExtensionStatus,
  getPasswordCredentialSecret,
  getPasswordVaultRiskSummary,
  getPasswordVaultStatus,
  listPasswordCredentials,
  lockPasswordVault,
  resetBrowserExtensionPairing,
  savePasswordCredential,
  setPasswordVaultPasscode,
  updatePasswordCredential,
  unlockPasswordVault,
} from "@/lib/invoke";
import type {
  BrowserExtensionStatus,
  PasswordCheckResult,
  PasswordVaultRiskSummary,
  PasswordVaultStatus,
  StoredCredential,
} from "@/types";
import {
  useAssistantSignal,
  type AssistantSignal,
} from "@/components/AssistantSignalContext";

const STRENGTH_META: Record<
  PasswordCheckResult["strength_label"],
  { color: string; progressScale: number }
> = {
  "Very Weak": { color: "var(--color-red)", progressScale: 0.22 },
  Weak: { color: "var(--color-orange)", progressScale: 0.4 },
  Moderate: { color: "var(--color-yellow)", progressScale: 0.62 },
  Strong: { color: "var(--color-blue)", progressScale: 0.82 },
  "Very Strong": { color: "var(--color-green)", progressScale: 1 },
};

const PASSWORD_MANAGER_SIGNAL_PATH = "/password-manager";

function formatRiskIssue(count: number, descriptor: string) {
  return `${count} saved password${count === 1 ? "" : "s"} ${
    count === 1 ? "is" : "are"
  } ${descriptor}`;
}

function buildRiskAlertMessage(summary: PasswordVaultRiskSummary) {
  const issues: string[] = [];

  if (summary.weak_count > 0) {
    issues.push(formatRiskIssue(summary.weak_count, "weak"));
  }

  if (summary.reused_count > 0) {
    issues.push(formatRiskIssue(summary.reused_count, "reused"));
  }

  if (issues.length === 0) {
    return "Threat Guard has not found any weak or reused saved passwords.";
  }

  return `Threat Guard found ${issues.join(
    " and ",
  )}. Change those passwords soon to reduce account risk.`;
}

function buildRiskCaption(summary: PasswordVaultRiskSummary) {
  if (!summary.has_alerts) {
    return "No weak or reused saved passwords detected.";
  }

  const labels: string[] = [];

  if (summary.weak_count > 0) {
    labels.push(`${summary.weak_count} weak`);
  }

  if (summary.reused_count > 0) {
    labels.push(`${summary.reused_count} reused`);
  }

  return `${labels.join(", ")}. Change them soon.`;
}

function buildAssistantSignal(summary: PasswordVaultRiskSummary): AssistantSignal {
  let title = "Review saved passwords";
  if (summary.weak_count > 0 && summary.reused_count > 0) {
    title = "Weak and reused passwords found";
  } else if (summary.weak_count > 0) {
    title = "Weak passwords found";
  } else if (summary.reused_count > 0) {
    title = "Reused passwords found";
  }

  return {
    path: PASSWORD_MANAGER_SIGNAL_PATH,
    severity: "warning",
    title,
    message: buildRiskAlertMessage(summary),
    badgeCount: summary.at_risk_count,
    prompts: [
      "Why is password reuse risky?",
      "How do I know which saved passwords to change first?",
      "What should I do after finding weak passwords?",
    ],
  };
}

export default function PasswordManagerPage() {
  const { setSignal, clearSignal } = useAssistantSignal();
  const [site, setSite] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [vault, setVault] = useState<StoredCredential[]>([]);
  const [vaultLoading, setVaultLoading] = useState(true);
  const [vaultError, setVaultError] = useState<string | null>(null);
  const [savingCredential, setSavingCredential] = useState(false);
  const [vaultStatus, setVaultStatus] = useState<PasswordVaultStatus | null>(null);
  const [setupPasscode, setSetupPasscode] = useState("");
  const [confirmPasscode, setConfirmPasscode] = useState("");
  const [unlockPasscode, setUnlockPasscode] = useState("");
  const [savingPasscode, setSavingPasscode] = useState(false);
  const [unlockingVault, setUnlockingVault] = useState(false);
  const [lockingVault, setLockingVault] = useState(false);
  const [credentialActionId, setCredentialActionId] = useState<string | null>(null);
  const [editingCredential, setEditingCredential] = useState<StoredCredential | null>(null);
  const [editSite, setEditSite] = useState("");
  const [editUsername, setEditUsername] = useState("");
  const [editPassword, setEditPassword] = useState("");
  const [passwordSecrets, setPasswordSecrets] = useState<Record<string, string>>({});

  const [bridgeStatus, setBridgeStatus] = useState<BrowserExtensionStatus | null>(null);
  const [bridgeError, setBridgeError] = useState<string | null>(null);
  const [resettingPairing, setResettingPairing] = useState(false);
  const [copiedPairCode, setCopiedPairCode] = useState(false);

  const [checkPasswordValue, setCheckPasswordValue] = useState("");
  const [analysis, setAnalysis] = useState<PasswordCheckResult | null>(null);
  const [analysisError, setAnalysisError] = useState<string | null>(null);
  const [analysisLoading, setAnalysisLoading] = useState(false);
  const [vaultRiskSummary, setVaultRiskSummary] = useState<PasswordVaultRiskSummary | null>(null);

  const [visiblePasswords, setVisiblePasswords] = useState<string[]>([]);

  useEffect(() => {
    void initializePage();
  }, []);

  useEffect(() => {
    return () => clearSignal(PASSWORD_MANAGER_SIGNAL_PATH);
  }, [clearSignal]);

  useEffect(() => {
    const interval = window.setInterval(() => {
      void refreshBridge();
      void refreshVaultRiskSummary();
      if (vaultStatus?.unlocked) {
        void refreshVault(false);
      }
    }, 5000);

    return () => window.clearInterval(interval);
  }, [vaultStatus?.unlocked]);

  const resetAddCredentialForm = () => {
    setSite("");
    setUsername("");
    setPassword("");
  };

  const resetEditForm = () => {
    setEditingCredential(null);
    setEditSite("");
    setEditUsername("");
    setEditPassword("");
  };

  const clearCachedCredentialSecret = (credentialId: string) => {
    setVisiblePasswords((previous) => previous.filter((id) => id !== credentialId));
    setPasswordSecrets((previous) => {
      const updated = { ...previous };
      delete updated[credentialId];
      return updated;
    });
  };

  const clearUnlockedVaultState = () => {
    setVault([]);
    setVisiblePasswords([]);
    setPasswordSecrets({});
    resetAddCredentialForm();
    resetEditForm();
  };

  const isVaultProtectionError = (message: string) => {
    const lowered = message.toLowerCase();
    return lowered.includes("passcode") || lowered.includes("password vault");
  };

  const isSixDigitPasscode = (value: string) => /^\d{6}$/.test(value.trim());

  const initializePage = async () => {
    setVaultLoading(true);
    await Promise.all([refreshBridge(), refreshVaultStatus(), refreshVaultRiskSummary()]);
  };

  const refreshVaultStatus = async () => {
    try {
      setVaultError(null);
      const status = await getPasswordVaultStatus();
      setVaultStatus(status);

      if (status.unlocked) {
        await refreshVault(false);
        return;
      }

      clearUnlockedVaultState();
    } catch (error) {
      setVaultError(
        error instanceof Error
          ? error.message
          : "Failed to check whether the credential vault is locked.",
      );
    } finally {
      setVaultLoading(false);
    }
  };

  const refreshVault = async (showSpinner = false) => {
    try {
      if (showSpinner) {
        setVaultLoading(true);
      }
      setVaultError(null);
      const credentials = await listPasswordCredentials();
      setVault(credentials);
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Failed to load the saved credential vault.";

      if (isVaultProtectionError(message)) {
        void refreshVaultStatus();
        clearUnlockedVaultState();
        setVaultError(null);
      } else {
        setVaultError(message);
      }
    } finally {
      setVaultLoading(false);
    }
  };

  const refreshBridge = async () => {
    try {
      setBridgeError(null);
      const status = await getBrowserExtensionStatus();
      setBridgeStatus(status);
    } catch (error) {
      setBridgeError(
        error instanceof Error ? error.message : "Failed to load the browser extension status.",
      );
    }
  };

  const refreshVaultRiskSummary = async () => {
    try {
      const summary = await getPasswordVaultRiskSummary();
      setVaultRiskSummary(summary);

      if (summary.has_alerts) {
        setSignal(buildAssistantSignal(summary));
      } else {
        clearSignal(PASSWORD_MANAGER_SIGNAL_PATH);
      }
    } catch (error) {
      console.error("Failed to refresh password vault risk summary:", error);
      setVaultRiskSummary(null);
      clearSignal(PASSWORD_MANAGER_SIGNAL_PATH);
    }
  };

  const handleSaveCredential = async () => {
    if (!site.trim() || !username.trim() || !password) {
      return;
    }

    setSavingCredential(true);
    setVaultError(null);

    try {
      await savePasswordCredential(site.trim(), username.trim(), password);
      resetAddCredentialForm();
      if (vaultStatus?.unlocked) {
        await refreshVault();
      }
      await refreshVaultRiskSummary();
    } catch (error) {
      setVaultError(
        error instanceof Error ? error.message : "Threat Guard could not save that credential.",
      );
    } finally {
      setSavingCredential(false);
    }
  };

  const handleStartEdit = async (credential: StoredCredential) => {
    setVaultError(null);
    setEditingCredential(credential);
    setEditSite(credential.origin);
    setEditUsername(credential.username);
    setEditPassword("");
  };

  const handleCancelEdit = () => {
    setVaultError(null);
    resetEditForm();
  };

  const handleSaveEditedCredential = async () => {
    if (!editingCredential || !editSite.trim() || !editUsername.trim()) {
      return;
    }

    setCredentialActionId(editingCredential.id);
    setVaultError(null);

    try {
      await updatePasswordCredential(
        editingCredential.id,
        editSite.trim(),
        editUsername.trim(),
        editPassword.trim() ? editPassword : null,
      );
      clearCachedCredentialSecret(editingCredential.id);
      resetEditForm();
      if (vaultStatus?.unlocked) {
        await refreshVault();
      }
      await refreshVaultRiskSummary();
    } catch (error) {
      setVaultError(
        error instanceof Error ? error.message : "Threat Guard could not update that credential.",
      );
    } finally {
      setCredentialActionId(null);
    }
  };

  const handleDeleteCredential = async (credentialId: string) => {
    try {
      setCredentialActionId(credentialId);
      await deletePasswordCredential(credentialId);
      setVault((previous) => previous.filter((credential) => credential.id !== credentialId));
      clearCachedCredentialSecret(credentialId);
      if (editingCredential?.id === credentialId) {
        resetEditForm();
      }
      await refreshVaultRiskSummary();
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Threat Guard could not delete that credential.";
      if (isVaultProtectionError(message)) {
        void refreshVaultStatus();
        clearUnlockedVaultState();
      }
      setVaultError(message);
    } finally {
      setCredentialActionId(null);
    }
  };

  const handleUnlockVault = async () => {
    if (!isSixDigitPasscode(unlockPasscode)) {
      setVaultError("Enter the 6-digit Threat Guard passcode you created for this vault.");
      return;
    }

    setUnlockingVault(true);
    setVaultError(null);

    try {
      const status = await unlockPasswordVault(unlockPasscode.trim());
      setVaultStatus(status);
      setUnlockPasscode("");
      await refreshVault(true);
      await refreshVaultRiskSummary();
    } catch (error) {
      setVaultError(
        error instanceof Error
          ? error.message
          : "Threat Guard could not unlock the vault with that passcode.",
      );
    } finally {
      setUnlockingVault(false);
      setVaultLoading(false);
    }
  };

  const handleCreatePasscode = async () => {
    if (!isSixDigitPasscode(setupPasscode)) {
      setVaultError("Create a 6-digit Threat Guard passcode for this vault.");
      return;
    }

    if (setupPasscode.trim() !== confirmPasscode.trim()) {
      setVaultError("The two passcode entries did not match.");
      return;
    }

    setSavingPasscode(true);
    setVaultError(null);

    try {
      const status = await setPasswordVaultPasscode(setupPasscode.trim());
      setVaultStatus(status);
      setSetupPasscode("");
      setConfirmPasscode("");
      await refreshVault(true);
      await refreshVaultRiskSummary();
    } catch (error) {
      setVaultError(
        error instanceof Error
          ? error.message
          : "Threat Guard could not save that vault passcode.",
      );
    } finally {
      setSavingPasscode(false);
    }
  };

  const handleLockVault = async () => {
    setLockingVault(true);
    setVaultError(null);

    try {
      const status = await lockPasswordVault();
      setVaultStatus(status);
      setUnlockPasscode("");
      clearUnlockedVaultState();
      await refreshVaultRiskSummary();
    } catch (error) {
      setVaultError(
        error instanceof Error ? error.message : "Threat Guard could not lock the credential vault.",
      );
    } finally {
      setLockingVault(false);
    }
  };

  const handleResetPairing = async () => {
    setResettingPairing(true);
    setBridgeError(null);

    try {
      const status = await resetBrowserExtensionPairing();
      setBridgeStatus(status);
    } catch (error) {
      setBridgeError(
        error instanceof Error ? error.message : "Threat Guard could not rotate the pairing code.",
      );
    } finally {
      setResettingPairing(false);
    }
  };

  const copyToClipboard = async (value: string, onSuccess?: () => void) => {
    try {
      await navigator.clipboard.writeText(value);
      onSuccess?.();
    } catch (error) {
      console.error("Failed to copy text:", error);
    }
  };

  const handleTogglePassword = async (credentialId: string) => {
    if (visiblePasswords.includes(credentialId)) {
      setVisiblePasswords((previous) => previous.filter((value) => value !== credentialId));
      setPasswordSecrets((previous) => {
        const updated = { ...previous };
        delete updated[credentialId];
        return updated;
      });
      return;
    }

    setCredentialActionId(credentialId);
    setVaultError(null);

    try {
      const secret = await getPasswordCredentialSecret(credentialId);
      setVaultStatus((previous) =>
        previous
          ? { ...previous, unlocked: true }
          : { configured: true, unlocked: true, unlock_window_seconds: 120 },
      );
      setPasswordSecrets((previous) => ({ ...previous, [credentialId]: secret.password }));
      setVisiblePasswords((previous) => [...previous, credentialId]);
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Threat Guard could not reveal that password.";
      if (isVaultProtectionError(message)) {
        void refreshVaultStatus();
        clearUnlockedVaultState();
      }
      setVaultError(message);
    } finally {
      setCredentialActionId(null);
    }
  };

  const handleCopyPassword = async (credentialId: string) => {
    setCredentialActionId(credentialId);
    setVaultError(null);

    try {
      const value =
        passwordSecrets[credentialId] ??
        (await getPasswordCredentialSecret(credentialId)).password;
      setVaultStatus((previous) =>
        previous
          ? { ...previous, unlocked: true }
          : { configured: true, unlocked: true, unlock_window_seconds: 120 },
      );
      await copyToClipboard(value);
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Threat Guard could not copy that password.";
      if (isVaultProtectionError(message)) {
        void refreshVaultStatus();
        clearUnlockedVaultState();
      }
      setVaultError(message);
    } finally {
      setCredentialActionId(null);
    }
  };

  const analyzePassword = async () => {
    if (!checkPasswordValue.trim()) {
      return;
    }

    setAnalysisLoading(true);
    setAnalysisError(null);

    try {
      const result = await checkPassword(checkPasswordValue);
      setAnalysis(result);
    } catch (error) {
      setAnalysisError(
        error instanceof Error ? error.message : "Password analysis failed.",
      );
    } finally {
      setAnalysisLoading(false);
    }
  };

  const analysisMeta = analysis
    ? STRENGTH_META[analysis.strength_label]
    : STRENGTH_META["Very Strong"];

  const extensionReady = Boolean(bridgeStatus?.running && bridgeStatus?.paired);
  const vaultConfigured = Boolean(vaultStatus?.configured);
  const vaultUnlocked = Boolean(vaultStatus?.unlocked);
  const unlockWindowMinutes = Math.max(
    1,
    Math.round((vaultStatus?.unlock_window_seconds ?? 120) / 60),
  );
  const passwordHealthLabel = vaultRiskSummary
    ? vaultRiskSummary.has_alerts
      ? "Needs Review"
      : "Looks Good"
    : "Checking";
  const passwordHealthStyle = vaultRiskSummary
    ? vaultRiskSummary.has_alerts
      ? styles.lockedHeading
      : styles.secure
    : undefined;

  return (
    <div style={styles.container}>
      <h1 style={styles.title}>
        <Key size={20} /> Password Manager
      </h1>
      <p style={styles.subtitle}>
        Threat Guard keeps credentials in an encrypted local vault and protects access with a
        6-digit passcode that you create inside Password Manager.
      </p>

      <div style={styles.cardFull}>
        <div style={styles.statusRow}>
          <div>
            <p style={styles.muted}>Vault Access</p>
            <h2 style={vaultUnlocked ? styles.secure : styles.lockedHeading}>
              {vaultConfigured ? (vaultUnlocked ? "Unlocked" : "Locked") : "Setup Needed"}
            </h2>
          </div>
          <div>
            <p style={styles.muted}>Stored Credentials</p>
            <h2>
              {vaultUnlocked ? vault.length : vaultConfigured ? "Protected" : "Awaiting passcode"}
            </h2>
          </div>
          <div>
            <p style={styles.muted}>Password Health</p>
            <h2 style={passwordHealthStyle}>{passwordHealthLabel}</h2>
            <p style={styles.riskHeading}>
              {vaultRiskSummary
                ? buildRiskCaption(vaultRiskSummary)
                : "Checking saved password health..."}
            </p>
          </div>
        </div>
      </div>

      <div style={styles.grid}>
        <div style={styles.leftCol}>
          <div style={styles.cardBig}>
            <div style={styles.cardHeader}>
              <ShieldCheck size={16} color="var(--color-blue)" />
              <h3>Password Strength Checker</h3>
            </div>
            <p style={styles.muted}>
              Uses the imported entropy model plus Have I Been Pwned range lookups.
            </p>

            <div style={styles.inputRow}>
              <input
                value={checkPasswordValue}
                onChange={(event) => setCheckPasswordValue(event.target.value)}
                onKeyDown={(event) => event.key === "Enter" && void analyzePassword()}
                placeholder="Enter password..."
                className="input"
                style={{ flex: 1 }}
                type="password"
              />
              <button
                className="btn btn-primary"
                onClick={() => void analyzePassword()}
                disabled={analysisLoading}
              >
                {analysisLoading ? "Analyzing..." : "Analyze"}
              </button>
            </div>

            {analysisError && (
              <div style={styles.errorBox}>
                <AlertTriangle size={14} color="var(--color-red)" />
                <span>{analysisError}</span>
              </div>
            )}

            {analysis && (
              <div style={styles.analysisPanel}>
                <div style={styles.analysisHeader}>
                  <div>
                    <p style={styles.muted}>Strength</p>
                    <h3 style={{ color: analysisMeta.color }}>{analysis.strength_label}</h3>
                  </div>
                  <div style={styles.analysisBadge}>{analysis.entropy.toFixed(1)} bits</div>
                </div>

                <div style={styles.barWrap}>
                  <div
                    style={{
                      ...styles.barFill,
                      width: `${Math.min(analysisMeta.progressScale * 100, 100)}%`,
                      background: analysisMeta.color,
                    }}
                  />
                </div>

                <div style={styles.analysisStats}>
                  <div style={styles.analysisStat}>
                    <span style={styles.analysisLabel}>Time to crack</span>
                    <span style={styles.analysisValue}>{analysis.crack_time_display}</span>
                  </div>
                  <div style={styles.analysisStat}>
                    <span style={styles.analysisLabel}>Breach status</span>
                    <span
                      style={{
                        ...styles.analysisValue,
                        color:
                          analysis.breach_count > 0
                            ? "var(--color-red)"
                            : "var(--color-green)",
                      }}
                    >
                      {analysis.breach_count > 0
                        ? `Found ${analysis.breach_count.toLocaleString()} times`
                        : "Not found in known breaches"}
                    </span>
                  </div>
                </div>
              </div>
            )}
          </div>

          <div style={styles.card}>
            <div style={styles.cardHeader}>
              <Globe size={16} color="var(--color-blue)" />
              <h3>Browser Autofill Bridge</h3>
            </div>
            <p style={styles.muted}>
              Chrome and Edge can pair with Threat Guard over localhost and save web logins into
              this encrypted vault. Autofill now asks for your Threat Guard passcode every time a
              saved login is approved on a website.
            </p>

            {bridgeError && (
              <div style={styles.errorBox}>
                <AlertTriangle size={14} color="var(--color-red)" />
                <span>{bridgeError}</span>
              </div>
            )}

            {bridgeStatus && (
              <>
                <div style={styles.bridgeStatusRow}>
                  <span style={styles.bridgePill}>
                    Bridge {bridgeStatus.running ? "running" : "offline"}
                  </span>
                  <span
                    style={{
                      ...styles.bridgePill,
                      borderColor: extensionReady
                        ? "rgba(74,222,128,0.3)"
                        : "rgba(96,165,250,0.25)",
                      color: extensionReady
                        ? "var(--color-green)"
                        : "var(--color-blue)",
                    }}
                  >
                    {bridgeStatus.paired ? "Extension paired" : "Not paired yet"}
                  </span>
                </div>

                <div style={styles.codePanel}>
                  <p style={styles.codeLabel}>Pair Code</p>
                  <div style={styles.codeValue}>{bridgeStatus.pair_code}</div>
                  <p style={styles.smallMuted}>
                    Threat Guard is listening on `127.0.0.1:{bridgeStatus.port}` for the browser
                    extension.
                  </p>
                </div>

                <div style={styles.actions}>
                  <button
                    style={styles.iconAction}
                    onClick={() =>
                      void copyToClipboard(bridgeStatus.pair_code, () => {
                        setCopiedPairCode(true);
                        window.setTimeout(() => setCopiedPairCode(false), 1800);
                      })
                    }
                  >
                    <Copy size={16} />
                    {copiedPairCode ? "Copied" : "Copy Code"}
                  </button>

                  <button
                    style={styles.iconAction}
                    onClick={() => void handleResetPairing()}
                    disabled={resettingPairing}
                  >
                    <RefreshCw size={16} />
                    {resettingPairing ? "Rotating..." : "Rotate Pairing"}
                  </button>
                </div>

                <div style={styles.setupList}>
                  <p style={styles.setupStep}>
                    1. Open `chrome://extensions` or `edge://extensions`, enable Developer mode,
                    and choose <strong>Load unpacked</strong>.
                  </p>
                  <p style={styles.setupStep}>
                    2. Select the `extensions/chrome-threat-guard` folder from this repo.
                  </p>
                  <p style={styles.setupStep}>
                    3. Click the extension icon, paste the pair code above, and connect.
                  </p>
                  <p style={styles.setupStep}>
                    4. Sign into a website. The extension will ask whether you want to save the
                    login, and every future autofill on that site will ask for your Threat Guard
                    passcode before filling.
                  </p>
                </div>

                {bridgeStatus.last_paired_at && (
                  <p style={styles.smallMuted}>
                    Last paired {new Date(bridgeStatus.last_paired_at).toLocaleString()}
                  </p>
                )}
              </>
            )}
          </div>

          <div style={styles.card}>
            <div style={styles.cardHeader}>
              <Pencil size={16} color="var(--color-blue)" />
              <h3>Add Credential</h3>
            </div>
            <p style={styles.muted}>
              Save a website manually if you want it available before the extension captures it.
            </p>

            <div style={styles.form}>
              <input
                value={site}
                onChange={(event) => setSite(event.target.value)}
                placeholder="Website or URL (example: youtube.com)"
                className="input"
              />
              <input
                value={username}
                onChange={(event) => setUsername(event.target.value)}
                placeholder="Username or email"
                className="input"
              />
              <input
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                placeholder="Password"
                type="password"
                className="input"
              />
              <button
                className="btn btn-primary"
                onClick={() => void handleSaveCredential()}
                disabled={savingCredential}
              >
                {savingCredential ? "Saving..." : "Add Credential"}
              </button>
            </div>
          </div>
        </div>

        <div style={styles.vaultPanel}>
          <div style={styles.vaultHeader}>
            <div>
              <h3>Saved Credentials</h3>
              <p style={styles.muted}>
                Encrypted on this device and shared with the browser extension only after autofill
                is confirmed with your Threat Guard passcode.
              </p>
            </div>
            <div style={styles.actions}>
              {vaultConfigured && vaultUnlocked && (
                <button
                  className="btn btn-ghost"
                  onClick={() => void refreshVault(true)}
                  disabled={vaultLoading}
                >
                  <RefreshCw size={14} />
                  Refresh
                </button>
              )}
              {vaultConfigured && vaultUnlocked && (
                <button
                  className="btn btn-ghost"
                  onClick={() => void handleLockVault()}
                  disabled={lockingVault}
                >
                  <Lock size={14} />
                  {lockingVault ? "Locking..." : "Lock Vault"}
                </button>
              )}
            </div>
          </div>

          {vaultError && (
            <div style={styles.errorBox}>
              <AlertTriangle size={14} color="var(--color-red)" />
              <span>{vaultError}</span>
            </div>
          )}

          {vaultLoading && <p style={styles.muted}>Loading vault status...</p>}

          {!vaultLoading && !vaultConfigured && (
            <div style={styles.lockedPanel}>
              <Lock size={20} color="var(--color-blue)" />
              <div style={styles.lockedCopy}>
                <p style={styles.lockedTitle}>Create your vault passcode</p>
                <p style={styles.muted}>
                  Choose a 6-digit Threat Guard passcode. You will use it to open saved credentials
                  here and to approve every browser autofill request.
                </p>
                <div style={styles.passcodeForm}>
                  <input
                    value={setupPasscode}
                    onChange={(event) => setSetupPasscode(event.target.value.replace(/\D/g, "").slice(0, 6))}
                    placeholder="Create 6-digit passcode"
                    className="input"
                    inputMode="numeric"
                    maxLength={6}
                  />
                  <input
                    value={confirmPasscode}
                    onChange={(event) => setConfirmPasscode(event.target.value.replace(/\D/g, "").slice(0, 6))}
                    onKeyDown={(event) => event.key === "Enter" && void handleCreatePasscode()}
                    placeholder="Confirm passcode"
                    className="input"
                    inputMode="numeric"
                    maxLength={6}
                  />
                  <button
                    className="btn btn-primary"
                    onClick={() => void handleCreatePasscode()}
                    disabled={savingPasscode}
                  >
                    {savingPasscode ? "Saving..." : "Create Passcode"}
                  </button>
                </div>
              </div>
            </div>
          )}

          {!vaultLoading && vaultConfigured && !vaultUnlocked && (
            <div style={styles.lockedPanel}>
              <Unlock size={20} color="var(--color-blue)" />
              <div style={styles.lockedCopy}>
                <p style={styles.lockedTitle}>Unlock with your Threat Guard passcode</p>
                <p style={styles.muted}>
                  Enter the 6-digit passcode you created for this vault. Threat Guard keeps the
                  vault open for about {unlockWindowMinutes} minute
                  {unlockWindowMinutes === 1 ? "" : "s"} so a few actions in a row still feel
                  smooth.
                </p>
                <div style={styles.passcodeForm}>
                  <input
                    value={unlockPasscode}
                    onChange={(event) => setUnlockPasscode(event.target.value.replace(/\D/g, "").slice(0, 6))}
                    onKeyDown={(event) => event.key === "Enter" && void handleUnlockVault()}
                    placeholder="Enter 6-digit passcode"
                    className="input"
                    inputMode="numeric"
                    maxLength={6}
                  />
                  <button
                    className="btn btn-primary"
                    onClick={() => void handleUnlockVault()}
                    disabled={unlockingVault}
                  >
                    {unlockingVault ? "Unlocking..." : "Unlock Vault"}
                  </button>
                </div>
              </div>
            </div>
          )}

          {!vaultLoading && vaultUnlocked && vault.length === 0 && (
            <p style={styles.muted}>
              No credentials saved yet. Add one manually or pair the Chrome/Edge extension and sign
              into a website.
            </p>
          )}

          {vault.map((item) => {
            const visible = visiblePasswords.includes(item.id);
            const sourceLabel =
              item.source === "browser_extension" ? "Browser" : item.source === "manual" ? "Manual" : item.source;
            const visiblePassword = passwordSecrets[item.id] ?? "********";
            const credentialBusy = credentialActionId === item.id;
            const editingThisCredential = editingCredential?.id === item.id;

            return (
              <div key={item.id} style={styles.vaultItem}>
                <div style={styles.vaultContent}>
                  <div style={styles.vaultTitleRow}>
                    <p style={styles.vaultTitle}>{item.site_label}</p>
                    <span style={styles.sourceBadge}>{sourceLabel}</span>
                    {editingThisCredential && <span style={styles.editBadge}>Editing</span>}
                  </div>
                  <p style={styles.originText}>{item.origin}</p>
                  <p style={styles.usernameText}>{item.username}</p>
                  <p style={styles.passwordText}>{visible ? visiblePassword : "********"}</p>
                  <p style={styles.smallMuted}>
                    Updated {new Date(item.updated_at).toLocaleString()}
                  </p>
                </div>

                <div style={styles.actions}>
                  <button
                    className="btn btn-ghost"
                    onClick={() => void handleStartEdit(item)}
                    disabled={credentialBusy}
                  >
                    <Pencil size={14} />
                    Edit
                  </button>

                  <button
                    style={styles.iconBtn}
                    onClick={() => void handleTogglePassword(item.id)}
                    title={visible ? "Hide password" : "Show password"}
                    disabled={credentialBusy}
                  >
                    {visible ? <EyeOff size={16} /> : <Eye size={16} />}
                  </button>

                  <button
                    style={styles.iconBtn}
                    onClick={() => void handleCopyPassword(item.id)}
                    title="Copy password"
                    disabled={credentialBusy}
                  >
                    <Copy size={16} />
                  </button>

                  <button
                    className="btn btn-danger"
                    onClick={() => void handleDeleteCredential(item.id)}
                    disabled={credentialBusy}
                  >
                    <Trash2 size={14} />
                    Delete
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {editingCredential && (
        <div style={styles.modalScrim} onClick={handleCancelEdit}>
          <div style={styles.modalCard} onClick={(event) => event.stopPropagation()}>
            <div style={styles.modalHeader}>
              <div style={styles.cardHeader}>
                <Pencil size={16} color="var(--color-orange)" />
                <h3>Edit Saved Credential</h3>
              </div>
              <p style={styles.muted}>
                Update this saved login. Leave the password blank if you want to keep the current
                one.
              </p>
            </div>

            <div style={styles.modalBody}>
              <input
                value={editSite}
                onChange={(event) => setEditSite(event.target.value)}
                placeholder="Website or URL"
                className="input"
              />
              <input
                value={editUsername}
                onChange={(event) => setEditUsername(event.target.value)}
                placeholder="Username or email"
                className="input"
              />
              <input
                value={editPassword}
                onChange={(event) => setEditPassword(event.target.value)}
                onKeyDown={(event) =>
                  event.key === "Enter" && void handleSaveEditedCredential()
                }
                placeholder="Leave blank to keep current password"
                type="password"
                className="input"
              />
            </div>

            <div style={styles.modalActions}>
              <button className="btn btn-ghost" onClick={handleCancelEdit}>
                Cancel
              </button>
              <button
                className="btn btn-primary"
                onClick={() => void handleSaveEditedCredential()}
                disabled={credentialActionId === editingCredential.id}
              >
                {credentialActionId === editingCredential.id ? "Saving..." : "Save Changes"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

const styles: Record<string, React.CSSProperties> = {
  container: {
    height: "100%",
    display: "flex",
    flexDirection: "column",
    background:
      "radial-gradient(circle at top, rgba(255,140,0,0.05), transparent 60%)",
  },
  title: { fontSize: 22, fontWeight: 700 },
  subtitle: { color: "var(--text-muted)", fontSize: 12, marginBottom: 16, lineHeight: 1.6 },
  grid: {
    display: "grid",
    gridTemplateColumns: "1.15fr 1.85fr",
    gap: 20,
    flex: 1,
  },
  leftCol: {
    display: "flex",
    flexDirection: "column",
    gap: 20,
    height: "100%",
  },
  cardFull: {
    padding: 18,
    borderRadius: 12,
    border: "1px solid #48423B",
    background: "linear-gradient(145deg, #2A2520, #1F1B18)",
    marginBottom: 16,
  },
  card: {
    padding: 18,
    borderRadius: 12,
    border: "1px solid #48423B",
    background: "linear-gradient(145deg, #2A2520, #1F1B18)",
    display: "flex",
    flexDirection: "column",
    gap: 12,
  },
  cardBig: {
    padding: 18,
    borderRadius: 12,
    border: "1px solid #48423B",
    background: "linear-gradient(145deg, #2A2520, #1F1B18)",
    flex: 1,
    display: "flex",
    flexDirection: "column",
    gap: 12,
  },
  vaultPanel: {
    padding: 18,
    borderRadius: 12,
    border: "1px solid #48423B",
    background: "linear-gradient(145deg, #2A2520, #1F1B18)",
    display: "flex",
    flexDirection: "column",
    gap: 12,
  },
  vaultHeader: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "flex-start",
    gap: 12,
  },
  vaultItem: {
    padding: 14,
    border: "1px solid #3A332D",
    borderRadius: 10,
    background: "linear-gradient(145deg, #25201C, #1A1714)",
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    gap: 16,
  },
  vaultContent: {
    display: "flex",
    flexDirection: "column",
    gap: 4,
    minWidth: 0,
  },
  vaultTitleRow: {
    display: "flex",
    alignItems: "center",
    gap: 8,
    flexWrap: "wrap",
  },
  vaultTitle: {
    fontWeight: 600,
    fontSize: 14,
    margin: 0,
  },
  sourceBadge: {
    padding: "3px 8px",
    borderRadius: 999,
    border: "1px solid rgba(96,165,250,0.2)",
    background: "rgba(96,165,250,0.08)",
    color: "var(--color-blue)",
    fontSize: 11,
    fontWeight: 600,
  },
  editBadge: {
    padding: "3px 8px",
    borderRadius: 999,
    border: "1px solid rgba(251,146,60,0.22)",
    background: "rgba(251,146,60,0.08)",
    color: "var(--color-orange)",
    fontSize: 11,
    fontWeight: 700,
  },
  originText: {
    color: "var(--text-muted)",
    fontSize: 12,
    margin: 0,
    wordBreak: "break-all",
  },
  usernameText: {
    color: "var(--text-primary)",
    fontSize: 13,
    margin: 0,
  },
  passwordText: {
    margin: 0,
    fontFamily: "ui-monospace, SFMono-Regular, Consolas, monospace",
    letterSpacing: "0.04em",
  },
  actions: { display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" },
  iconBtn: {
    background: "#2A2520",
    border: "1px solid #48423B",
    borderRadius: 8,
    padding: "6px 8px",
    cursor: "pointer",
    color: "#F7F0E6",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
  },
  iconAction: {
    background: "#2A2520",
    border: "1px solid #48423B",
    borderRadius: 8,
    padding: "8px 12px",
    cursor: "pointer",
    color: "#F7F0E6",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    gap: 8,
  },
  form: { display: "flex", flexDirection: "column", gap: 10 },
  inputRow: { display: "flex", gap: 10 },
  statusRow: { display: "flex", justifyContent: "space-between", gap: 12 },
  cardHeader: { display: "flex", alignItems: "center", gap: 8 },
  barWrap: {
    width: "100%",
    height: 8,
    background: "#333",
    borderRadius: 999,
    overflow: "hidden",
  },
  barFill: {
    height: "100%",
    borderRadius: 999,
    transition: "width 0.3s ease",
  },
  muted: { color: "var(--text-muted)", fontSize: 12, margin: 0 },
  smallMuted: { color: "var(--text-muted)", fontSize: 11, margin: 0, lineHeight: 1.5 },
  secure: {
    color: "#4ADE80",
    textShadow: "0 0 10px rgba(74,222,128,0.6)",
  },
  lockedHeading: {
    color: "var(--color-orange)",
  },
  riskHeading: {
    color: "var(--text-muted)",
    fontSize: 11,
    margin: "4px 0 0",
    lineHeight: 1.5,
    maxWidth: 220,
  },
  analysisPanel: {
    marginTop: 4,
    padding: 14,
    borderRadius: 12,
    border: "1px solid #3A332D",
    background: "linear-gradient(145deg, #25201C, #1A1714)",
    display: "flex",
    flexDirection: "column",
    gap: 12,
  },
  analysisHeader: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    gap: 12,
  },
  analysisBadge: {
    padding: "6px 10px",
    borderRadius: 999,
    border: "1px solid #48423B",
    background: "#2A2520",
    color: "var(--text-primary)",
    fontSize: 12,
    fontWeight: 600,
  },
  analysisStats: {
    display: "flex",
    flexDirection: "column",
    gap: 8,
  },
  analysisStat: {
    display: "flex",
    justifyContent: "space-between",
    gap: 12,
    alignItems: "center",
  },
  analysisLabel: {
    fontSize: 12,
    color: "var(--text-muted)",
  },
  analysisValue: {
    fontSize: 12,
    color: "var(--text-primary)",
    fontWeight: 600,
    textAlign: "right",
  },
  errorBox: {
    display: "flex",
    alignItems: "center",
    gap: 8,
    padding: "10px 12px",
    borderRadius: 10,
    border: "1px solid rgba(248,113,113,0.28)",
    background: "rgba(248,113,113,0.08)",
    color: "var(--text-primary)",
    fontSize: 12,
  },
  modalScrim: {
    position: "fixed",
    inset: 0,
    background: "rgba(15,23,42,0.48)",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    padding: 20,
    zIndex: 40,
  },
  modalCard: {
    width: "min(460px, calc(100vw - 32px))",
    borderRadius: 16,
    border: "1px solid #48423B",
    background: "linear-gradient(145deg, #2A2520, #1F1B18)",
    boxShadow: "0 24px 60px rgba(15,23,42,0.3)",
    display: "flex",
    flexDirection: "column",
    gap: 14,
    padding: 18,
  },
  modalHeader: {
    display: "flex",
    flexDirection: "column",
    gap: 8,
  },
  modalBody: {
    display: "flex",
    flexDirection: "column",
    gap: 10,
  },
  modalActions: {
    display: "flex",
    justifyContent: "flex-end",
    gap: 10,
    flexWrap: "wrap",
  },
  lockedPanel: {
    padding: 16,
    borderRadius: 12,
    border: "1px solid rgba(96,165,250,0.2)",
    background: "rgba(96,165,250,0.06)",
    display: "flex",
    gap: 12,
    alignItems: "flex-start",
  },
  lockedCopy: {
    display: "flex",
    flexDirection: "column",
    gap: 6,
  },
  passcodeForm: {
    display: "flex",
    flexDirection: "column",
    gap: 10,
    marginTop: 8,
    maxWidth: 280,
  },
  lockedTitle: {
    margin: 0,
    fontSize: 14,
    fontWeight: 600,
  },
  bridgeStatusRow: {
    display: "flex",
    gap: 10,
    flexWrap: "wrap",
  },
  bridgePill: {
    padding: "4px 10px",
    borderRadius: 999,
    border: "1px solid rgba(244,200,160,0.18)",
    background: "rgba(244,200,160,0.06)",
    color: "var(--text-secondary)",
    fontSize: 11,
    fontWeight: 600,
  },
  codePanel: {
    padding: 14,
    borderRadius: 12,
    border: "1px solid #3A332D",
    background: "linear-gradient(145deg, #25201C, #1A1714)",
    display: "flex",
    flexDirection: "column",
    gap: 6,
  },
  codeLabel: {
    margin: 0,
    fontSize: 11,
    color: "var(--text-muted)",
    textTransform: "uppercase",
    letterSpacing: "0.06em",
  },
  codeValue: {
    margin: 0,
    fontFamily: "ui-monospace, SFMono-Regular, Consolas, monospace",
    fontSize: 24,
    fontWeight: 700,
    letterSpacing: "0.08em",
    color: "var(--text-primary)",
  },
  setupList: {
    display: "flex",
    flexDirection: "column",
    gap: 8,
  },
  setupStep: {
    margin: 0,
    fontSize: 12,
    lineHeight: 1.6,
    color: "var(--text-secondary)",
  },
};
