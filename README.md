# Threat Guard

Threat Guard is a Windows-first desktop security workspace built with Tauri, Rust, React, and TypeScript. It monitors running processes and startup persistence, records security events, explains activity through AI, scans suspicious links, and includes a local password manager with browser autofill.

## Project Structure

```text
personal_soc/
|- apps/
|  |- desktop-ui/                 React + TypeScript frontend (Vite)
|  `- tauri-shell/
|     `- src-tauri/               Tauri 2 shell and Rust commands
|- crates/
|  |- ai-explainer/               AI client and prompt/context helpers
|  |- monitor-core/               Monitoring, scoring, rules, SQLite persistence
|  `- shared-types/               Shared Rust models
|- extensions/
|  `- chrome-threat-guard/        Chrome and Edge password bridge extension
|- package.json
`- README.md
```

## Prerequisites

| Tool | Version |
| ---- | ------- |
| Windows | 10 or 11 |
| Rust | 1.77+ |
| Node.js | 18+ |
| npm | 9+ |
| Tauri CLI | v2 |

Install the Tauri CLI with:

```powershell
cargo install tauri-cli --version "^2"
```

## Quick Start

### 1. Clone the repo

```powershell
git clone <repo-url>
cd personal_soc
```

### 2. Install dependencies

```powershell
npm install
npm --prefix apps/desktop-ui install
```

### 3. Optional: configure API keys

Threat Guard can run without build-time keys, but AI features and VirusTotal-backed link scanning need keys configured either at build time or later in Settings.

```powershell
Copy-Item apps/tauri-shell/src-tauri/.env.example apps/tauri-shell/src-tauri/.env
```

Example:

```env
GROQ_API_KEY=your_groq_key_here
VIRUSTOTAL_API_KEY=your_virustotal_key_here
```

Notes:
- `apps/tauri-shell/src-tauri/.env` is gitignored.
- `build.rs` reads that file and bakes those keys into the local desktop build.
- You can also add or override the Groq and VirusTotal keys later from the Settings page.

### 4. Run the app in development

```powershell
cargo tauri dev
```

The frontend dev server runs at `http://localhost:43125`.

## Useful Commands

From the repo root:

```powershell
npm run typecheck
npm run build
cargo check -p threat-guard
```

## Current Features

### Core Monitoring

- Dashboard with health score, suspicious-process counts, startup-change counts, and recent alerts
- Live process inventory with risk scoring, signing/path context, and process detail pages
- Startup entry review and removal workflows
- Unified events timeline for process activity, alerts, startup changes, and user actions
- Alerts page with severity triage, status actions, and password-health alerts

### AI Assistant

- Floating Threat Guard assistant available across the app instead of a dedicated assistant tab
- Page-aware prompt suggestions based on the current screen
- Password-health assistant warnings when weak or reused passwords are found

### Security Tools

- Phishing detector page for reviewing suspicious message content
- Malicious link detector for URLs, domains, and IP addresses
- VirusTotal-backed reputation lookups when a VirusTotal API key is configured
- Local heuristic fallback when VirusTotal is unavailable
- Recent scan history with clear-history control

### Password Manager

- Local encrypted credential vault stored on the device
- 6-digit Threat Guard passcode for vault access
- Add, edit, reveal, copy, delete, lock, and unlock saved credentials
- Password strength checker with Have I Been Pwned range lookups
- Weak-password, reused-password, and compromised-password review signals
- Alerts-tab warning when saved passwords appear in known breaches

### Browser Autofill Bridge

- Included Chrome and Edge extension in `extensions/chrome-threat-guard`
- Save login prompts from supported password forms
- Autofill after Threat Guard passcode confirmation
- Pairing code flow between the desktop app and browser extension

## Browser Extension Setup

1. Open `chrome://extensions` or `edge://extensions`
2. Turn on Developer mode
3. Click Load unpacked
4. Select `extensions/chrome-threat-guard`
5. Open Threat Guard and go to Password Manager
6. Copy the pair code from the Browser Autofill Bridge card
7. Open the extension popup, paste the code, and connect

The extension stores only its pairing token in browser storage. Saved credentials stay in the Threat Guard desktop vault.

## Data and Security Notes

- Threat Guard stores app data in the Tauri app-data directory, not inside the repo.
- The main local database is `psa.db` in the app-data folder.
- Saved credential payloads are protected with Windows DPAPI.
- The Threat Guard vault passcode is stored as a salted hash, not plaintext.
- Browser autofill requires a Threat Guard passcode confirmation before credentials are returned.
- If you upload built binaries created from a local `.env`, the compiled app may contain baked API keys.

## Detection Rules

| Rule | Weight | Description |
| ---- | ------ | ----------- |
| `unsigned_in_user_writable_dir` | 40 | Unsigned executable from AppData, Temp, or Downloads |
| `powershell_spawned_by_office` | 60 | PowerShell launched by an Office process |
| `cmd_spawned_by_script_host` | 55 | `cmd.exe` launched by `wscript`, `cscript`, or `mshta` |
| `process_name_masquerade` | 70 | System-looking binary name running from a non-system path |
| `suspicious_parent_child_chain` | 45 | Suspicious shell or execution chain |
| `exe_in_temp_dir` | 25 | Executable running from `%TEMP%` |
| `high_risk_path_category` | 20 | Executable in a higher-risk user path |

Risk score `>= 40` is treated as at-risk. Risk score `>= 70` is treated as high severity.

## Architecture Notes

- Everything runs locally. There is no required backend server.
- The desktop shell is Tauri 2, the frontend is Vite + React, and the backend command layer is Rust.
- TypeScript invoke parameters use camelCase and map to Rust snake_case handlers through Tauri.
- The layout refreshes core overview, alert, and startup data every 15 seconds and process summaries every 30 seconds.

## Current Limitations

- Windows is the primary supported platform.
- The password vault currently depends on Windows DPAPI protection.
- The included browser extension targets Chromium browsers only.
- The extension currently autofills the first matching account for a site rather than showing an account picker.
- Heuristic process scoring is not a substitute for full malware analysis.
