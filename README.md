# ThreatGuard — Personal Security Assistant

A Windows desktop security monitor that tracks running processes, startup persistence, and suspicious behaviour in real time, then explains findings through an AI-powered chat interface.

---

## Project Structure

```
personal-soc/
├── apps/
│   ├── desktop-ui/                  # React + TypeScript frontend (Vite)
│   └── tauri-shell/                 # Tauri 2 desktop shell + Rust commands
│       └── src-tauri/
│           ├── .env.example         # Copy to .env and add your key
│           └── build.rs             # Bakes GROQ_API_KEY into binary at compile time
├── crates/
│   ├── monitor-core/                # Process monitoring, rules engine, SQLite persistence
│   ├── ai-explainer/                # Groq AI client + context builder
│   └── shared-types/                # Shared Rust types (serde-serializable)
└── README.md
```

---

## Prerequisites

| Tool | Version | Install |
|------|---------|---------|
| Rust (stable) | 1.77+ | https://rustup.rs |
| Node.js | 18+ | https://nodejs.org |
| npm | 9+ | Bundled with Node.js |
| Tauri CLI v2 | latest | `cargo install tauri-cli --version "^2"` |
| Windows | 10 / 11 | Required (primary target) |

---

## Getting Started

### 1. Clone the repo

```bash
git clone <repo-url>
cd personal-soc
```

### 2. Create your `.env` file

The AI assistant requires a Groq API key. You will receive this key separately.

```bash
cd apps/tauri-shell/src-tauri
cp .env.example .env
```

Open `.env` and replace `your_key_here` with the key you were given:

```env
GROQ_API_KEY=gsk_xxxxxxxxxxxxxxxxxxxxxxxx
```

> **Important:** Never commit `.env` — it is already listed in `.gitignore`.

### 3. Install frontend dependencies

```bash
# From the repo root
npm --prefix apps/desktop-ui install
```

### 4. Run in development mode

```bash
# From the repo root
cargo tauri dev
```

This starts the Vite dev server and the Tauri desktop window together. The app will hot-reload on frontend changes. Rust changes require a restart.

If another app is already using common frontend dev ports, this project now expects `http://localhost:43125` during development.

---

## Current Features

| Page | Description |
|------|-------------|
| Dashboard | Health score, alert counts, CPU/memory graphs, recent alerts |
| Processes | Live paginated process table — risk scores, signer status, path category, sort/filter |
| Process Detail | CPU/memory/network charts, metadata, AI Q&A panel, kill/trust actions |
| Alerts | Security alerts with severity triage and status management |
| Startup | Registry Run keys and startup folder monitoring, remove entries |
| Events | Unified security timeline — process starts/stops, alerts, startup changes, user actions |
| AI Assistant | General PC security chatbot — ask anything about your system |
| Settings | Groq API key override, data retention cleanup |

---

## Unfinished Pages (assigned features)

These pages are wired up and appear in the sidebar but are empty. Each is a separate feature for a team member to implement.

### Phishing Detector
- **File:** `apps/desktop-ui/src/pages/PhishingDetectorPage.tsx`
- **Route:** `/phishing-detector`


### Malicious Link Detector
- **File:** `apps/desktop-ui/src/pages/MaliciousLinkDetectorPage.tsx`
- **Route:** `/malicious-link-detector`
-

### Password Manager
- **File:** `apps/desktop-ui/src/pages/PasswordManagerPage.tsx`
- **Route:** `/password-manager`

To add backend logic for your feature, follow the pattern used by other pages, I recommend using a ai editor like codex or claude for assitance with this project:

1. Add a Tauri command in `apps/tauri-shell/src-tauri/src/commands.rs`
2. Register it in `apps/tauri-shell/src-tauri/src/lib.rs` inside `tauri::generate_handler!`
3. Add the TypeScript wrapper in `apps/desktop-ui/src/lib/invoke.ts`
4. Build your UI in the page file

---

## Detection Rules

| Rule | Weight | Description |
|------|--------|-------------|
| `unsigned_in_user_writable_dir` | 40 | Unsigned exe from AppData/Temp/Downloads |
| `powershell_spawned_by_office` | 60 | PowerShell child of Office app |
| `cmd_spawned_by_script_host` | 55 | cmd.exe child of wscript/cscript/mshta |
| `process_name_masquerade` | 70 | System binary name from non-system path |
| `suspicious_parent_child_chain` | 45 | Shell spawned by browser/document viewer |
| `exe_in_temp_dir` | 25 | Any executable running from %TEMP% |
| `high_risk_path_category` | 20 | Executable in Downloads folder |

Risk score ≥ 40 → flagged as "At Risk". Risk score ≥ 70 → high severity alert.

---

## Architecture Notes

- **No server required** — everything runs locally. The database is a SQLite file stored in the Tauri app data directory.
- **AI key baked in at build time** — `build.rs` reads `GROQ_API_KEY` from `.env` and compiles it into the binary via `option_env!`. Users of the built installer never need to configure anything. The key can also be overridden at runtime in the Settings page.
- **Polling intervals** — overview/alerts/startup refresh every 15 s; process list refreshes every 30 s. The Events page also refreshes every 30 s.
- **Tauri v2 param convention** — invoke parameters are written in camelCase in TypeScript and automatically converted to snake_case by Tauri before reaching Rust handlers.

---

## Known Limitations

- Heuristic scoring is not malware detection — it surfaces suspicious patterns for human review
- No kernel-level telemetry (ETW, Sysmon) in this version
- CPU % requires two samples over time; newly seen processes show 0%
- Some process metadata (command line, user) may be unavailable without running as Administrator
- Events timeline covers the last 30 days only

---
