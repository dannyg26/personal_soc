fn bake_env_var(contents: &str, key: &str) {
    let prefix = format!("{key}=");

    for line in contents.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }

        if let Some(val) = line.strip_prefix(&prefix) {
            println!("cargo:rustc-env={key}={}", val.trim());
        }
    }
}

fn main() {
    tauri_build::build();

    // Read API keys from the local .env next to this build.rs and bake them into the binary.
    // The .env file is gitignored so secrets are never committed.
    let env_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(".env");
    if let Ok(contents) = std::fs::read_to_string(&env_path) {
        bake_env_var(&contents, "GROQ_API_KEY");
        bake_env_var(&contents, "VIRUSTOTAL_API_KEY");
    }

    // Re-run if the .env file changes
    println!("cargo:rerun-if-changed=.env");
}
