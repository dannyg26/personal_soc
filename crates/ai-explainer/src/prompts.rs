use shared_types::models::{AiContext, PathCategory, SignerStatus};

pub fn build_system_prompt() -> String {
    r#"You are Threat-Guard's built-in Windows security assistant.
Answer like a thoughtful analyst helping a real person, not like a canned report.

Guidelines:
- Respond in plain text.
- Default to short paragraphs. Use a short list only when it genuinely makes the answer clearer.
- Start with the direct answer to the user's question instead of forcing a fixed template.
- Let the structure vary naturally based on the question. Do not force labels like "What it is" or "Next step" unless the user explicitly asks for a breakdown.
- Ground your answer in the telemetry you were given. Mention concrete facts such as the process name, path, signer status, parent process, risk score, or triggered rules when relevant.
- Explain uncertainty honestly using phrases like "based on the available telemetry" or "this may indicate".
- Do not claim definite malware attribution unless the evidence clearly supports it.
- If the user asks whether something is safe to kill, mention operational risk and be very careful around critical Windows processes.
- Keep the tone calm, specific, and useful.

You receive structured telemetry rather than full system access. Work with what is provided."#
        .to_string()
}

pub fn build_process_context_prompt(
    ctx: &AiContext,
    conversation_history: Option<&str>,
    question: &str,
) -> String {
    let signer_str = match &ctx.signer_status {
        SignerStatus::Signed => "digitally signed",
        SignerStatus::Unsigned => "unsigned (no valid signature)",
        SignerStatus::InvalidSignature => "has an invalid or tampered signature",
        SignerStatus::Unknown => "signature status unknown",
    };

    let path_str = match &ctx.path_category {
        PathCategory::System => "system directory (Windows/System32)",
        PathCategory::ProgramFiles => "Program Files",
        PathCategory::UserWritable => "user-writable location",
        PathCategory::Temp => "Temp directory",
        PathCategory::Downloads => "Downloads folder",
        PathCategory::AppData => "AppData directory",
        PathCategory::Unknown => "unknown location",
    };

    let rules_str = if ctx.triggered_rules.is_empty() {
        "No suspicious rules triggered.".to_string()
    } else {
        ctx.triggered_rules
            .iter()
            .map(|r| format!("- [{}] {}", r.rule_key, r.explanation))
            .collect::<Vec<_>>()
            .join("\n")
    };

    let history_block = conversation_history
        .filter(|history| !history.trim().is_empty())
        .map(|history| format!("Recent Conversation:\n{}\n\n", history))
        .unwrap_or_default();

    format!(
        r#"{history_block}Process Telemetry:
- Name: {}
- Path: {} (categorized as: {})
- Signature: {}
- Hash: {}
- Parent Process: {}
- Command Line: {}
- Risk Score: {}/100
- Recent CPU: {:.1}%
- Recent Memory: {:.0} MB
- Startup Linked: {}
- Network Active: {}

Triggered Security Rules:
{}

Current User Question: {}

Answer the current question using the telemetry above. If this is a follow-up, continue the conversation instead of repeating the same explanation."#,
        ctx.process_name,
        ctx.exe_path.as_deref().unwrap_or("unknown"),
        path_str,
        signer_str,
        ctx.file_hash.as_deref().unwrap_or("not computed"),
        ctx.parent_process_name.as_deref().unwrap_or("unknown"),
        ctx.command_line.as_deref().unwrap_or("not available"),
        ctx.risk_score,
        ctx.recent_cpu_avg,
        ctx.recent_memory_mb,
        if ctx.startup_linked { "yes" } else { "no" },
        if ctx.network_active { "yes" } else { "no" },
        rules_str,
        question,
        history_block = history_block,
    )
}

pub fn build_general_system_prompt() -> String {
    r#"You are Threat-Guard's AI assistant for Windows security and performance.
You have access to a telemetry snapshot of the user's PC, including processes, alerts, startup entries, and recent activity.

Guidelines:
- Respond in plain text.
- Sound conversational and specific, not robotic or templated.
- Start with the takeaway in the first sentence or two.
- Default to short paragraphs. Use a short list only when it clearly helps.
- Let the structure vary with the question. Do not force the same headings or labels in every response.
- If this is a follow-up question, continue the thread naturally and avoid restating the entire system snapshot unless it helps answer the question.
- Ground your answer in the provided telemetry. Mention concrete process names, alert titles, risk scores, signer status, or startup paths when relevant.
- Speak plainly and avoid unnecessary jargon.
- Be honest about uncertainty and do not claim definite malware attribution without strong evidence.
- If the system looks healthy, say so clearly.
- When action is warranted, suggest one or two practical next steps rather than a generic checklist.

You receive a bounded telemetry snapshot. Work with what is provided."#
        .to_string()
}

pub fn build_system_context_prompt(
    context: &str,
    conversation_history: Option<&str>,
    question: &str,
) -> String {
    let history_block = conversation_history
        .filter(|history| !history.trim().is_empty())
        .map(|history| format!("Recent Conversation:\n{}\n\n", history))
        .unwrap_or_default();

    format!(
        "Current System Snapshot:\n{}\n\n{}Current User Question: {}\n\nAnswer naturally using the snapshot above. Continue the conversation if this is a follow-up, and avoid repeating the full context unless it helps answer the question.",
        context, history_block, question
    )
}

pub fn build_summary_prompt(alert_count: u32, high_count: u32, process_summary: &str) -> String {
    format!(
        r#"Security Summary Request:
- Total alerts today: {}
- High severity alerts: {}
- Process activity summary: {}

Please provide a brief plain-English summary of today's security activity and any recommended actions."#,
        alert_count, high_count, process_summary
    )
}
