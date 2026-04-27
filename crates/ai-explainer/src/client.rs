use anyhow::Result;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use shared_types::models::AiContext;
use tracing::{debug, error};

use crate::prompts::{build_process_context_prompt, build_system_prompt};

#[derive(Debug, Clone)]
pub struct AiClientConfig {
    pub provider: AiProvider,
    pub api_key: Option<String>,
    pub model: String,
    pub base_url: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum AiProvider {
    Groq,
    Anthropic,
    OpenAI,
    Local,
}

impl Default for AiClientConfig {
    fn default() -> Self {
        Self {
            provider: AiProvider::Groq,
            api_key: None,
            model: "llama-3.3-70b-versatile".to_string(),
            base_url: None,
        }
    }
}

pub struct AiClient {
    config: AiClientConfig,
    http: Client,
}

#[derive(Debug, Serialize)]
struct AnthropicRequest {
    model: String,
    max_tokens: u32,
    system: String,
    messages: Vec<AnthropicMessage>,
}

#[derive(Debug, Serialize)]
struct AnthropicMessage {
    role: String,
    content: String,
}

#[derive(Debug, Deserialize)]
struct AnthropicResponse {
    content: Vec<AnthropicContent>,
}

#[derive(Debug, Deserialize)]
struct AnthropicContent {
    text: String,
}

impl AiClient {
    pub fn new(config: AiClientConfig) -> Self {
        Self {
            config,
            http: Client::new(),
        }
    }

    pub async fn ask_about_process(
        &self,
        ctx: &AiContext,
        conversation_history: Option<&str>,
        question: &str,
    ) -> Result<String> {
        let system = build_system_prompt();
        let user_prompt = build_process_context_prompt(ctx, conversation_history, question);

        debug!("Sending AI request for process: {}", ctx.process_name);

        match self.config.provider {
            AiProvider::Groq => self.call_groq(&system, &user_prompt).await,
            AiProvider::Anthropic => self.call_anthropic(&system, &user_prompt).await,
            AiProvider::Local => self.call_local(&system, &user_prompt).await,
            AiProvider::OpenAI => self.call_openai(&system, &user_prompt).await,
        }
    }

    async fn call_groq(&self, system: &str, prompt: &str) -> Result<String> {
        let api_key =
            self.config.api_key.as_deref().ok_or_else(|| {
                anyhow::anyhow!("Groq API key not configured. Add it in Settings.")
            })?;

        #[derive(Serialize)]
        struct GroqRequest {
            model: String,
            messages: Vec<GroqMessage>,
            max_tokens: u32,
            temperature: f32,
        }
        #[derive(Serialize)]
        struct GroqMessage {
            role: String,
            content: String,
        }
        #[derive(Deserialize)]
        struct GroqResponse {
            choices: Vec<GroqChoice>,
        }
        #[derive(Deserialize)]
        struct GroqChoice {
            message: GroqMessageResp,
        }
        #[derive(Deserialize)]
        struct GroqMessageResp {
            content: String,
        }

        let request = GroqRequest {
            model: self.config.model.clone(),
            messages: vec![
                GroqMessage {
                    role: "system".to_string(),
                    content: system.to_string(),
                },
                GroqMessage {
                    role: "user".to_string(),
                    content: prompt.to_string(),
                },
            ],
            max_tokens: 1024,
            temperature: 0.3,
        };

        let response = self
            .http
            .post("https://api.groq.com/openai/v1/chat/completions")
            .header("Authorization", format!("Bearer {}", api_key))
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            error!("Groq API error {}: {}", status, body);
            anyhow::bail!("Groq API error: {} — {}", status, body);
        }

        let parsed: GroqResponse = response.json().await?;
        Ok(parsed
            .choices
            .into_iter()
            .map(|c| c.message.content)
            .collect::<Vec<_>>()
            .join(""))
    }

    async fn call_anthropic(&self, system: &str, prompt: &str) -> Result<String> {
        let api_key = self
            .config
            .api_key
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("Anthropic API key not configured"))?;

        let base_url = self
            .config
            .base_url
            .as_deref()
            .unwrap_or("https://api.anthropic.com");

        let request = AnthropicRequest {
            model: self.config.model.clone(),
            max_tokens: 1024,
            system: system.to_string(),
            messages: vec![AnthropicMessage {
                role: "user".to_string(),
                content: prompt.to_string(),
            }],
        };

        let response = self
            .http
            .post(format!("{}/v1/messages", base_url))
            .header("x-api-key", api_key)
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .json(&request)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            error!("Anthropic API error {}: {}", status, body);
            anyhow::bail!("AI API error: {} - {}", status, body);
        }

        let parsed: AnthropicResponse = response.json().await?;
        Ok(parsed
            .content
            .into_iter()
            .map(|c| c.text)
            .collect::<Vec<_>>()
            .join(""))
    }

    async fn call_openai(&self, system: &str, prompt: &str) -> Result<String> {
        // OpenAI-compatible endpoint (also works with local models like Ollama)
        let api_key = self.config.api_key.as_deref().unwrap_or("none");
        let base_url = self
            .config
            .base_url
            .as_deref()
            .unwrap_or("https://api.openai.com");

        #[derive(Serialize)]
        struct OAIRequest {
            model: String,
            messages: Vec<OAIMessage>,
            max_tokens: u32,
        }

        #[derive(Serialize)]
        struct OAIMessage {
            role: String,
            content: String,
        }

        #[derive(Deserialize)]
        struct OAIResponse {
            choices: Vec<OAIChoice>,
        }

        #[derive(Deserialize)]
        struct OAIChoice {
            message: OAIMessageResp,
        }

        #[derive(Deserialize)]
        struct OAIMessageResp {
            content: String,
        }

        let request = OAIRequest {
            model: self.config.model.clone(),
            messages: vec![
                OAIMessage {
                    role: "system".to_string(),
                    content: system.to_string(),
                },
                OAIMessage {
                    role: "user".to_string(),
                    content: prompt.to_string(),
                },
            ],
            max_tokens: 1024,
        };

        let response = self
            .http
            .post(format!("{}/v1/chat/completions", base_url))
            .header("Authorization", format!("Bearer {}", api_key))
            .json(&request)
            .send()
            .await?;

        let parsed: OAIResponse = response.json().await?;
        Ok(parsed
            .choices
            .into_iter()
            .map(|c| c.message.content)
            .collect::<Vec<_>>()
            .join(""))
    }

    async fn call_local(&self, system: &str, prompt: &str) -> Result<String> {
        // Local model via Ollama or similar OpenAI-compatible endpoint
        let base_url = self
            .config
            .base_url
            .as_deref()
            .unwrap_or("http://localhost:11434");

        // Use OpenAI-compatible path for local models
        let mut local_config = self.config.clone();
        local_config.base_url = Some(base_url.to_string());
        local_config.provider = AiProvider::OpenAI;

        let client = AiClient::new(local_config);
        client.call_openai(system, prompt).await
    }

    /// Call the configured AI provider with a raw system + user prompt pair.
    pub async fn call_raw(&self, system: &str, prompt: &str) -> Result<String> {
        match self.config.provider {
            AiProvider::Groq => self.call_groq(system, prompt).await,
            AiProvider::Anthropic => self.call_anthropic(system, prompt).await,
            AiProvider::Local => self.call_local(system, prompt).await,
            AiProvider::OpenAI => self.call_openai(system, prompt).await,
        }
    }

    pub fn is_configured(&self) -> bool {
        match self.config.provider {
            AiProvider::Groq | AiProvider::Anthropic | AiProvider::OpenAI => {
                self.config.api_key.is_some()
            }
            AiProvider::Local => true,
        }
    }
}
