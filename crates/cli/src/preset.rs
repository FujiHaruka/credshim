use credshim_core::dummy;

pub struct Preset {
    pub name: &'static str,
    host: &'static str,
    dummy_prefix: &'static str,
    inject: &'static str,
    allow_paths: &'static str,
    env: &'static str,
}

pub const PRESETS: &[Preset] = &[
    Preset {
        name: "openai",
        host: "api.openai.com",
        dummy_prefix: "sk-credshim-openai-",
        inject: r#"{ header = "authorization" }"#,
        allow_paths: r#"["/v1/chat/completions", "/v1/responses", "/v1/completions", "/v1/embeddings", "/v1/models", "/v1/moderations", "/v1/audio", "/v1/images"]"#,
        env: "OPENAI_API_KEY",
    },
    Preset {
        name: "anthropic",
        host: "api.anthropic.com",
        dummy_prefix: "sk-ant-credshim-",
        inject: r#"{ header = "x-api-key" }"#,
        allow_paths: r#"["/v1/messages", "/v1/models", "/v1/complete"]"#,
        env: "ANTHROPIC_API_KEY",
    },
    Preset {
        name: "gemini",
        host: "generativelanguage.googleapis.com",
        dummy_prefix: "credshim-gemini-",
        inject: r#"{ header = "x-goog-api-key", query = "key" }"#,
        allow_paths: r#"["/v1beta/models", "/v1/models", "/v1beta/files", "/upload/v1beta/files"]"#,
        env: "GEMINI_API_KEY",
    },
];

pub fn find(name: &str) -> Option<&'static Preset> {
    PRESETS.iter().find(|preset| preset.name == name)
}

impl Preset {
    pub fn render(&self) -> String {
        let dummy = dummy::generate(self.dummy_prefix);
        format!(
            "# app side: {env}={dummy}\n[[rule]]\nname = \"{name}\"\nhost = \"{host}\"\nsecret = \"{name}\"\ndummy = \"{dummy}\"\ninject = {inject}\nallow_methods = [\"GET\", \"POST\"]\nallow_paths = {allow_paths}\n",
            env = self.env,
            name = self.name,
            host = self.host,
            inject = self.inject,
            allow_paths = self.allow_paths,
        )
    }
}
