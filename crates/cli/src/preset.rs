use credshim_core::dummy;

pub struct Preset {
    pub name: &'static str,
    host: &'static str,
    dummy_prefix: &'static str,
    inject: &'static str,
    env: &'static str,
}

pub const PRESETS: &[Preset] = &[
    Preset {
        name: "openai",
        host: "api.openai.com",
        dummy_prefix: "sk-credshim-openai-",
        inject: r#"{ header = "authorization" }"#,
        env: "OPENAI_API_KEY",
    },
    Preset {
        name: "anthropic",
        host: "api.anthropic.com",
        dummy_prefix: "sk-ant-credshim-",
        inject: r#"{ header = "x-api-key" }"#,
        env: "ANTHROPIC_API_KEY",
    },
    Preset {
        name: "gemini",
        host: "generativelanguage.googleapis.com",
        dummy_prefix: "credshim-gemini-",
        inject: r#"{ header = "x-goog-api-key", query = "key" }"#,
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
            "# app side: {env}={dummy}\n[[rule]]\nname = \"{name}\"\nhost = \"{host}\"\nsecret = \"{name}\"\ndummy = \"{dummy}\"\ninject = {inject}\n",
            env = self.env,
            name = self.name,
            host = self.host,
            inject = self.inject,
        )
    }
}
