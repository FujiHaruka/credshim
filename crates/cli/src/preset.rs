use credshim_core::dummy;

pub struct Preset {
    pub name: &'static str,
    host: &'static str,
    dummy_prefix: &'static str,
    inject: &'static str,
    allow_paths: &'static str,
    env: &'static str,
    base_url_prefix: &'static str,
}

pub const PRESETS: &[Preset] = &[
    Preset {
        name: "openai",
        host: "api.openai.com",
        dummy_prefix: "sk-credshim-openai-",
        inject: r#"{ header = "authorization" }"#,
        allow_paths: r#"["/v1/chat/completions", "/v1/responses", "/v1/completions", "/v1/embeddings", "/v1/models", "/v1/moderations", "/v1/audio", "/v1/images"]"#,
        env: "OPENAI_API_KEY",
        base_url_prefix: "/openai",
    },
    Preset {
        name: "anthropic",
        host: "api.anthropic.com",
        dummy_prefix: "sk-ant-credshim-",
        inject: r#"{ header = "x-api-key" }"#,
        allow_paths: r#"["/v1/messages", "/v1/models", "/v1/complete"]"#,
        env: "ANTHROPIC_API_KEY",
        base_url_prefix: "/anthropic",
    },
    Preset {
        name: "gemini",
        host: "generativelanguage.googleapis.com",
        dummy_prefix: "credshim-gemini-",
        inject: r#"{ header = "x-goog-api-key", query = "key" }"#,
        allow_paths: r#"["/v1beta/models", "/v1/models", "/v1beta/files", "/upload/v1beta/files"]"#,
        env: "GEMINI_API_KEY",
        base_url_prefix: "/gemini",
    },
];

pub struct SshPreset {
    pub name: &'static str,
    rule: &'static str,
    users: &'static [&'static str],
    host_keys: &'static [&'static str],
}

pub const SSH_PRESETS: &[SshPreset] = &[SshPreset {
    name: "github-ssh",
    rule: "github",
    users: &["git"],
    host_keys: &[
        "SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU",
        "SHA256:p2QAMXNIC1TJYWeIOttrVc98/R1BUFWu3/LiyKgUfQM",
        "SHA256:uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s",
    ],
}];

pub const AWS_PRESET: &str = "aws";

pub fn names() -> impl Iterator<Item = &'static str> {
    PRESETS
        .iter()
        .map(|preset| preset.name)
        .chain(SSH_PRESETS.iter().map(|preset| preset.name))
        .chain([AWS_PRESET])
}

pub fn render(name: &str) -> Option<String> {
    if name == AWS_PRESET {
        return Some(render_aws());
    }
    PRESETS
        .iter()
        .find(|preset| preset.name == name)
        .map(Preset::render)
        .or_else(|| {
            SSH_PRESETS
                .iter()
                .find(|preset| preset.name == name)
                .map(SshPreset::render)
        })
}

fn render_aws() -> String {
    format!(
        "[[aws_key]]\nname = \"aws\"\ndummy_access_key_id = \"{dummy}\"\naccess_key_id = \"aws-access-key-id\"\nsecret_access_key = \"aws-secret-access-key\"\n",
        dummy = dummy::generate("CREDSHIMAWS"),
    )
}

impl SshPreset {
    fn render(&self) -> String {
        let quoted = |values: &[&str]| {
            values
                .iter()
                .map(|value| format!("\"{value}\""))
                .collect::<Vec<_>>()
                .join(", ")
        };
        format!(
            "[[ssh_key]]\nname = \"{rule}\"\nsecret = \"ssh-{rule}\"\nusers = [{users}]\nhost_keys = [{host_keys}]\n",
            rule = self.rule,
            users = quoted(self.users),
            host_keys = quoted(self.host_keys),
        )
    }
}

impl Preset {
    fn render(&self) -> String {
        let dummy = dummy::generate(self.dummy_prefix);
        format!(
            "[[rule]]\nname = \"{name}\"\nhost = \"{host}\"\nsecret = \"{name}\"\ndummy = \"{dummy}\"\nenv = \"{env}\"\ninject = {inject}\nallow_methods = [\"GET\", \"POST\"]\nallow_paths = {allow_paths}\nbase_url_prefix = \"{base_url_prefix}\"\n",
            env = self.env,
            name = self.name,
            host = self.host,
            inject = self.inject,
            allow_paths = self.allow_paths,
            base_url_prefix = self.base_url_prefix,
        )
    }
}
