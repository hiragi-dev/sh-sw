//! ルールセット(API の /internal/sync が返す JSON)と、その判定ロジック。

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};

/// API から受け取るルールセット(ディスクキャッシュにもこの形で保存する)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuleSetJson {
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub rules: Vec<PolicyRuleJson>,
    #[serde(default)]
    pub passes: Vec<PassRuleJson>,
    #[serde(default)]
    pub intercept_hosts: Vec<HostJson>,
    #[serde(default)]
    pub intercept_all: bool,
    #[serde(default)]
    pub ca_fingerprint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRuleJson {
    pub host: String,
    #[serde(default = "default_true")]
    pub include_subdomains: bool,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub user_agent: String,
    pub policy_id: i64,
    pub policy_name: String,
    pub action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassRuleJson {
    pub host: String,
    #[serde(default = "default_true")]
    pub include_subdomains: bool,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub user_agent: String,
    pub pass_id: i64,
    pub pass_name: String,
    /// 解除期限 (UNIX epoch 秒)。0 ならロック中
    #[serde(default)]
    pub unlocked_until: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostJson {
    pub host: String,
    #[serde(default = "default_true")]
    pub include_subdomains: bool,
}

fn default_true() -> bool {
    true
}

/// `*` のみをワイルドカードとして扱う簡易 glob → 正規表現本体
fn glob(pattern: &str) -> String {
    regex::escape(pattern).replace(r"\*", ".*")
}

fn host_regex(host: &str, include_subdomains: bool) -> Regex {
    let body = glob(host.trim().trim_start_matches('.').to_ascii_lowercase().as_str());
    let prefix = if include_subdomains { r"(?:.*\.)?" } else { "" };
    Regex::new(&format!("^{prefix}{body}$")).unwrap_or_else(|_| Regex::new("^$").expect("valid"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleKind {
    Allow,
    Block,
    Pass,
}

#[derive(Debug)]
pub struct Rule {
    pub id: i64,
    pub name: String,
    pub kind: RuleKind,
    host_re: Regex,
    path: String,
    /// `*` を含むパスは全体一致の glob、含まなければ前方一致
    path_re: Option<Regex>,
    /// User-Agent の条件 (大文字小文字を区別しない)。`*` を含めば全体一致、含まなければ部分一致
    ua_re: Option<Regex>,
    /// タイムパスの解除期限 (epoch 秒)
    pub unlocked_until: f64,
}

impl Rule {
    fn new(
        id: i64,
        name: String,
        kind: RuleKind,
        host: &str,
        include_subdomains: bool,
        path: &str,
        user_agent: &str,
        unlocked_until: f64,
    ) -> Self {
        let path = path.trim().to_owned();
        let path_re = path
            .contains('*')
            .then(|| Regex::new(&format!("(?s)^{}$", glob(&path))).ok())
            .flatten();
        let user_agent = user_agent.trim();
        let ua_re = (!user_agent.is_empty())
            .then(|| {
                let body = if user_agent.contains('*') {
                    format!("^{}$", glob(user_agent))
                } else {
                    regex::escape(user_agent)
                };
                Regex::new(&format!("(?is){body}")).ok()
            })
            .flatten();
        Self {
            id,
            name,
            kind,
            host_re: host_regex(host, include_subdomains),
            path,
            path_re,
            ua_re,
            unlocked_until,
        }
    }

    pub fn matches(&self, host: &str, path: &str, user_agent: &str) -> bool {
        if !self.host_re.is_match(host) {
            return false;
        }
        if let Some(re) = &self.ua_re
            && !re.is_match(user_agent)
        {
            return false;
        }
        if self.path.is_empty() {
            return true;
        }
        match &self.path_re {
            Some(re) => re.is_match(path),
            None => path.starts_with(&self.path),
        }
    }
}

/// 判定結果
#[derive(Debug, Clone, Copy)]
pub enum Verdict<'a> {
    Allow,
    Block(&'a Rule),
}

/// コンパイル済みルールセット。同期のたびに丸ごと差し替える(ArcSwap)
#[derive(Debug, Default)]
pub struct RuleSet {
    pub version: String,
    pub intercept_all: bool,
    allow: Vec<Rule>,
    block: Vec<Rule>,
    passes: Vec<Rule>,
    intercept: Vec<Regex>,
    /// ホスト名 → 復号対象か のキャッシュ
    host_cache: Mutex<HashMap<String, bool>>,
}

impl RuleSet {
    pub fn compile(json: &RuleSetJson) -> Self {
        let mut allow = Vec::new();
        let mut block = Vec::new();
        for r in &json.rules {
            let kind = if r.action == "allow" { RuleKind::Allow } else { RuleKind::Block };
            let rule = Rule::new(
                r.policy_id,
                r.policy_name.clone(),
                kind,
                &r.host,
                r.include_subdomains,
                &r.path,
                &r.user_agent,
                0.0,
            );
            match kind {
                RuleKind::Allow => allow.push(rule),
                _ => block.push(rule),
            }
        }
        let passes = json
            .passes
            .iter()
            .map(|p| {
                Rule::new(
                    p.pass_id,
                    p.pass_name.clone(),
                    RuleKind::Pass,
                    &p.host,
                    p.include_subdomains,
                    &p.path,
                    &p.user_agent,
                    p.unlocked_until,
                )
            })
            .collect();
        Self {
            version: json.version.clone(),
            intercept_all: json.intercept_all,
            allow,
            block,
            passes,
            intercept: json
                .intercept_hosts
                .iter()
                .map(|h| host_regex(&h.host, h.include_subdomains))
                .collect(),
            host_cache: Mutex::default(),
        }
    }

    pub fn counts(&self) -> (usize, usize, usize, usize) {
        (self.block.len(), self.allow.len(), self.passes.len(), self.intercept.len())
    }

    /// TLS を復号すべきホストか(ルールに無いホストは素通し)
    pub fn should_intercept(&self, host: &str) -> bool {
        if self.intercept_all {
            return true;
        }
        let host = normalize_host(host);
        let mut cache = self.host_cache.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(hit) = cache.get(&host) {
            return *hit;
        }
        let hit = self.intercept.iter().any(|re| re.is_match(&host));
        if cache.len() > 10_000 {
            cache.clear();
        }
        cache.insert(host, hit);
        hit
    }

    /// 優先順位: 有効な allow ポリシー → block ポリシー → ロック中のタイムパス
    pub fn evaluate(&self, host: &str, path: &str, user_agent: &str, now_epoch: f64) -> Verdict<'_> {
        let host = normalize_host(host);
        if self.allow.iter().any(|r| r.matches(&host, path, user_agent)) {
            return Verdict::Allow;
        }
        if let Some(r) = self.block.iter().find(|r| r.matches(&host, path, user_agent)) {
            return Verdict::Block(r);
        }
        if let Some(r) = self
            .passes
            .iter()
            .find(|r| now_epoch >= r.unlocked_until && r.matches(&host, path, user_agent))
        {
            return Verdict::Block(r);
        }
        Verdict::Allow
    }
}

pub fn normalize_host(host: &str) -> String {
    host.trim().trim_end_matches('.').to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rs() -> RuleSet {
        let json: RuleSetJson = serde_json::from_value(serde_json::json!({
            "version": "v1",
            "rules": [
                {"host": "example.com", "include_subdomains": true, "path": "", "policy_id": 1, "policy_name": "ex", "action": "block"},
                {"host": "httpbin.org", "include_subdomains": false, "path": "/status/*", "policy_id": 2, "policy_name": "hb", "action": "block"},
                {"host": "youtube.com", "include_subdomains": true, "path": "/@lectures", "policy_id": 3, "policy_name": "allow", "action": "allow"},
                {"host": "youtube.com", "include_subdomains": true, "path": "", "policy_id": 4, "policy_name": "yt", "action": "block"}
            ],
            "passes": [
                {"host": "tiktok.com", "include_subdomains": true, "path": "", "pass_id": 9, "pass_name": "tt", "unlocked_until": 100.0}
            ],
            "intercept_hosts": [{"host": "example.com", "include_subdomains": true}, {"host": "*.cdn.test", "include_subdomains": false}],
        }))
        .unwrap();
        RuleSet::compile(&json)
    }

    #[test]
    fn host_and_subdomains() {
        let r = rs();
        assert!(matches!(r.evaluate("example.com", "/", "", 0.0), Verdict::Block(_)));
        assert!(matches!(r.evaluate("WWW.Example.com.", "/x", "", 0.0), Verdict::Block(_)));
        assert!(matches!(r.evaluate("notexample.com", "/", "", 0.0), Verdict::Allow));
    }

    #[test]
    fn path_glob_and_prefix() {
        let r = rs();
        assert!(matches!(r.evaluate("httpbin.org", "/status/200", "", 0.0), Verdict::Block(_)));
        assert!(matches!(r.evaluate("httpbin.org", "/get", "", 0.0), Verdict::Allow));
        assert!(matches!(r.evaluate("sub.httpbin.org", "/status/200", "", 0.0), Verdict::Allow));
    }

    #[test]
    fn allow_has_priority() {
        let r = rs();
        assert!(matches!(r.evaluate("www.youtube.com", "/@lectures/videos", "", 0.0), Verdict::Allow));
        assert!(matches!(r.evaluate("www.youtube.com", "/shorts/x", "", 0.0), Verdict::Block(_)));
    }

    #[test]
    fn time_pass_expiry() {
        let r = rs();
        assert!(matches!(r.evaluate("www.tiktok.com", "/", "", 99.9), Verdict::Allow));
        match r.evaluate("www.tiktok.com", "/", "", 100.0) {
            Verdict::Block(rule) => assert_eq!(rule.kind, RuleKind::Pass),
            v => panic!("{v:?}"),
        }
    }

    #[test]
    fn user_agent_condition() {
        let json: RuleSetJson = serde_json::from_value(serde_json::json!({
            "rules": [
                {"host": "googlevideo.com", "path": "", "user_agent": "com.google.ios.youtube/*", "policy_id": 1, "policy_name": "yt app", "action": "block"},
                {"host": "youtubei.googleapis.com", "path": "", "user_agent": "ios.youtube/", "policy_id": 2, "policy_name": "yt api", "action": "block"}
            ]
        }))
        .unwrap();
        let r = RuleSet::compile(&json);
        let yt = "com.google.ios.youtube/20.10.4 (iPhone16,2; U; CPU iOS 18_6 like Mac OS X;)";
        let music = "com.google.ios.youtubemusic/8.10 (iPhone16,2; U; CPU iOS 18_6 like Mac OS X;)";
        assert!(matches!(r.evaluate("rr1.googlevideo.com", "/videoplayback", yt, 0.0), Verdict::Block(_)));
        assert!(matches!(r.evaluate("rr1.googlevideo.com", "/videoplayback", music, 0.0), Verdict::Allow));
        assert!(matches!(r.evaluate("youtubei.googleapis.com", "/youtubei/v1/browse", yt, 0.0), Verdict::Block(_)));
        assert!(matches!(r.evaluate("youtubei.googleapis.com", "/youtubei/v1/browse", music, 0.0), Verdict::Allow));
        assert!(matches!(r.evaluate("youtubei.googleapis.com", "/", "", 0.0), Verdict::Allow));
    }

    #[test]
    fn intercept_decision() {
        let r = rs();
        assert!(r.should_intercept("api.example.com"));
        assert!(r.should_intercept("a.cdn.test"));
        assert!(!r.should_intercept("github.com"));
    }
}
