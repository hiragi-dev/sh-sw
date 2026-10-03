//! 管理 API とのロングポーリング同期。
//!
//! - 未送信のブロックログと統計を送り、最新のルールセットを受け取る
//! - ルールセットが変わらなければ API 側で最大 SHSW_SYNC_WAIT 秒待ってから返る
//!   (変更系 API が呼ばれると即座に返るため、解除・ロックはほぼ即時に反映される)
//! - CA が差し替えられたら読み直して MITM 用の発行元を入れ替える(再起動不要)

use crate::ca::{self, CaFiles};
use crate::rules::RuleSetJson;
use crate::state::Shared;
use rama::telemetry::tracing;
use serde_json::json;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

pub struct SyncConfig {
    pub api_url: String,
    pub internal_token: String,
    pub wait: f64,
    pub cache_file: PathBuf,
    pub ca_files: CaFiles,
}

/// CA の再読み込みを MITM サービスへ反映するコールバック
pub type CaReloader = Arc<dyn Fn(ca::LoadedCa) + Send + Sync>;

const RETRY: Duration = Duration::from_secs(2);

pub fn load_cache(shared: &Shared, cfg: &SyncConfig) {
    match std::fs::read(&cfg.cache_file) {
        Ok(data) => match serde_json::from_slice::<RuleSetJson>(&data) {
            Ok(json) => {
                tracing::info!(version = %json.version, "loaded cached ruleset");
                shared.apply_rules(json);
            }
            Err(err) => tracing::warn!(%err, "invalid ruleset cache"),
        },
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => tracing::warn!(%err, "cannot read ruleset cache"),
    }
}

fn persist_cache(json: &RuleSetJson, path: &PathBuf) {
    let tmp = path.with_extension("tmp");
    let res = serde_json::to_vec(json)
        .map_err(std::io::Error::other)
        .and_then(|data| std::fs::write(&tmp, data))
        .and_then(|()| std::fs::rename(&tmp, path));
    if let Err(err) = res {
        tracing::warn!(%err, "failed to persist ruleset cache");
    }
}

pub async fn run(shared: Arc<Shared>, cfg: SyncConfig, reload_ca: CaReloader) {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs_f64(cfg.wait + 10.0))
        .build()
        .expect("http client");
    let mut last_err_log: Option<Instant> = None;

    loop {
        let batch = shared.drain_events();
        // 未送信のブロックログがあるときは待たずに返してもらう
        let wait = if batch.is_empty() { cfg.wait } else { 0.0 };
        let current_version = shared.rules.load().version.clone();
        let s = &shared.stats;
        let body = json!({
            "events": &batch,
            "stats": {
                "engine": "rama",
                "requests": s.requests.load(Ordering::Relaxed),
                "blocked": s.blocked.load(Ordering::Relaxed),
                "passthrough": s.passthrough.load(Ordering::Relaxed),
                "intercepted": s.intercepted.load(Ordering::Relaxed),
                "sync_errors": s.sync_errors.load(Ordering::Relaxed),
                "uptime": shared.started.elapsed().as_secs(),
                "ruleset": current_version,
            },
            "ca_fingerprint": shared.ca_fingerprint.load().as_str(),
        });

        let request = async {
            client
                .post(format!("{}/internal/sync", cfg.api_url))
                .query(&[("known_version", current_version.as_str()), ("wait", &wait.to_string())])
                .header("X-Internal-Token", &cfg.internal_token)
                .json(&body)
                .send()
                .await?
                .error_for_status()?
                .json::<RuleSetJson>()
                .await
        };

        let json = if batch.is_empty() {
            // 待機中にブロックログが積まれたら、ロングポーリングを打ち切ってすぐ送る
            tokio::select! {
                res = request => res,
                () = shared.events_ready.notified() => {
                    // 連続するログをまとめるため少しだけ待つ
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    continue;
                }
            }
        } else {
            request.await
        };

        match json {
            Ok(json) => {
                if !json.ca_fingerprint.is_empty() && json.ca_fingerprint != **shared.ca_fingerprint.load() {
                    match ca::load(&cfg.ca_files) {
                        Ok(loaded) if loaded.fingerprint == json.ca_fingerprint => {
                            tracing::warn!(fingerprint = %loaded.fingerprint, "CA changed; reloading MITM issuer");
                            shared.ca_fingerprint.store(Arc::new(loaded.fingerprint.clone()));
                            reload_ca(loaded);
                        }
                        Ok(_) => tracing::debug!("CA file not yet updated"),
                        Err(err) => tracing::warn!(%err, "failed to reload CA"),
                    }
                }
                if json.version != current_version {
                    persist_cache(&json, &cfg.cache_file);
                    shared.apply_rules(json);
                }
            }
            Err(err) => {
                shared.requeue_events(batch);
                shared.stats.sync_errors.fetch_add(1, Ordering::Relaxed);
                if last_err_log.is_none_or(|t| t.elapsed() > Duration::from_secs(30)) {
                    last_err_log = Some(Instant::now());
                    tracing::warn!(%err, api = %cfg.api_url, "sync with API failed");
                }
                tokio::time::sleep(RETRY).await;
            }
        }
    }
}
