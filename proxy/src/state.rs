//! プロセス全体で共有する状態: ルールセット、ブロックログのキュー、統計。

use crate::rules::{RuleSet, RuleSetJson};
use arc_swap::ArcSwap;
use serde::Serialize;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Instant;

/// API へ送るブロックイベント(API の block_events テーブルと同じ形)
#[derive(Debug, Clone, Serialize)]
pub struct BlockEvent {
    pub ts: String,
    pub client: Option<String>,
    pub method: String,
    pub scheme: String,
    pub host: String,
    pub path: String,
    /// タイムパスによるブロックは null
    pub policy_id: Option<i64>,
    pub policy_name: String,
}

#[derive(Debug, Default)]
pub struct Stats {
    pub requests: AtomicU64,
    pub blocked: AtomicU64,
    pub passthrough: AtomicU64,
    pub intercepted: AtomicU64,
    pub sync_errors: AtomicU64,
}

impl Stats {
    pub fn inc(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }
}

const MAX_QUEUED_EVENTS: usize = 5000;

#[derive(Debug)]
pub struct Shared {
    pub rules: ArcSwap<RuleSet>,
    pub stats: Stats,
    pub started: Instant,
    /// 現在プロキシが使っている CA の SHA-256 (hex)
    pub ca_fingerprint: ArcSwap<String>,
    /// ブロックログが積まれたことを同期ループに知らせる(ロングポーリングを中断して即送信)
    pub events_ready: tokio::sync::Notify,
    events: Mutex<VecDeque<BlockEvent>>,
}

impl Shared {
    pub fn new(ca_fingerprint: String) -> Arc<Self> {
        Arc::new(Self {
            rules: ArcSwap::from_pointee(RuleSet::default()),
            stats: Stats::default(),
            started: Instant::now(),
            ca_fingerprint: ArcSwap::from_pointee(ca_fingerprint),
            events_ready: tokio::sync::Notify::new(),
            events: Mutex::default(),
        })
    }

    pub fn apply_rules(&self, json: RuleSetJson) {
        let compiled = RuleSet::compile(&json);
        let (block, allow, passes, intercept) = compiled.counts();
        rama::telemetry::tracing::info!(
            version = %compiled.version,
            block, allow, passes, intercept,
            intercept_all = compiled.intercept_all,
            "ruleset applied"
        );
        self.rules.store(Arc::new(compiled));
    }

    pub fn push_event(&self, ev: BlockEvent) {
        let mut q = self.events.lock().unwrap_or_else(PoisonError::into_inner);
        if q.len() >= MAX_QUEUED_EVENTS {
            q.pop_front();
        }
        q.push_back(ev);
        drop(q);
        self.events_ready.notify_one();
    }

    pub fn drain_events(&self) -> Vec<BlockEvent> {
        let mut q = self.events.lock().unwrap_or_else(PoisonError::into_inner);
        q.drain(..).collect()
    }

    /// 送信に失敗したイベントを先頭に戻す(溢れた分は古いものから捨てる)
    pub fn requeue_events(&self, batch: Vec<BlockEvent>) {
        let mut q = self.events.lock().unwrap_or_else(PoisonError::into_inner);
        for ev in batch.into_iter().rev() {
            if q.len() >= MAX_QUEUED_EVENTS {
                break;
            }
            q.push_front(ev);
        }
    }
}
