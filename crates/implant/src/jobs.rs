//! Long-running task ("job") registry.
//!
//! Session-mode agents execute long tasks on dedicated tokio tasks so the
//! receive loop stays responsive; operators can list running jobs and cancel
//! or pause them. Cancellation is cooperative: each long task polls its flag,
//! child processes die when the waiting future is dropped (`kill_on_drop`).

use serde::Serialize;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

#[derive(Clone)]
pub struct JobHandle {
    pub task_id: String,
    pub kind: String,
    pub started_unix: u64,
    pub cancel: Arc<AtomicBool>,
    pub paused: Arc<AtomicBool>,
}

#[derive(Serialize)]
pub struct JobView {
    pub task_id: String,
    pub kind: String,
    pub started_unix: u64,
    pub paused: bool,
}

static JOBS: OnceLock<Mutex<HashMap<String, JobHandle>>> = OnceLock::new();

fn registry() -> &'static Mutex<HashMap<String, JobHandle>> {
    JOBS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

/// Kinds that are executed on their own task in session mode.
pub fn is_long_running(kind: &str) -> bool {
    matches!(
        kind,
        "shell"
            | "portscan"
            | "download"
            | "upload"
            | "execute_assembly"
            | "wasm_run"
            | "native_run"
    )
}

pub fn register(task_id: &str, kind: &str) -> JobHandle {
    let handle = JobHandle {
        task_id: task_id.to_string(),
        kind: kind.to_string(),
        started_unix: now_unix(),
        cancel: Arc::new(AtomicBool::new(false)),
        paused: Arc::new(AtomicBool::new(false)),
    };
    registry()
        .lock()
        .expect("job registry poisoned")
        .insert(task_id.to_string(), handle.clone());
    handle
}

pub fn finish(task_id: &str) {
    registry()
        .lock()
        .expect("job registry poisoned")
        .remove(task_id);
}

pub fn cancel(task_id: &str) -> bool {
    let registry = registry().lock().expect("job registry poisoned");
    match registry.get(task_id) {
        Some(handle) => {
            handle.cancel.store(true, Ordering::SeqCst);
            true
        }
        None => false,
    }
}

pub fn set_paused(task_id: &str, paused: bool) -> bool {
    let registry = registry().lock().expect("job registry poisoned");
    match registry.get(task_id) {
        Some(handle) => {
            handle.paused.store(paused, Ordering::SeqCst);
            true
        }
        None => false,
    }
}

pub fn cancel_flag(task_id: &str) -> Option<Arc<AtomicBool>> {
    registry()
        .lock()
        .expect("job registry poisoned")
        .get(task_id)
        .map(|handle| handle.cancel.clone())
}

pub fn pause_flag(task_id: &str) -> Option<Arc<AtomicBool>> {
    registry()
        .lock()
        .expect("job registry poisoned")
        .get(task_id)
        .map(|handle| handle.paused.clone())
}

pub fn list_json() -> Vec<u8> {
    let registry = registry().lock().expect("job registry poisoned");
    let mut jobs: Vec<JobView> = registry
        .values()
        .map(|handle| JobView {
            task_id: handle.task_id.clone(),
            kind: handle.kind.clone(),
            started_unix: handle.started_unix,
            paused: handle.paused.load(Ordering::SeqCst),
        })
        .collect();
    jobs.sort_by_key(|job| job.started_unix);
    serde_json::to_vec(&jobs).unwrap_or_else(|_| b"[]".to_vec())
}

/// Waits until the cancel flag is set (or forever when no flag exists).
pub async fn wait_cancel(flag: Option<Arc<AtomicBool>>) {
    let Some(flag) = flag else {
        std::future::pending::<()>().await;
        return;
    };
    while !flag.load(Ordering::SeqCst) {
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    }
}

/// Blocks (async) while a job is paused.
pub async fn wait_resume(flag: Option<Arc<AtomicBool>>) {
    let Some(flag) = flag else { return };
    while flag.load(Ordering::SeqCst) {
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
}

pub fn cancelled(handle: &JobHandle) -> bool {
    handle.cancel.load(Ordering::SeqCst)
}
