use crate::provider::AiError;
use std::collections::HashSet;

/// Risk tier assigned to every tool the model can call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Risk {
    /// Read-only reconnaissance (list sessions, cat a file…).
    ReadOnly,
    /// Mutates remote state but is routine operator work (shell, upload).
    Mutating,
    /// Destructive or infrastructure-level (BOF, WASM, tunnels).
    Destructive,
}

/// Static risk table for the built-in tool surface. Unknown tools default to
/// `Destructive` so a hallucinated tool can never bypass approval.
pub fn risk_of(tool: &str) -> Risk {
    match tool {
        "list_sessions" | "session_info" | "list_tasks" | "fs_ls" | "fs_cat" | "wasm_list" => {
            Risk::ReadOnly
        }
        "run_shell" | "run_task" | "fs_download" | "fs_upload" => Risk::Mutating,
        _ => Risk::Destructive,
    }
}

/// Approval policy for agent tool calls.
#[derive(Debug, Clone, Default)]
pub struct ApprovalPolicy {
    /// When true, `ReadOnly` and `Mutating` tools run unattended.
    pub auto_approve_mutating: bool,
    /// When true, `Destructive` tools may run after the gate approves.
    pub allow_destructive: bool,
    /// Explicit tool allowlist. Empty means "no explicit allowlist".
    pub allowed_tools: HashSet<String>,
}

impl ApprovalPolicy {
    /// Evaluate whether a tool call is permitted without human interaction.
    pub fn evaluate(&self, tool: &str) -> Result<bool, AiError> {
        if !self.allowed_tools.is_empty() && !self.allowed_tools.contains(tool) {
            return Ok(false);
        }
        match risk_of(tool) {
            Risk::ReadOnly => Ok(true),
            Risk::Mutating => Ok(self.auto_approve_mutating),
            Risk::Destructive => Ok(self.allow_destructive && self.auto_approve_mutating),
        }
    }

    /// Human-readable reason used in audit logs and UI prompts.
    pub fn describe(&self, tool: &str) -> &'static str {
        match risk_of(tool) {
            Risk::ReadOnly => "read-only tool",
            Risk::Mutating if self.auto_approve_mutating => "mutating tool (pre-approved)",
            Risk::Mutating => "mutating tool requires approval",
            Risk::Destructive if self.allow_destructive && self.auto_approve_mutating => {
                "destructive tool (pre-approved)"
            }
            Risk::Destructive => "destructive tool requires explicit approval",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_only_always_allowed() {
        let policy = ApprovalPolicy::default();
        assert!(policy.evaluate("list_sessions").expect("eval"));
        assert!(policy.evaluate("fs_cat").expect("eval"));
    }

    #[test]
    fn mutating_requires_approval_by_default() {
        let policy = ApprovalPolicy::default();
        assert!(!policy.evaluate("run_shell").expect("eval"));
        let relaxed = ApprovalPolicy {
            auto_approve_mutating: true,
            ..Default::default()
        };
        assert!(relaxed.evaluate("run_shell").expect("eval"));
    }

    #[test]
    fn destructive_needs_both_flags() {
        let policy = ApprovalPolicy {
            auto_approve_mutating: true,
            allow_destructive: false,
            allowed_tools: HashSet::new(),
        };
        assert!(!policy.evaluate("bof_run").expect("eval"));

        let policy = ApprovalPolicy {
            auto_approve_mutating: true,
            allow_destructive: true,
            allowed_tools: HashSet::new(),
        };
        assert!(policy.evaluate("bof_run").expect("eval"));
    }

    #[test]
    fn unknown_tool_is_destructive() {
        assert_eq!(risk_of("rm_rf_everything"), Risk::Destructive);
    }

    #[test]
    fn allowlist_restricts() {
        let mut allowed = HashSet::new();
        allowed.insert("run_shell".to_string());
        let policy = ApprovalPolicy {
            auto_approve_mutating: true,
            allow_destructive: true,
            allowed_tools: allowed,
        };
        assert!(policy.evaluate("run_shell").expect("eval"));
        assert!(!policy.evaluate("fs_ls").expect("eval"));
    }
}
