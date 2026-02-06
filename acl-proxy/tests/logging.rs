use std::io::Write;
use std::process::Command;

use assert_cmd::prelude::*;
use predicates::str::contains;
use tempfile::{tempdir, NamedTempFile};

use acl_proxy::config::{
    LoggingConfig, LoggingEvidenceConfig, LoggingPolicyDecisionsConfig, PolicyDefaultAction,
};
use acl_proxy::logging::{LoggingSettings, PolicyDecisionLogContext};
use acl_proxy::policy::{MatchedRule, PolicyDecision};

#[test]
fn config_validate_fails_for_invalid_logging_level() {
    let mut file = NamedTempFile::new().expect("create temp config");
    writeln!(
        file,
        r#"
schema_version = "1"

[proxy]
bind_address = "127.0.0.1"
http_port = 8080

[logging]
directory = "logs"
level = "notalevel"

[policy]
default = "deny"
        "#
    )
    .expect("write config");

    let mut cmd = Command::new(assert_cmd::cargo_bin!("acl-proxy"));
    cmd.arg("config")
        .arg("validate")
        .arg("--config")
        .arg(file.path());

    cmd.assert()
        .failure()
        .stderr(contains("invalid log level for logging.level"));
}

#[test]
fn evidence_is_written_even_when_policy_logs_disabled() {
    let dir = tempdir().expect("create tempdir");
    let evidence_path = dir.path().join("acl_proxy_evidence.jsonl");
    let cfg = LoggingConfig {
        directory: "logs".to_string(),
        level: "info".to_string(),
        policy_decisions: LoggingPolicyDecisionsConfig {
            log_allows: false,
            log_denies: false,
            level_allows: "info".to_string(),
            level_denies: "warn".to_string(),
        },
        evidence: LoggingEvidenceConfig {
            enabled: true,
            path: evidence_path.to_string_lossy().to_string(),
        },
    };
    let settings = LoggingSettings::from_config(&cfg).expect("build settings");

    let allow_decision = PolicyDecision {
        allowed: true,
        matched: Some(MatchedRule {
            index: 0,
            action: PolicyDefaultAction::Allow,
            pattern: Some("http://example.com/**".into()),
            description: None,
            rule_id: None,
            subnets: vec![],
            methods: vec!["GET".into()],
            header_actions: vec![],
            external_auth_profile: None,
        }),
    };
    let deny_decision = PolicyDecision {
        allowed: false,
        matched: None,
    };

    settings.log_policy_decision(PolicyDecisionLogContext {
        request_id: "req-allow",
        url: "http://example.com/health",
        method: Some("GET"),
        client_ip: Some("127.0.0.1"),
        decision: &allow_decision,
    });
    settings.log_policy_decision(PolicyDecisionLogContext {
        request_id: "req-deny",
        url: "http://example.com/deny",
        method: Some("GET"),
        client_ip: Some("127.0.0.1"),
        decision: &deny_decision,
    });

    let content = std::fs::read_to_string(&evidence_path).expect("read evidence");
    let lines: Vec<_> = content.lines().collect();
    assert_eq!(
        lines.len(),
        2,
        "evidence should record allow+deny decisions"
    );
}
