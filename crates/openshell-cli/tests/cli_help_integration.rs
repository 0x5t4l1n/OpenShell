// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Rendered help and command-shape checks for the `openshell` binary.

mod common;

use common::run_isolated;

#[test]
fn root_help_shows_top_level_commands() {
    let output = run_isolated(&["--help"]);
    assert_eq!(output.code, 0, "openshell --help:\n{}", output.combined);

    for command in [
        "gateway", "status", "sandbox", "forward", "logs", "policy", "agent",
    ] {
        assert!(
            output.combined.contains(command),
            "expected '{command}' in openshell --help:\n{}",
            output.combined
        );
    }
}

#[test]
fn gateway_help_shows_registration_commands_and_omits_lifecycle_commands() {
    let output = run_isolated(&["gateway", "--help"]);
    assert_eq!(output.code, 0, "gateway --help:\n{}", output.combined);

    for command in ["add", "remove", "login", "logout", "select", "info", "list"] {
        assert!(
            output.combined.contains(command),
            "expected '{command}' in gateway --help:\n{}",
            output.combined
        );
    }
    for removed in ["start", "stop", "destroy"] {
        assert!(
            !output.combined.contains(removed),
            "unexpected removed command '{removed}' in gateway --help:\n{}",
            output.combined
        );
    }
}

#[test]
fn sandbox_help_shows_transfer_and_lifecycle_commands() {
    let output = run_isolated(&["sandbox", "--help"]);
    assert_eq!(output.code, 0, "sandbox --help:\n{}", output.combined);

    for command in [
        "upload", "download", "create", "get", "list", "delete", "connect",
    ] {
        assert!(
            output.combined.contains(command),
            "expected '{command}' in sandbox --help:\n{}",
            output.combined
        );
    }
}

#[test]
fn sandbox_create_help_shows_creation_flags() {
    let output = run_isolated(&["sandbox", "create", "--help"]);
    assert_eq!(
        output.code, 0,
        "sandbox create --help:\n{}",
        output.combined
    );

    for flag in [
        "--gpu",
        "--upload",
        "--no-git-ignore",
        "--editor",
        "--auto-providers",
        "--no-auto-providers",
    ] {
        assert!(
            output.combined.contains(flag),
            "expected '{flag}' in sandbox create --help:\n{}",
            output.combined
        );
    }
}

#[test]
fn sandbox_connect_help_shows_editor_flag() {
    let output = run_isolated(&["sandbox", "connect", "--help"]);
    assert_eq!(
        output.code, 0,
        "sandbox connect --help:\n{}",
        output.combined
    );
    assert!(output.combined.contains("--editor"), "{}", output.combined);
}

#[test]
fn gateway_add_help_shows_endpoint_and_gateway_type_flags() {
    let output = run_isolated(&["gateway", "add", "--help"]);
    assert_eq!(output.code, 0, "gateway add --help:\n{}", output.combined);

    for expected in ["--name", "--remote", "--local"] {
        assert!(
            output.combined.contains(expected),
            "expected '{expected}' in gateway add --help:\n{}",
            output.combined
        );
    }
    assert!(
        output.combined.contains("endpoint") || output.combined.contains("<ENDPOINT>"),
        "expected endpoint argument in gateway add --help:\n{}",
        output.combined
    );
}

#[test]
fn gateway_login_help_describes_authentication() {
    let output = run_isolated(&["gateway", "login", "--help"]);
    assert_eq!(output.code, 0, "gateway login --help:\n{}", output.combined);

    let help = output.combined.to_lowercase();
    assert!(
        ["authenticat", "cloudflare", "login", "browser"]
            .iter()
            .any(|term| help.contains(term)),
        "expected auth-related gateway login help:\n{}",
        output.combined
    );
}

#[test]
fn removed_gateway_lifecycle_subcommands_fail_to_parse() {
    for command in ["start", "stop", "destroy"] {
        let output = run_isolated(&["gateway", command, "--help"]);
        assert_ne!(
            output.code, 0,
            "gateway {command} should fail after lifecycle command removal"
        );
        assert!(
            output.combined.contains("unrecognized subcommand")
                || output.combined.contains("error:"),
            "expected parser error for gateway {command}:\n{}",
            output.combined
        );
    }
}

#[test]
fn gateway_add_rejects_conflicting_type_flags() {
    let conflicting = run_isolated(&[
        "gateway",
        "add",
        "https://example.com",
        "--remote",
        "user@host",
        "--local",
    ]);
    assert_ne!(
        conflicting.code, 0,
        "--remote and --local should conflict:\n{}",
        conflicting.combined
    );
}

#[test]
fn gateway_add_rejects_removed_ssh_key_flag() {
    let removed = run_isolated(&[
        "gateway",
        "add",
        "https://example.com",
        "--ssh-key",
        "/tmp/fake-key",
    ]);
    assert_ne!(
        removed.code, 0,
        "removed --ssh-key flag should fail:\n{}",
        removed.combined
    );
}

/// Upper bound for the overview every agent loads first. If this fails, move
/// detail out of the overview rather than raising the bound casually.
const AGENT_OVERVIEW_BUDGET_BYTES: usize = 10_000;
/// Upper bound for one section. If this fails, split the section in
/// `AGENT_SECTIONS` so agents keep loading only what they need.
const AGENT_SECTION_BUDGET_BYTES: usize = 24_000;

/// Section names and their leaf command paths, parsed from the overview.
fn overview_sections(overview: &str) -> Vec<(String, Vec<String>)> {
    let mut sections: Vec<(String, Vec<String>)> = Vec::new();
    let body = overview
        .split_once("\n## Sections\n")
        .map_or("", |(_, body)| body);
    for line in body.lines() {
        if let Some(name) = line.strip_prefix("### ") {
            sections.push((name.to_string(), Vec::new()));
        } else if let Some(entry) = line.strip_prefix("  ")
            && let Some((_, leaves)) = sections.last_mut()
        {
            let path = entry.split("  ").next().unwrap_or_default();
            leaves.push(path.to_string());
        }
    }
    sections
}

#[test]
fn agent_context_overview_lists_every_section_without_details() {
    // Force color to prove the reference stays plain even when styling is on.
    let output = run_isolated(&["--color", "always", "agent", "context"]);
    assert_eq!(output.code, 0, "agent context:\n{}", output.combined);
    let overview = &output.stdout;

    for expected in [
        "## Global flags",
        "## Sections",
        "### sandboxes",
        "### providers",
        "  sandbox create",
        "  provider refresh configure",
        "  workspace member add",
        "  agent context",
    ] {
        assert!(
            overview.contains(expected),
            "expected '{expected}' in agent context overview:\n{overview}"
        );
    }
    for unexpected in ["### other", "Usage:", "doctor", "ssh-proxy", "\x1b"] {
        assert!(
            !overview.contains(unexpected),
            "unexpected '{unexpected}' in agent context overview:\n{overview}"
        );
    }
    assert!(
        overview.len() <= AGENT_OVERVIEW_BUDGET_BYTES,
        "agent context overview is {} bytes, over the {AGENT_OVERVIEW_BUDGET_BYTES}-byte budget",
        overview.len()
    );
}

#[test]
fn agent_context_sections_document_every_overview_command() {
    let overview = run_isolated(&["agent", "context"]);
    assert_eq!(overview.code, 0, "agent context:\n{}", overview.combined);
    let sections = overview_sections(&overview.stdout);
    assert!(
        sections.len() > 1,
        "expected sections in overview:\n{}",
        overview.stdout
    );

    for (name, leaves) in sections {
        assert!(
            !leaves.is_empty(),
            "section '{name}' lists no commands in the overview:\n{}",
            overview.stdout
        );
        let output = run_isolated(&["--color", "always", "agent", "context", &name]);
        assert_eq!(output.code, 0, "agent context {name}:\n{}", output.combined);
        for leaf in leaves {
            let heading = format!("\n## openshell {leaf}\n");
            assert!(
                output.stdout.contains(&heading),
                "section '{name}' is missing '{leaf}':\n{}",
                output.stdout
            );
        }
        for unexpected in ["## Global flags", "  --keep\n", "\x1b"] {
            assert!(
                !output.stdout.contains(unexpected),
                "unexpected '{unexpected}' in section '{name}':\n{}",
                output.stdout
            );
        }
        assert!(
            output.stdout.len() <= AGENT_SECTION_BUDGET_BYTES,
            "section '{name}' is {} bytes, over the {AGENT_SECTION_BUDGET_BYTES}-byte budget",
            output.stdout.len()
        );
    }
}

#[test]
fn agent_context_section_points_to_related_sections() {
    let output = run_isolated(&["agent", "context", "sandboxes"]);
    assert_eq!(
        output.code, 0,
        "agent context sandboxes:\n{}",
        output.combined
    );

    for expected in [
        "## openshell sandbox create",
        "## openshell logs",
        "(see section providers)",
        "(see section templates)",
    ] {
        assert!(
            output.stdout.contains(expected),
            "expected '{expected}' in sandboxes section:\n{}",
            output.stdout
        );
    }
    assert!(
        !output
            .stdout
            .contains("## openshell sandbox provider attach"),
        "sandbox provider commands belong to the providers section:\n{}",
        output.stdout
    );
}

#[test]
fn agent_context_narrows_to_command_path() {
    let output = run_isolated(&["agent", "context", "sb", "create"]);
    assert_eq!(
        output.code, 0,
        "agent context sb create:\n{}",
        output.combined
    );

    assert!(
        output.stdout.contains("## openshell sandbox create"),
        "expected sandbox create in narrowed agent context:\n{}",
        output.stdout
    );
    for excluded in ["## openshell sandbox list", "## openshell gateway add"] {
        assert!(
            !output.stdout.contains(excluded),
            "unexpected '{excluded}' in narrowed agent context:\n{}",
            output.stdout
        );
    }
}

#[test]
fn agent_context_rejects_unknown_target() {
    let output = run_isolated(&["agent", "context", "bogus"]);
    assert_ne!(
        output.code, 0,
        "unknown target should fail:\n{}",
        output.combined
    );
    for expected in ["unknown section or command `bogus`", "sandboxes"] {
        assert!(
            output.combined.contains(expected),
            "expected '{expected}' in error:\n{}",
            output.combined
        );
    }
}

#[test]
fn agent_without_subcommand_prints_group_help() {
    let output = run_isolated(&["agent"]);
    assert_eq!(output.code, 0, "agent:\n{}", output.combined);
    assert!(
        output.combined.contains("context"),
        "expected context subcommand in agent help:\n{}",
        output.combined
    );
}
