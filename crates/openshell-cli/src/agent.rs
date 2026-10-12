// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Agent-oriented CLI reference rendered from the clap command tree.
//!
//! `openshell agent context` prints one compact reference that lists every
//! visible command with its usage line and description, and every flag with
//! its description, allowed values, default, and environment variable. Each
//! description is complete but folded onto one line, so a coding agent can
//! bootstrap from that single call and fall back to `--help` only for flag
//! constraints. The text is projected from the clap definitions that parse
//! arguments, so it cannot drift from the binary.
//!
//! The output is deterministic. Commands and arguments appear in definition
//! order, hidden commands and flags are omitted, and no ANSI styling survives.

use std::fmt::Write as _;

use clap::{Arg, ArgAction, Command};

/// Usage notes printed under the title. Each one must hold for every command.
const CONVENTIONS: &[&str] = &[
    "This reference is generated from the installed binary, so it matches this version exactly.",
    "Global flags work with every command and are listed once.",
    "Prefer `--output json` where a command offers it. Table output is for people and may change.",
    "Most commands with an optional sandbox name default to the last-used sandbox. Pass the name explicitly in automation.",
    "Descriptions are complete but folded onto one line. Run `openshell <command> --help` for flag constraints, such as which flags conflict.",
];

/// Widest argument form that sets the description column. Longer forms are
/// followed by two spaces so one long flag cannot pad a whole block.
const MAX_FORM_WIDTH: usize = 32;

/// Render the agent reference for the root command `cmd`, normally
/// `Cli::command()`.
pub fn render_context(cmd: &Command) -> String {
    let mut root = cmd.clone();
    // Propagate global arguments and binary names so usage lines match what
    // `--help` shows.
    root.build();

    let mut out = String::new();
    write_header(&mut out, &root);
    for command in root.get_subcommands_mut().filter(|c| !c.is_hide_set()) {
        write_top_level(&mut out, command);
    }

    // Example constants embed ANSI escapes, and clap strips styling only when
    // its `color` feature is enabled. Strip unconditionally so agents always
    // receive plain text.
    let text = console::strip_ansi_codes(&out);
    let mut text = text.trim_end().to_string();
    text.push('\n');
    text
}

fn write_header(out: &mut String, root: &Command) {
    let _ = write!(out, "# {}", root.get_name());
    if let Some(version) = root.get_version() {
        let _ = write!(out, " {version}");
    }
    out.push('\n');
    if let Some(about) = root.get_about() {
        let _ = writeln!(out, "\n{}", one_line(&about.to_string()));
    }
    out.push_str("\nConventions:\n");
    for convention in CONVENTIONS {
        let _ = writeln!(out, "- {convention}");
    }

    let globals = root
        .get_arguments()
        .filter(|arg| arg.is_global_set() && is_documented(arg))
        .collect::<Vec<_>>();
    if !globals.is_empty() {
        out.push_str("\n## Global flags\n\n");
        write_args(out, &globals);
    }
}

/// Write one top-level command: a heading, every visible leaf command beneath
/// it, and the examples from its help text.
fn write_top_level(out: &mut String, cmd: &mut Command) {
    let _ = write!(out, "\n## {}", cmd.get_name());
    if let Some(about) = cmd.get_about() {
        let _ = write!(out, ": {}", one_line(&about.to_string()));
    }
    let aliases = cmd.get_all_aliases().collect::<Vec<_>>();
    match aliases.as_slice() {
        [] => {}
        [alias] => {
            let _ = write!(out, " (alias: {alias})");
        }
        _ => {
            let _ = write!(out, " (aliases: {})", aliases.join(", "));
        }
    }
    out.push('\n');

    let is_leaf = visible_subcommands(cmd).next().is_none();
    // A top-level leaf already shows its summary in the heading.
    write_leaves(out, cmd, !is_leaf);

    let examples = examples(cmd);
    if !examples.is_empty() {
        out.push_str("\nExamples:\n");
        for example in examples {
            let _ = writeln!(out, "  {example}");
        }
    }
}

/// Write every visible leaf command under `cmd`, depth first.
fn write_leaves(out: &mut String, cmd: &mut Command, show_about: bool) {
    if visible_subcommands(cmd).next().is_some() {
        for child in cmd.get_subcommands_mut().filter(|c| !c.is_hide_set()) {
            write_leaves(out, child, true);
        }
        return;
    }

    let usage = cmd.render_usage().to_string();
    let usage = usage.trim();
    let usage = usage.strip_prefix("Usage:").unwrap_or(usage).trim();
    let _ = writeln!(out, "\n{usage}");
    if show_about && let Some(about) = cmd.get_long_about().or_else(|| cmd.get_about()) {
        let _ = writeln!(out, "  {}", one_line(&about.to_string()));
    }
    let args = cmd
        .get_arguments()
        .filter(|arg| !arg.is_global_set() && is_documented(arg))
        .collect::<Vec<_>>();
    write_args(out, &args);
}

/// Write one aligned line per argument: form, description, and attribute tags.
fn write_args(out: &mut String, args: &[&Arg]) {
    let forms = args.iter().map(|arg| arg_form(arg)).collect::<Vec<_>>();
    let width = forms
        .iter()
        .map(String::len)
        .filter(|len| *len <= MAX_FORM_WIDTH)
        .max()
        .unwrap_or_default();
    for (arg, form) in args.iter().zip(forms) {
        let mut line = format!("  {form:width$}");
        if let Some(help) = arg.get_long_help().or_else(|| arg.get_help()) {
            let _ = write!(line, "  {}", one_line(&help.to_string()));
        }
        for tag in arg_tags(arg) {
            let _ = write!(line, " [{tag}]");
        }
        let _ = writeln!(out, "{}", line.trim_end());
    }
}

/// Arguments worth listing: visible and not the built-in help or version flags.
fn is_documented(arg: &Arg) -> bool {
    !arg.is_hide_set()
        && !matches!(
            arg.get_action(),
            ArgAction::Help | ArgAction::HelpShort | ArgAction::HelpLong | ArgAction::Version
        )
}

fn visible_subcommands(cmd: &Command) -> impl Iterator<Item = &Command> {
    cmd.get_subcommands().filter(|c| !c.is_hide_set())
}

/// How the argument is written on the command line, such as
/// `-o, --output <OUTPUT>` or `-- <COMMAND>...`.
fn arg_form(arg: &Arg) -> String {
    let value = value_form(arg);
    if arg.is_positional() {
        return if arg.is_last_set() {
            format!("-- {value}")
        } else {
            value
        };
    }
    let mut form = String::new();
    if let Some(short) = arg.get_short() {
        let _ = write!(form, "-{short}");
        if arg.get_long().is_some() {
            form.push_str(", ");
        }
    }
    if let Some(long) = arg.get_long() {
        let _ = write!(form, "--{long}");
    }
    if !value.is_empty() {
        let _ = write!(form, " {value}");
    }
    form
}

/// Value placeholder for an argument, such as `<NAME>`, `[<COUNT>]`, or
/// `<COMMAND>...`. Empty for flags that take no value.
fn value_form(arg: &Arg) -> String {
    if !arg.get_action().takes_values() {
        return String::new();
    }
    // clap's own help falls back to the argument id when no value name is set.
    let names = arg.get_value_names().map_or_else(
        || vec![arg.get_id().to_string()],
        |names| names.iter().map(ToString::to_string).collect(),
    );
    let mut value = names
        .iter()
        .map(|name| format!("<{name}>"))
        .collect::<Vec<_>>()
        .join(" ");
    let range = arg.get_num_args().unwrap_or_default();
    if range.max_values() > names.len() {
        value.push_str("...");
    }
    if range.min_values() == 0 {
        value = format!("[{value}]");
    }
    value
}

fn arg_tags(arg: &Arg) -> Vec<String> {
    let mut tags = Vec::new();
    if arg.is_required_set() {
        tags.push("required".to_string());
    }
    if !arg.is_positional() && matches!(arg.get_action(), ArgAction::Append | ArgAction::Count) {
        tags.push("repeatable".to_string());
    }
    if !arg.is_hide_possible_values_set() {
        let values = arg
            .get_possible_values()
            .into_iter()
            .filter(|value| !value.is_hide_set())
            .map(|value| value.get_name().to_string())
            .collect::<Vec<_>>();
        if !values.is_empty() {
            tags.push(format!("values: {}", values.join(", ")));
        }
    }
    if arg.get_action().takes_values() && !arg.is_hide_default_value_set() {
        let defaults = arg
            .get_default_values()
            .iter()
            .map(|value| value.to_string_lossy().into_owned())
            .filter(|value| !value.is_empty())
            .collect::<Vec<_>>();
        if !defaults.is_empty() {
            tags.push(format!("default: {}", defaults.join(", ")));
        }
    }
    if !arg.is_hide_env_set()
        && let Some(env) = arg.get_env()
    {
        tags.push(format!("env: {}", env.to_string_lossy()));
    }
    tags
}

/// Example invocations from the command's after-help text. Every example
/// constant in the CLI writes invocations as lines starting with `$ `.
fn examples(cmd: &Command) -> Vec<String> {
    [cmd.get_after_help(), cmd.get_after_long_help()]
        .into_iter()
        .flatten()
        .flat_map(|text| {
            text.to_string()
                .lines()
                .map(str::trim)
                .filter(|line| line.starts_with("$ "))
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        })
        .collect()
}

/// Collapse whitespace so a description always fits on one line.
fn one_line(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLES: &str = "\x1b[1mALIAS\x1b[0m
  bx

\x1b[1mEXAMPLES\x1b[0m
  $ tool box create demo
  $ tool box list
";

    fn fixture() -> Command {
        Command::new("tool")
            .version("1.2.3")
            .about("Fixture CLI.")
            .disable_help_subcommand(true)
            .arg(
                Arg::new("profile")
                    .long("profile")
                    .short('p')
                    .global(true)
                    .env("TOOL_PROFILE")
                    .help("Profile to use."),
            )
            .arg(
                Arg::new("internal")
                    .long("internal")
                    .global(true)
                    .hide(true)
                    .action(ArgAction::SetTrue),
            )
            .subcommand(
                Command::new("box")
                    .about("Manage boxes.")
                    .alias("bx")
                    .after_help(EXAMPLES)
                    .subcommand(
                        Command::new("create")
                            .about("Create a box.")
                            .long_about("Create a box.\n\nThe box starts empty.")
                            .arg(Arg::new("name").required(true).help("Box name."))
                            .arg(
                                Arg::new("output")
                                    .short('o')
                                    .long("output")
                                    .value_parser(["table", "json"])
                                    .default_value("table")
                                    .help("Output format."),
                            )
                            .arg(
                                Arg::new("label")
                                    .long("label")
                                    .action(ArgAction::Append)
                                    .help("Label to add."),
                            )
                            .arg(
                                Arg::new("size")
                                    .long("size")
                                    .help("Box size.")
                                    .long_help("Box size.\n\nLarger boxes take longer."),
                            )
                            .arg(
                                Arg::new("legacy")
                                    .long("legacy")
                                    .action(ArgAction::SetTrue)
                                    .hide(true),
                            )
                            .arg(
                                Arg::new("command")
                                    .last(true)
                                    .num_args(1..)
                                    .action(ArgAction::Append)
                                    .help("Command to run."),
                            ),
                    )
                    .subcommand(Command::new("list").about("List boxes."))
                    .subcommand(
                        Command::new("shelf")
                            .about("Manage shelves.")
                            .subcommand(Command::new("add").about("Add a shelf.")),
                    )
                    .subcommand(Command::new("secret").about("Hidden box.").hide(true)),
            )
            .subcommand(
                Command::new("ping")
                    .about("Ping the server.")
                    .alias("p")
                    .alias("pg"),
            )
            .subcommand(Command::new("debug").about("Hidden command.").hide(true))
    }

    #[test]
    fn renders_header_conventions_and_global_flags_once() {
        let text = render_context(&fixture());

        assert!(
            text.starts_with("# tool 1.2.3\n\nFixture CLI.\n\nConventions:\n"),
            "{text}"
        );
        assert!(
            text.contains("## Global flags\n\n  -p, --profile <profile>  Profile to use. [env: TOOL_PROFILE]\n"),
            "{text}"
        );
        assert_eq!(text.matches("--profile").count(), 1, "{text}");
    }

    #[test]
    fn lists_every_visible_leaf_with_usage_and_summary() {
        let text = render_context(&fixture());

        assert!(
            text.contains("## box: Manage boxes. (alias: bx)\n"),
            "{text}"
        );
        assert!(
            text.contains(
                "\ntool box create [OPTIONS] <name> [-- <command>...]\n  Create a box. The box starts empty.\n"
            ),
            "{text}"
        );
        assert!(
            text.contains("\ntool box list [OPTIONS]\n  List boxes.\n"),
            "{text}"
        );
        assert!(
            text.contains("\ntool box shelf add [OPTIONS]\n  Add a shelf.\n"),
            "{text}"
        );
        // A top-level leaf shows its summary once, in the heading.
        assert!(
            text.contains("## ping: Ping the server. (aliases: p, pg)\n\ntool ping [OPTIONS]\n"),
            "{text}"
        );
        assert_eq!(text.matches("Ping the server.").count(), 1, "{text}");
    }

    #[test]
    fn describes_each_argument_on_one_line() {
        let text = render_context(&fixture());

        for line in [
            "  Create a box. The box starts empty.",
            "  <name>                 Box name. [required]",
            "  -o, --output <output>  Output format. [values: table, json] [default: table]",
            "  --label <label>        Label to add. [repeatable]",
            "  --size <size>          Box size. Larger boxes take longer.",
            "  -- <command>...        Command to run.",
        ] {
            assert!(
                text.contains(&format!("{line}\n")),
                "missing {line:?}:\n{text}"
            );
        }
    }

    #[test]
    fn omits_hidden_commands_flags_and_help() {
        let text = render_context(&fixture());

        for hidden in [
            "secret",
            "debug",
            "--legacy",
            "--internal",
            "-h, --help",
            "-V, --version",
        ] {
            assert!(!text.contains(hidden), "unexpected {hidden:?}:\n{text}");
        }
    }

    #[test]
    fn includes_plain_examples() {
        let text = render_context(&fixture());

        assert!(
            text.contains("\nExamples:\n  $ tool box create demo\n  $ tool box list\n"),
            "{text}"
        );
        assert!(!text.contains('\x1b'), "{text:?}");
        assert!(!text.contains("ALIAS"), "{text}");
    }

    #[test]
    fn output_is_deterministic_and_plain() {
        let first = render_context(&fixture());
        let second = render_context(&fixture());

        assert_eq!(first, second);
        assert!(
            first.ends_with('\n') && !first.ends_with("\n\n"),
            "{first:?}"
        );
        for line in first.lines() {
            assert_eq!(line, line.trim_end(), "trailing whitespace in {line:?}");
        }
    }
}
