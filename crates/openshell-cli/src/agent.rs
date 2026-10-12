// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Agent-oriented CLI reference rendered from the clap command tree.
//!
//! `openshell agent context` prints every visible command, argument, and flag
//! as one plain-text document, so a coding agent can learn the installed CLI
//! in a single call instead of walking nested `--help` pages. The text is
//! projected from the same clap definitions that parse arguments, which keeps
//! it in lockstep with the binary.
//!
//! The output is deterministic. Commands and arguments appear in definition
//! order, hidden commands and flags are omitted, and no ANSI styling survives.

use std::fmt::Write as _;

use clap::{Arg, ArgAction, Command};
use miette::{Result, miette};

/// Usage notes printed under the header. Each one must hold for every command.
const CONVENTIONS: &[&str] = &[
    "This reference is generated from the installed binary and matches its version.",
    "Global flags apply to every command and are listed once.",
    "Prefer `--output json` where a command offers it. Table output is for people and may change.",
    "Most commands with an optional sandbox name default to the last-used sandbox. Pass the name explicitly in automation.",
    "Run `openshell agent context <COMMAND>...` to print one command group or command.",
];

/// Indentation for argument forms such as `-o, --output <OUTPUT>`.
const ARG_INDENT: &str = "  ";
/// Indentation for argument descriptions and attribute tags.
const ARG_BODY_INDENT: &str = "      ";

/// Render the agent reference for `cmd`, optionally narrowed by `path`.
///
/// `cmd` is the root command, normally `Cli::command()`. `path` names a
/// command group or command, for example `["sandbox", "create"]`. Aliases are
/// accepted in `path`; hidden commands are not.
pub fn render_context(cmd: &Command, path: &[String]) -> Result<String> {
    let mut root = cmd.clone();
    // Propagate global arguments and binary names so subcommand usage lines
    // and argument lists match what `--help` shows.
    root.build();

    let mut out = String::new();
    write_header(&mut out, &root);
    write_global_flags(&mut out, &root);

    let target = find_command(&mut root, path)?;
    if path.is_empty() {
        for child in target.get_subcommands_mut().filter(|c| !c.is_hide_set()) {
            write_tree(&mut out, child);
        }
    } else {
        write_tree(&mut out, target);
    }

    // Example constants embed ANSI escapes, and clap strips styling only when
    // its `color` feature is enabled. Strip unconditionally so agents always
    // receive plain text.
    let text = console::strip_ansi_codes(&out);
    let mut text = text.trim_end().to_string();
    text.push('\n');
    Ok(text)
}

/// Walk `path` from `root` and return the named visible command.
fn find_command<'a>(root: &'a mut Command, path: &[String]) -> Result<&'a mut Command> {
    let mut current = root;
    for segment in path {
        let parent = command_path(current).to_string();
        let available = visible_subcommands(current)
            .map(|c| c.get_name().to_string())
            .collect::<Vec<_>>();
        if available.is_empty() {
            return Err(miette!("`{parent}` has no subcommands"));
        }
        let Some(next) = current
            .get_subcommands_mut()
            .find(|c| !c.is_hide_set() && answers_to(c, segment))
        else {
            return Err(miette!(
                "unknown command `{parent} {segment}`\nAvailable under `{parent}`: {}",
                available.join(", ")
            ));
        };
        current = next;
    }
    Ok(current)
}

fn answers_to(cmd: &Command, name: &str) -> bool {
    cmd.get_name() == name || cmd.get_all_aliases().any(|alias| alias == name)
}

fn visible_subcommands(cmd: &Command) -> impl Iterator<Item = &Command> {
    cmd.get_subcommands().filter(|c| !c.is_hide_set())
}

/// Full invocation path, such as `openshell sandbox create`.
fn command_path(cmd: &Command) -> &str {
    cmd.get_bin_name().unwrap_or_else(|| cmd.get_name())
}

fn write_header(out: &mut String, root: &Command) {
    let _ = write!(out, "# {}", root.get_name());
    if let Some(version) = root.get_version() {
        let _ = write!(out, " {version}");
    }
    out.push('\n');
    if let Some(about) = root.get_about() {
        out.push('\n');
        write_text(out, &about.to_string(), "");
    }
    out.push_str("\nConventions:\n");
    for convention in CONVENTIONS {
        let _ = writeln!(out, "- {convention}");
    }
}

fn write_global_flags(out: &mut String, root: &Command) {
    let globals = root
        .get_arguments()
        .filter(|arg| arg.is_global_set() && is_documented(arg))
        .collect::<Vec<_>>();
    if globals.is_empty() {
        return;
    }
    out.push_str("\n## Global flags\n\n");
    for arg in globals {
        write_arg(out, root, arg);
    }
}

/// Write `cmd` and then each visible descendant, depth first.
fn write_tree(out: &mut String, cmd: &mut Command) {
    write_command(out, cmd);
    for child in cmd.get_subcommands_mut().filter(|c| !c.is_hide_set()) {
        write_tree(out, child);
    }
}

fn write_command(out: &mut String, cmd: &mut Command) {
    let is_group = visible_subcommands(cmd).next().is_some();
    let usage = if is_group {
        None
    } else {
        let usage = cmd.render_usage().to_string();
        let usage = usage.trim();
        Some(
            usage
                .strip_prefix("Usage:")
                .unwrap_or(usage)
                .trim()
                .to_string(),
        )
    };
    let cmd = &*cmd;

    let _ = writeln!(out, "\n## {}\n", command_path(cmd));
    if let Some(about) = cmd.get_long_about().or_else(|| cmd.get_about()) {
        write_text(out, &about.to_string(), "");
        out.push('\n');
    }
    if let Some(usage) = usage {
        let _ = writeln!(out, "Usage: {usage}");
    }
    let aliases = cmd.get_all_aliases().collect::<Vec<_>>();
    if !aliases.is_empty() {
        let _ = writeln!(out, "Aliases: {}", aliases.join(", "));
    }

    if is_group {
        out.push_str("Subcommands:\n");
        let width = visible_subcommands(cmd)
            .map(|c| c.get_name().len())
            .max()
            .unwrap_or_default();
        for child in visible_subcommands(cmd) {
            let about = child.get_about().map(ToString::to_string);
            let line = format!(
                "  {:width$}  {}",
                child.get_name(),
                about.unwrap_or_default()
            );
            let _ = writeln!(out, "{}", line.trim_end());
        }
    }

    let (positionals, flags): (Vec<&Arg>, Vec<&Arg>) = cmd
        .get_arguments()
        .filter(|arg| !arg.is_global_set() && is_documented(arg))
        .partition(|arg| arg.is_positional());
    for (title, args) in [("Arguments", positionals), ("Flags", flags)] {
        if args.is_empty() {
            continue;
        }
        let _ = writeln!(out, "\n{title}:");
        for arg in args {
            write_arg(out, cmd, arg);
        }
    }

    let examples = examples(cmd);
    if !examples.is_empty() {
        out.push_str("\nExamples:\n");
        for example in examples {
            let _ = writeln!(out, "  {example}");
        }
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

fn write_arg(out: &mut String, cmd: &Command, arg: &Arg) {
    let _ = writeln!(out, "{ARG_INDENT}{}", arg_form(arg));
    if let Some(help) = arg.get_long_help().or_else(|| arg.get_help()) {
        write_text(out, &help.to_string(), ARG_BODY_INDENT);
    }
    let tags = arg_tags(cmd, arg);
    if !tags.is_empty() {
        let tags = tags
            .iter()
            .map(|tag| format!("[{tag}]"))
            .collect::<Vec<_>>()
            .join(" ");
        let _ = writeln!(out, "{ARG_BODY_INDENT}{tags}");
    }
    if !arg.is_hide_possible_values_set() {
        for value in arg.get_possible_values() {
            if let Some(help) = value.get_help().filter(|_| !value.is_hide_set()) {
                let _ = writeln!(out, "{ARG_BODY_INDENT}- {}: {help}", value.get_name());
            }
        }
    }
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

/// Short name used when one argument refers to another, such as in conflicts.
fn arg_reference(arg: &Arg) -> String {
    arg.get_long().map_or_else(
        || {
            arg.get_short()
                .map_or_else(|| arg_form(arg), |short| format!("-{short}"))
        },
        |long| format!("--{long}"),
    )
}

fn arg_tags(cmd: &Command, arg: &Arg) -> Vec<String> {
    let mut tags = Vec::new();
    if arg.is_required_set() {
        tags.push("required".to_string());
    }
    if !arg.is_positional() && matches!(arg.get_action(), ArgAction::Append | ArgAction::Count) {
        tags.push("repeatable".to_string());
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
    let conflicts = conflicts(cmd, arg);
    if !conflicts.is_empty() {
        tags.push(format!("conflicts with: {}", conflicts.join(", ")));
    }
    tags
}

/// Visible arguments that cannot be combined with `arg`, from either side of
/// the declaration, in definition order.
fn conflicts(cmd: &Command, arg: &Arg) -> Vec<String> {
    if arg.is_global_set() {
        return Vec::new();
    }
    let declared = cmd.get_arg_conflicts_with(arg);
    cmd.get_arguments()
        .filter(|other| other.get_id() != arg.get_id() && is_documented(other))
        .filter(|other| !other.is_global_set())
        .filter(|other| {
            declared.iter().any(|d| d.get_id() == other.get_id())
                || cmd
                    .get_arg_conflicts_with(other)
                    .iter()
                    .any(|c| c.get_id() == arg.get_id())
        })
        .map(arg_reference)
        .collect()
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

/// Write `text` with each non-empty line prefixed by `indent`.
fn write_text(out: &mut String, text: &str, indent: &str) {
    for line in text.trim().lines() {
        let line = line.trim_end();
        if line.is_empty() {
            out.push('\n');
        } else {
            let _ = writeln!(out, "{indent}{line}");
        }
    }
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
                                Arg::new("fast")
                                    .long("fast")
                                    .action(ArgAction::SetTrue)
                                    .conflicts_with("slow")
                                    .help("Go fast."),
                            )
                            .arg(
                                Arg::new("slow")
                                    .long("slow")
                                    .action(ArgAction::SetTrue)
                                    .help("Go slow."),
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
                                    .action(ArgAction::Append),
                            ),
                    )
                    .subcommand(Command::new("list").about("List boxes."))
                    .subcommand(Command::new("secret").about("Hidden box.").hide(true)),
            )
            .subcommand(Command::new("ping").about("Ping the server."))
            .subcommand(Command::new("debug").about("Hidden command.").hide(true))
    }

    fn render(path: &[&str]) -> Result<String> {
        let path = path.iter().map(ToString::to_string).collect::<Vec<_>>();
        render_context(&fixture(), &path)
    }

    #[test]
    fn renders_every_visible_command_with_usage() {
        let text = render(&[]).expect("render");

        assert!(text.starts_with("# tool 1.2.3\n"), "{text}");
        for heading in [
            "## tool box\n",
            "## tool box create\n",
            "## tool box list\n",
            "## tool ping\n",
        ] {
            assert!(text.contains(heading), "missing {heading:?}:\n{text}");
        }
        assert!(
            text.contains("Usage: tool box create [OPTIONS] <name> [-- <command>...]"),
            "{text}"
        );
        assert!(text.contains("Aliases: bx"), "{text}");
        assert!(text.contains("The box starts empty."), "{text}");
    }

    #[test]
    fn omits_hidden_commands_flags_and_help() {
        let text = render(&[]).expect("render");

        for hidden in [
            "secret",
            "debug",
            "--legacy",
            "--internal",
            "--help",
            "--version",
        ] {
            assert!(!text.contains(hidden), "unexpected {hidden:?}:\n{text}");
        }
    }

    #[test]
    fn lists_global_flags_once() {
        let text = render(&[]).expect("render");

        assert!(text.contains("## Global flags"), "{text}");
        assert_eq!(text.matches("--profile").count(), 1, "{text}");
        assert!(text.contains("[env: TOOL_PROFILE]"), "{text}");
    }

    #[test]
    fn describes_argument_attributes() {
        let text = render(&["box", "create"]).expect("render");

        assert!(
            text.contains("  <name>\n      Box name.\n      [required]"),
            "{text}"
        );
        assert!(
            text.contains("  -o, --output <output>\n      Output format.\n      [default: table] [values: table, json]"),
            "{text}"
        );
        assert!(
            text.contains("  --label <label>\n      Label to add.\n      [repeatable]"),
            "{text}"
        );
        assert!(text.contains("  -- <command>..."), "{text}");
    }

    #[test]
    fn reports_conflicts_from_both_sides() {
        let text = render(&["box", "create"]).expect("render");

        assert!(
            text.contains("Go fast.\n      [conflicts with: --slow]"),
            "{text}"
        );
        assert!(
            text.contains("Go slow.\n      [conflicts with: --fast]"),
            "{text}"
        );
    }

    #[test]
    fn lists_group_subcommands_and_plain_examples() {
        let text = render(&["box"]).expect("render");

        assert!(
            text.contains("Subcommands:\n  create  Create a box.\n  list    List boxes.\n"),
            "{text}"
        );
        assert!(
            text.contains("Examples:\n  $ tool box create demo\n  $ tool box list\n"),
            "{text}"
        );
        assert!(!text.contains('\x1b'), "{text:?}");
        assert!(!text.contains("ALIAS"), "{text}");
    }

    #[test]
    fn path_narrows_output_and_accepts_aliases() {
        let text = render(&["bx", "create"]).expect("render");

        assert!(text.contains("## tool box create"), "{text}");
        assert!(!text.contains("## tool box list"), "{text}");
        assert!(!text.contains("## tool ping"), "{text}");
        assert!(text.contains("## Global flags"), "{text}");
    }

    #[test]
    fn unknown_or_hidden_path_lists_available_commands() {
        for path in [&["bogus"][..], &["debug"][..]] {
            let err = render(path).expect_err("unknown command should fail");
            let message = err.to_string();
            assert!(
                message.contains("Available under `tool`: box, ping"),
                "{message}"
            );
        }

        let err = render(&["box", "secret"]).expect_err("hidden subcommand should fail");
        assert!(
            err.to_string()
                .contains("Available under `tool box`: create, list"),
            "{err}"
        );

        let err = render(&["ping", "extra"]).expect_err("leaf has no subcommands");
        assert!(
            err.to_string().contains("`tool ping` has no subcommands"),
            "{err}"
        );
    }

    #[test]
    fn output_is_deterministic_and_plain() {
        let first = render(&[]).expect("render");
        let second = render(&[]).expect("render");

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
