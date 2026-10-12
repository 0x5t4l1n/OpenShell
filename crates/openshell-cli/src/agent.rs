// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Agent-oriented CLI reference rendered from the clap command tree.
//!
//! `openshell agent context` gives a coding agent the installed CLI in a few
//! calls instead of a walk through nested `--help` pages. Without arguments it
//! prints global flags and an overview of every command, grouped into
//! sections of commands that are used together. A section name prints the
//! full usage, flags, and examples of that section's commands, and a command
//! path prints one command or command group.
//!
//! Everything except the section grouping is projected from the clap
//! definitions that parse arguments, so the reference cannot drift from the
//! binary. Commands that no section claims still appear, in an `other`
//! section, and [`section_problems`] lets a test require that every command is
//! assigned.
//!
//! The output is deterministic. Commands and arguments appear in definition
//! order, hidden commands and flags are omitted, and no ANSI styling survives.

use std::fmt::Write as _;

use clap::{Arg, ArgAction, Command};
use miette::{Result, miette};

/// Usage notes printed in the overview. Each one must hold for every command.
const CONVENTIONS: &[&str] = &[
    "This reference is generated from the installed binary and matches its version.",
    "Global flags apply to every command and are listed only in this overview.",
    "Prefer `--output json` where a command offers it. Table output is for people and may change.",
    "Most commands with an optional sandbox name default to the last-used sandbox. Pass the name explicitly in automation.",
];

/// Section that collects visible commands no configured section claims.
const OTHER_SECTION: &str = "other";

/// Indentation for argument forms such as `-o, --output <OUTPUT>`.
const ARG_INDENT: &str = "  ";
/// Indentation for argument descriptions and attribute tags.
const ARG_BODY_INDENT: &str = "      ";

/// A named group of commands that agents usually need together.
#[derive(Debug, Clone, Copy)]
pub struct ContextSection {
    /// Name passed to `agent context`, such as `sandboxes`. Must not match a
    /// top-level command name or alias.
    pub name: &'static str,
    /// One-line description shown in the overview.
    pub summary: &'static str,
    /// Command paths relative to the root, such as `sandbox` or
    /// `sandbox provider`. A path includes its subcommands, except subtrees
    /// that another section claims with a longer path.
    pub commands: &'static [&'static str],
}

/// Render the agent reference for the root command `cmd`.
///
/// `cmd` is normally `Cli::command()`. With an empty `target` the result is
/// the overview. A single `target` that names a section renders that section.
/// Otherwise `target` is a command path such as `["sandbox", "create"]`;
/// aliases are accepted and hidden commands are not.
pub fn render_context(
    cmd: &Command,
    sections: &[ContextSection],
    target: &[String],
) -> Result<String> {
    let mut root = cmd.clone();
    // Propagate global arguments and binary names so subcommand usage lines
    // and argument lists match what `--help` shows.
    root.build();
    let layout = Layout::new(&root, sections);

    let section = match target {
        [name] => layout.index_of(name),
        _ => None,
    };
    let mut out = String::new();
    if target.is_empty() {
        write_overview(&mut out, &root, &layout);
    } else if let Some(index) = section {
        write_section(&mut out, &mut root, &layout, index);
    } else {
        if !visible_subcommands(&root).any(|c| answers_to(c, &target[0])) {
            return Err(miette!(
                "unknown section or command `{}`\nSections: {}\nCommands: {}",
                target[0],
                layout.names().join(", "),
                visible_subcommands(&root)
                    .map(Command::get_name)
                    .collect::<Vec<_>>()
                    .join(", "),
            ));
        }
        write_title(&mut out, &root, Some(&target.join(" ")));
        write_overview_pointer(&mut out, &root);
        let command = find_command(&mut root, target)?;
        write_tree(&mut out, command);
    }

    // Example constants embed ANSI escapes, and clap strips styling only when
    // its `color` feature is enabled. Strip unconditionally so agents always
    // receive plain text.
    let text = console::strip_ansi_codes(&out);
    let mut text = text.trim_end().to_string();
    text.push('\n');
    Ok(text)
}

/// Describe every way `sections` fails to cover `cmd` cleanly.
///
/// Returns an empty list when every visible top-level command belongs to a
/// section, every section path names a visible command by its canonical
/// name, no path is claimed twice, and section names are unique and distinct
/// from top-level command names and aliases.
pub fn section_problems(cmd: &Command, sections: &[ContextSection]) -> Vec<String> {
    let mut problems = Vec::new();

    let mut names = Vec::new();
    let mut paths = Vec::new();
    for section in sections {
        if names.contains(&section.name) {
            problems.push(format!("section `{}` is defined twice", section.name));
        }
        names.push(section.name);
        if section.name == OTHER_SECTION {
            problems.push(format!("section name `{OTHER_SECTION}` is reserved"));
        }
        if visible_subcommands(cmd).any(|c| answers_to(c, section.name)) {
            problems.push(format!(
                "section `{}` has the same name as a command",
                section.name
            ));
        }
        for path in section.commands {
            if paths.contains(path) {
                problems.push(format!("command `{path}` is claimed by two sections"));
            }
            paths.push(path);
            if !is_visible_path(cmd, path) {
                problems.push(format!(
                    "section `{}` names `{path}`, which is not a visible command",
                    section.name
                ));
            }
        }
    }

    let layout = Layout::configured(sections);
    for command in visible_subcommands(cmd) {
        if layout.owner(command.get_name()).is_none() {
            problems.push(format!(
                "command `{}` is not in any section",
                command.get_name()
            ));
        }
    }
    problems
}

/// Sections resolved against a built command tree, including a trailing
/// `other` section when some visible top-level commands are unclaimed.
struct Layout {
    sections: Vec<ResolvedSection>,
}

struct ResolvedSection {
    name: &'static str,
    summary: &'static str,
    roots: Vec<String>,
}

impl Layout {
    /// The configured sections only, without the `other` fallback.
    fn configured(sections: &[ContextSection]) -> Self {
        Self {
            sections: sections
                .iter()
                .map(|section| ResolvedSection {
                    name: section.name,
                    summary: section.summary,
                    roots: section.commands.iter().map(ToString::to_string).collect(),
                })
                .collect(),
        }
    }

    fn new(root: &Command, sections: &[ContextSection]) -> Self {
        let mut layout = Self::configured(sections);
        let unclaimed = visible_subcommands(root)
            .map(|c| c.get_name().to_string())
            .filter(|name| layout.owner(name).is_none())
            .collect::<Vec<_>>();
        if !unclaimed.is_empty() {
            layout.sections.push(ResolvedSection {
                name: OTHER_SECTION,
                summary: "Commands that are not assigned to a section yet.",
                roots: unclaimed,
            });
        }
        layout
    }

    fn names(&self) -> Vec<&'static str> {
        self.sections.iter().map(|section| section.name).collect()
    }

    fn index_of(&self, name: &str) -> Option<usize> {
        self.sections
            .iter()
            .position(|section| section.name == name)
    }

    /// Index of the section that owns the command at `path`: the section
    /// whose claimed path is the longest prefix of `path`. Duplicate claims
    /// are rejected by [`section_problems`], so ties do not arise in practice.
    fn owner(&self, path: &str) -> Option<usize> {
        self.sections
            .iter()
            .enumerate()
            .flat_map(|(index, section)| section.roots.iter().map(move |root| (index, root)))
            .filter(|(_, root)| {
                path == root.as_str()
                    || path
                        .strip_prefix(root.as_str())
                        .is_some_and(|rest| rest.starts_with(' '))
            })
            .max_by_key(|(_, root)| root.len())
            .map(|(index, _)| index)
    }
}

fn write_overview(out: &mut String, root: &Command, layout: &Layout) {
    write_title(out, root, None);
    if let Some(about) = root.get_about() {
        out.push('\n');
        write_text(out, &about.to_string(), "");
    }
    let name = root.get_name();
    let _ = writeln!(
        out,
        "\nThis overview lists every command by section. Run `{name} agent context <SECTION>` \
         for the usage, flags, and examples of every command in a section, or \
         `{name} agent context <COMMAND>...` for one command or command group."
    );
    out.push_str("\nConventions:\n");
    for convention in CONVENTIONS {
        let _ = writeln!(out, "- {convention}");
    }
    write_global_flags(out, root);

    out.push_str("\n## Sections\n");
    for (index, section) in layout.sections.iter().enumerate() {
        let _ = writeln!(out, "\n### {}\n\n{}\n", section.name, section.summary);
        let mut leaves = Vec::new();
        for path in &section.roots {
            if let Some(command) = lookup(root, path) {
                collect_leaves(command, path, layout, index, &mut leaves);
            }
        }
        let width = leaves
            .iter()
            .map(|(path, _)| path.len())
            .max()
            .unwrap_or_default();
        for (path, about) in leaves {
            let line = format!("  {path:width$}  {about}");
            let _ = writeln!(out, "{}", line.trim_end());
        }
    }
}

/// Collect `(path, summary)` for each visible leaf command under `cmd` that
/// belongs to section `index`.
fn collect_leaves(
    cmd: &Command,
    path: &str,
    layout: &Layout,
    index: usize,
    leaves: &mut Vec<(String, String)>,
) {
    let mut children = visible_subcommands(cmd).peekable();
    if children.peek().is_none() {
        let about = cmd.get_about().map(ToString::to_string).unwrap_or_default();
        leaves.push((path.to_string(), about));
        return;
    }
    for child in children {
        let child_path = format!("{path} {}", child.get_name());
        if layout.owner(&child_path) == Some(index) {
            collect_leaves(child, &child_path, layout, index, leaves);
        }
    }
}

fn write_section(out: &mut String, root: &mut Command, layout: &Layout, index: usize) {
    let section = &layout.sections[index];
    write_title(out, root, Some(section.name));
    let _ = writeln!(out, "\n{}", section.summary);
    write_overview_pointer(out, root);
    for path in &section.roots {
        if let Some(command) = lookup_mut(root, path) {
            write_section_tree(out, command, path, layout, index);
        }
    }
}

/// Write `cmd` and each visible descendant that belongs to section `index`.
fn write_section_tree(
    out: &mut String,
    cmd: &mut Command,
    path: &str,
    layout: &Layout,
    index: usize,
) {
    let elsewhere = |child: &str| {
        let owner = layout.owner(&format!("{path} {child}"))?;
        (owner != index).then(|| layout.sections[owner].name)
    };
    write_command(out, cmd, &elsewhere);
    for child in cmd.get_subcommands_mut().filter(|c| !c.is_hide_set()) {
        let child_path = format!("{path} {}", child.get_name());
        if layout.owner(&child_path) == Some(index) {
            write_section_tree(out, child, &child_path, layout, index);
        }
    }
}

/// Write `cmd` and every visible descendant, depth first.
fn write_tree(out: &mut String, cmd: &mut Command) {
    write_command(out, cmd, &|_| None);
    for child in cmd.get_subcommands_mut().filter(|c| !c.is_hide_set()) {
        write_tree(out, child);
    }
}

/// Resolve a canonical command path such as `sandbox provider`.
fn lookup<'a>(root: &'a Command, path: &str) -> Option<&'a Command> {
    path.split(' ')
        .try_fold(root, |cmd, name| cmd.find_subcommand(name))
}

fn lookup_mut<'a>(root: &'a mut Command, path: &str) -> Option<&'a mut Command> {
    path.split(' ')
        .try_fold(root, |cmd, name| cmd.find_subcommand_mut(name))
}

/// Whether `path` names a visible command using canonical names only.
fn is_visible_path(root: &Command, path: &str) -> bool {
    path.split(' ')
        .try_fold(root, |cmd, name| {
            visible_subcommands(cmd).find(|c| c.get_name() == name)
        })
        .is_some()
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

/// Write the first line, such as `# openshell 1.2.3: sandboxes`.
fn write_title(out: &mut String, root: &Command, subject: Option<&str>) {
    let _ = write!(out, "# {}", root.get_name());
    if let Some(version) = root.get_version() {
        let _ = write!(out, " {version}");
    }
    if let Some(subject) = subject {
        let _ = write!(out, ": {subject}");
    }
    out.push('\n');
}

fn write_overview_pointer(out: &mut String, root: &Command) {
    let _ = writeln!(
        out,
        "\nRun `{} agent context` for global flags, conventions, and the other sections.",
        root.get_name()
    );
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

/// Write one command block. `elsewhere` maps a child command name to the
/// section that documents it when that is not the section being written.
fn write_command(
    out: &mut String,
    cmd: &mut Command,
    elsewhere: &dyn Fn(&str) -> Option<&'static str>,
) {
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
            let mut about = child
                .get_about()
                .map(ToString::to_string)
                .unwrap_or_default();
            if let Some(section) = elsewhere(child.get_name()) {
                let _ = write!(about, " (see section {section})");
            }
            let line = format!("  {:width$}  {about}", child.get_name());
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

    const SECTIONS: &[ContextSection] = &[
        ContextSection {
            name: "boxes",
            summary: "Create and list boxes.",
            commands: &["box"],
        },
        ContextSection {
            name: "storage",
            summary: "Organize shelves.",
            commands: &["box shelf"],
        },
    ];

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
                    .subcommand(
                        Command::new("shelf")
                            .about("Manage shelves.")
                            .subcommand(Command::new("add").about("Add a shelf.")),
                    )
                    .subcommand(Command::new("secret").about("Hidden box.").hide(true)),
            )
            .subcommand(Command::new("ping").about("Ping the server."))
            .subcommand(Command::new("debug").about("Hidden command.").hide(true))
    }

    fn render(target: &[&str]) -> Result<String> {
        let target = target.iter().map(ToString::to_string).collect::<Vec<_>>();
        render_context(&fixture(), SECTIONS, &target)
    }

    #[test]
    fn overview_lists_globals_and_leaf_commands_by_section() {
        let text = render(&[]).expect("render");

        assert!(text.starts_with("# tool 1.2.3\n\nFixture CLI.\n"), "{text}");
        assert!(
            text.contains("Run `tool agent context <SECTION>`"),
            "{text}"
        );
        assert!(text.contains("## Global flags"), "{text}");
        assert!(text.contains("[env: TOOL_PROFILE]"), "{text}");
        assert!(
            text.contains(
                "### boxes\n\nCreate and list boxes.\n\n  box create  Create a box.\n  box list    List boxes.\n"
            ),
            "{text}"
        );
        assert!(
            text.contains("### storage\n\nOrganize shelves.\n\n  box shelf add  Add a shelf.\n"),
            "{text}"
        );
        assert!(
            !text.contains("Usage:"),
            "overview should omit details:\n{text}"
        );
    }

    #[test]
    fn unclaimed_commands_fall_into_other_section() {
        let text = render(&[]).expect("render");
        assert!(text.contains("### other\n"), "{text}");
        assert!(text.contains("  ping  Ping the server."), "{text}");

        let other = render(&["other"]).expect("render other");
        assert!(other.contains("## tool ping"), "{other}");
    }

    #[test]
    fn section_renders_owned_commands_and_points_to_other_sections() {
        let text = render(&["boxes"]).expect("render");

        assert!(
            text.starts_with("# tool 1.2.3: boxes\n\nCreate and list boxes.\n"),
            "{text}"
        );
        assert!(
            text.contains("Run `tool agent context` for global flags"),
            "{text}"
        );
        for heading in [
            "## tool box\n",
            "## tool box create\n",
            "## tool box list\n",
        ] {
            assert!(text.contains(heading), "missing {heading:?}:\n{text}");
        }
        assert!(
            text.contains("  shelf   Manage shelves. (see section storage)"),
            "{text}"
        );
        assert!(!text.contains("## tool box shelf"), "{text}");
        assert!(!text.contains("## Global flags"), "{text}");
        assert!(!text.contains("## tool ping"), "{text}");

        let storage = render(&["storage"]).expect("render storage");
        assert!(storage.contains("## tool box shelf\n"), "{storage}");
        assert!(storage.contains("## tool box shelf add\n"), "{storage}");
        assert!(!storage.contains("## tool box create"), "{storage}");
    }

    #[test]
    fn command_path_renders_full_subtree_and_accepts_aliases() {
        let text = render(&["bx"]).expect("render");

        assert!(text.starts_with("# tool 1.2.3: bx\n"), "{text}");
        for heading in [
            "## tool box\n",
            "## tool box create\n",
            "## tool box shelf add\n",
        ] {
            assert!(text.contains(heading), "missing {heading:?}:\n{text}");
        }
        assert!(!text.contains("(see section"), "{text}");

        let leaf = render(&["box", "create"]).expect("render leaf");
        assert!(leaf.contains("## tool box create"), "{leaf}");
        assert!(!leaf.contains("## tool box list"), "{leaf}");
        assert!(
            leaf.contains("Usage: tool box create [OPTIONS] <name> [-- <command>...]"),
            "{leaf}"
        );
        assert!(leaf.contains("The box starts empty."), "{leaf}");
    }

    #[test]
    fn omits_hidden_commands_flags_and_help() {
        for target in [&[][..], &["boxes"][..], &["box"][..]] {
            let text = render(target).expect("render");
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
            text.contains("Subcommands:\n  create  Create a box.\n  list    List boxes.\n  shelf   Manage shelves.\n"),
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
    fn unknown_target_lists_sections_and_commands() {
        for target in [&["bogus"][..], &["debug"][..], &["bogus", "create"][..]] {
            let message = render(target).expect_err("unknown target").to_string();
            assert!(message.contains("unknown section or command"), "{message}");
            assert!(
                message.contains("Sections: boxes, storage, other"),
                "{message}"
            );
            assert!(message.contains("Commands: box, ping"), "{message}");
        }

        let err = render(&["box", "secret"]).expect_err("hidden subcommand should fail");
        assert!(
            err.to_string()
                .contains("Available under `tool box`: create, list, shelf"),
            "{err}"
        );

        let err = render(&["ping", "extra"]).expect_err("leaf has no subcommands");
        assert!(
            err.to_string().contains("`tool ping` has no subcommands"),
            "{err}"
        );
    }

    #[test]
    fn section_problems_require_complete_valid_assignment() {
        assert_eq!(
            section_problems(&fixture(), SECTIONS),
            vec!["command `ping` is not in any section".to_string()]
        );

        let complete = [
            SECTIONS[0],
            SECTIONS[1],
            ContextSection {
                name: "network",
                summary: "Check the server.",
                commands: &["ping"],
            },
        ];
        assert!(section_problems(&fixture(), &complete).is_empty());

        let broken = [
            ContextSection {
                name: "box",
                summary: "Collides with a command.",
                commands: &["box", "bx create", "box secret"],
            },
            ContextSection {
                name: "box",
                summary: "Duplicate name and path.",
                commands: &["box", "missing"],
            },
        ];
        let problems = section_problems(&fixture(), &broken);
        for expected in [
            "section `box` has the same name as a command",
            "section `box` names `bx create`, which is not a visible command",
            "section `box` names `box secret`, which is not a visible command",
            "section `box` is defined twice",
            "command `box` is claimed by two sections",
            "section `box` names `missing`, which is not a visible command",
            "command `ping` is not in any section",
        ] {
            assert!(
                problems.iter().any(|problem| problem == expected),
                "missing {expected:?} in {problems:?}"
            );
        }
    }

    #[test]
    fn output_is_deterministic_and_plain() {
        for target in [&[][..], &["boxes"][..], &["box"][..]] {
            let first = render(target).expect("render");
            let second = render(target).expect("render");

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
}
