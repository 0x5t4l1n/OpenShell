// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OCI image behavior shared by the Docker and Podman compute drivers.
//!
//! Each test builds a small image with the container engine that backs the
//! target gateway, creates a sandbox from it through the CLI, and checks the
//! process identity, privileges, workspace, and image content seen by both the
//! sandbox main process and `sandbox exec`. One scenario also inspects the
//! containers the driver created, through the same engine.
//!
//! `OPENSHELL_TEST_CONTAINER_ENGINE` is the command for the gateway's container
//! engine and image store, such as `docker`, `podman`, or `sudo -n podman`.
//! These tests need a gateway backed by one of those engines.

use std::process::Command;

use testkit::{Context, Error, Result};

const BASE_IMAGE: &str = "nvcr.io/nvidia/base/ubuntu:24.04";
const ENGINE_ENV: &str = "OPENSHELL_TEST_CONTAINER_ENGINE";
/// Sandbox condition reason for an image `WORKDIR` the sandbox identity
/// cannot use.
const WORKSPACE_VALIDATION_FAILED: &str = "WorkspaceValidationFailed";
/// A complete sandbox policy without a `process` section, so the sandbox
/// identity falls back to the image `USER`.
const IMAGE_IDENTITY_POLICY: &str = "version: 1

filesystem_policy:
  include_workdir: true
  read_only: [/usr, /lib, /lib64, /proc, /dev/urandom, /etc]
  read_write: [/tmp, /dev/null]
landlock:
  compatibility: best_effort

network_policies: {}
";

/// A named image user that owns its custom `WORKDIR`. Existing image content
/// keeps its ownership.
#[testkit::test]
async fn custom_workdir_with_named_user(cx: &mut Context) -> Result {
    scenario(cx, async |cx, engine| {
        let image = engine.build_image(
            "named-workdir",
            &format!(
                "FROM {BASE_IMAGE}
RUN groupadd -g 1235 appstaff && useradd -m -u 1234 -g appstaff app
WORKDIR /workspace/project
RUN printf root-owned > root-owned.txt && chown app:appstaff . && \\
    printf custom-image-e2e-marker > /etc/oci-image-marker
USER app
"
            ),
        )?;
        let checks = format!(
            "{} test \"$(stat -c %u:%g .)\" = 1234:1235; \
             test \"$(cat /etc/oci-image-marker)\" = custom-image-e2e-marker; \
             test \"$(stat -c %u:%g /etc/oci-image-marker)\" = 0:0;",
            workspace_checks("1234:1235", "/workspace/project", true)
        );
        let sandbox = create_sandbox(cx, "nu", &image, None, &checks).await?;
        file_transfer_uses_workspace(cx, &sandbox).await
    })
    .await
}

/// A numeric image user without passwd entries can reach a custom `WORKDIR`
/// whose parent directories are private to that user. The sandbox policy omits
/// `process`, so the image `USER` is the only source of the sandbox identity.
/// The driver's containers launch the inspected image and keep the
/// supervisor separate from the workload.
#[testkit::test]
async fn custom_workdir_with_numeric_user_and_private_parents(cx: &mut Context) -> Result {
    scenario(cx, async |cx, engine| {
        let image = engine.build_image(
            "numeric-workdir",
            &format!(
                "FROM {BASE_IMAGE}
RUN mkdir -p /home/app/project && \\
    chown 2345:2346 /home/app /home/app/project && \\
    chmod 0700 /home/app /home/app/project
WORKDIR /home/app/project
RUN printf root-owned > root-owned.txt
USER 2345:2346
"
            ),
        )?;
        let policy = PolicyFile::new(IMAGE_IDENTITY_POLICY)?;
        let checks = workspace_checks("2345:2346", "/home/app/project", true);
        let sandbox = create_sandbox(cx, "pu", &image, Some(policy.path()?), &checks).await?;
        container_checks(engine, &sandbox, &image, "2345:2346")
    })
    .await
}

/// An image without `USER`, with no policy identity, runs as the numeric
/// default `1000:1000`. The base image has an account with UID 1000 in other
/// groups, such as `sudo`, and the default identity does not get them.
#[testkit::test]
async fn userless_image_uses_default_identity(cx: &mut Context) -> Result {
    scenario(cx, async |cx, engine| {
        let image = engine.build_image("userless", &format!("FROM {BASE_IMAGE}\n"))?;
        let policy = PolicyFile::new(IMAGE_IDENTITY_POLICY)?;
        let checks = format!(
            "{} test \"$(id -G)\" = 1000;",
            workspace_checks("1000:1000", "/sandbox", false)
        );
        let sandbox = create_sandbox(cx, "ud", &image, Some(policy.path()?), &checks).await?;
        container_checks(engine, &sandbox, &image, "1000:1000")
    })
    .await
}

/// A policy `run_as_user` and `run_as_group` replace an image's `USER root`.
/// The image has no `WORKDIR`, so the managed `/sandbox` workspace is
/// writable by the policy identity and only identity resolution is tested.
#[testkit::test]
async fn policy_identity_overrides_root_image_user(cx: &mut Context) -> Result {
    scenario(cx, async |cx, engine| {
        let image = engine.build_image(
            "root-user",
            &format!(
                "FROM {BASE_IMAGE}
RUN groupadd -g 4235 appstaff && useradd -m -u 4234 -g appstaff app
USER root
"
            ),
        )?;
        let policy = PolicyFile::new(&format!(
            "{IMAGE_IDENTITY_POLICY}
process:
  run_as_user: \"4234\"
  run_as_group: \"4235\"
"
        ))?;
        let checks = format!(
            "{} test \"$(id -G)\" = 4235;",
            workspace_checks("4234:4235", "/sandbox", false)
        );
        let sandbox = create_sandbox(cx, "pr", &image, Some(policy.path()?), &checks).await?;
        container_checks(engine, &sandbox, &image, "4234:4235")
    })
    .await
}

/// An image without a `WORKDIR` uses the managed `/sandbox` workspace, owned
/// by the image user, even when the image does not contain `/sandbox`.
#[testkit::test]
async fn default_workdir_uses_managed_workspace(cx: &mut Context) -> Result {
    scenario(cx, async |cx, engine| {
        let image = engine.build_image(
            "default-workdir",
            &format!("FROM {BASE_IMAGE}\nUSER 2345:2346\n"),
        )?;
        let checks = workspace_checks("2345:2346", "/sandbox", false);
        create_sandbox(cx, "dw", &image, None, &checks).await?;
        Ok(())
    })
    .await
}

/// OpenShell rejects a custom `WORKDIR` that the image user cannot write
/// instead of granting the user new access to it, and reports that reason
/// rather than a generic startup failure.
#[testkit::test]
async fn unwritable_custom_workdir_is_rejected(cx: &mut Context) -> Result {
    scenario(cx, async |cx, engine| {
        // First prove that this user, workspace and command can run. Only the
        // directory owner differs between the control and rejected image.
        for (suffix, owner, writable) in [("wc", "3234:3235", true), ("uw", "0:0", false)] {
            let image = engine.build_image(
                suffix,
                &format!(
                    "FROM {BASE_IMAGE}
RUN groupadd -g 3235 appstaff && useradd -m -u 3234 -g appstaff app
WORKDIR /workspace/project
RUN chown {owner} .
USER app
"
                ),
            )?;
            let name = cx.track_sandbox(suffix);
            let create = cx
                .cli([
                    "sandbox",
                    "create",
                    "--name",
                    &name,
                    "--from",
                    &image.tag,
                    "--no-tty",
                    "--",
                    "sh",
                    "-c",
                    "echo workspace-access-marker",
                ])
                .await?;
            if writable {
                let create = create.success()?;
                testkit::ensure!(
                    create.stdout.contains("workspace-access-marker"),
                    "writable control did not execute the command marker; `{}` stdout: {}",
                    create.command,
                    create.stdout.trim()
                );
                continue;
            }
            let printed = |text: &str| create.stdout.contains(text) || create.stderr.contains(text);
            testkit::ensure!(
                create.exit_code != 0 && !printed("workspace-access-marker"),
                "sandbox creation must fail before the command runs; `{}` exited {}\nstdout: {}\nstderr: {}",
                create.command,
                create.exit_code,
                create.stdout.trim(),
                create.stderr.trim()
            );
            // Require the condition reason, so another provisioning failure
            // cannot pass as a workspace rejection.
            let sandbox = cx
                .cli(["sandbox", "get", &name, "--output", "json"])
                .await?
                .success()?;
            let reasons: Vec<String> = sandbox.json::<serde_json::Value>()?["conditions"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|condition| condition["reason"].as_str().map(str::to_string))
                .collect();
            testkit::ensure!(
                reasons
                    .iter()
                    .any(|reason| reason == WORKSPACE_VALIDATION_FAILED),
                "sandbox condition reason is {WORKSPACE_VALIDATION_FAILED}, got {reasons:?}; `{}` stdout: {}",
                sandbox.command,
                sandbox.stdout.trim()
            );
        }
        Ok(())
    })
    .await
}

/// Run `test` with a container engine, then delete the sandboxes before
/// removing the images they use. Non-forced image removal must report remaining
/// users rather than deleting workloads behind the gateway's back. The test's
/// own failure is reported first.
async fn scenario(
    cx: &mut Context,
    test: impl AsyncFnOnce(&mut Context, &mut Engine) -> Result,
) -> Result {
    let mut engine = Engine::from_env(cx.run_id())?;
    let mut errors: Vec<String> = test(cx, &mut engine)
        .await
        .err()
        .map(|error| error.to_string())
        .into_iter()
        .collect();
    errors.extend(
        cx.delete_sandboxes()
            .await
            .err()
            .map(|error| error.to_string()),
    );
    errors.extend(engine.remove_images());
    if errors.is_empty() {
        Ok(())
    } else {
        Err(Error::msg(errors.join("\n")))
    }
}

/// Shell checks for the identity, working directory, and `HOME` of a sandbox
/// child. The image user gains no capabilities and cannot read the sandbox's
/// control credentials. A custom workspace is the image directory itself, not
/// a mount over it, and does not also get the managed `/sandbox`. With
/// `image_file`, also check that root-owned image content is present and
/// unchanged in the workspace.
fn workspace_checks(identity: &str, workspace: &str, image_file: bool) -> String {
    let mut checks = format!(
        "test \"$(id -u):$(id -g)\" = {identity}; \
         test \"$(pwd -P)\" = {workspace}; \
         test \"$HOME\" = {workspace}; \
         awk '/^(CapEff|CapBnd):/ && $2 != \"0000000000000000\" {{ exit 1 }} \
              /^NoNewPrivs:/ && $2 != 1 {{ exit 1 }}' /proc/self/status; \
         test ! -r /.openshell/channel/sandbox/server.key; \
         test ! -r /.openshell/supervisor/runtime-descriptor.json;"
    );
    if workspace != "/sandbox" {
        checks.push_str(&format!(
            " awk -v w={workspace} '$5 == w {{ exit 1 }}' /proc/self/mountinfo; \
             test ! -e /sandbox;"
        ));
    }
    if image_file {
        checks.push_str(
            " test \"$(cat root-owned.txt)\" = root-owned; \
             test \"$(stat -c %u:%g root-owned.txt)\" = 0:0;",
        );
    }
    checks
}

/// Create a detached sandbox whose main process runs `checks` and writes to
/// the workspace, then run the same checks and a write through `sandbox exec`.
/// Returns the sandbox name.
async fn create_sandbox(
    cx: &Context,
    short: &str,
    image: &TestImage,
    policy: Option<&str>,
    checks: &str,
) -> Result<String> {
    let name = cx.track_sandbox(short);
    let main = format!(
        "(set -eu; {checks} touch main-write) >/tmp/oci-main.log 2>&1; \
         echo $? >/tmp/oci-main.status; exec sleep infinity"
    );
    let mut args = vec!["sandbox", "create", "--name", &name, "--from", &image.tag];
    if let Some(policy) = policy {
        args.extend(["--policy", policy]);
    }
    args.extend(["--detach", "--", "sh", "-c", &main]);
    cx.cli(args).await?.success()?;

    let script = format!(
        "set -eu; i=0; \
         while [ ! -f /tmp/oci-main.status ]; do \
           i=$((i + 1)); [ \"$i\" -le 60 ] || {{ echo main process checks did not finish >&2; exit 1; }}; \
           sleep 1; \
         done; \
         if [ \"$(cat /tmp/oci-main.status)\" != 0 ]; then \
           echo main process checks failed: >&2; cat /tmp/oci-main.log >&2; exit 1; \
         fi; \
         test -f main-write; {checks} touch exec-write"
    );
    exec(cx, &name, &script).await?;
    Ok(name)
}

/// Upload and download default to paths relative to the image workspace.
async fn file_transfer_uses_workspace(cx: &Context, sandbox: &str) -> Result {
    let local = tempfile::tempdir().map_err(|error| Error::from_error(&error))?;
    let upload = local.path().join("oci-transfer.txt");
    std::fs::write(&upload, "oci-transfer-ok").map_err(|error| Error::from_error(&error))?;
    // Upload without a destination writes to the workspace.
    cx.cli([
        "sandbox",
        "upload",
        sandbox,
        utf8(&upload)?,
        "--no-git-ignore",
    ])
    .await?
    .success()?;
    // The uploaded file is in the workspace.
    exec(
        cx,
        sandbox,
        "test \"$(cat oci-transfer.txt)\" = oci-transfer-ok",
    )
    .await?;

    // Download resolves relative paths in the workspace.
    let download = local.path().join("downloaded.txt");
    cx.cli([
        "sandbox",
        "download",
        sandbox,
        "oci-transfer.txt",
        utf8(&download)?,
    ])
    .await?
    .success()?;
    let downloaded =
        std::fs::read_to_string(&download).map_err(|error| Error::from_error(&error))?;
    testkit::ensure!(
        downloaded == "oci-transfer-ok",
        "downloaded file has unexpected content: {downloaded:?}"
    );

    // A directory upload merges into an existing workspace directory.
    let merge = local.path().join("merge-upload");
    std::fs::create_dir(&merge).map_err(|error| Error::from_error(&error))?;
    std::fs::write(merge.join("conflict.txt"), "local-conflict")
        .and_then(|()| std::fs::write(merge.join("added.txt"), "local-added"))
        .map_err(|error| Error::from_error(&error))?;
    exec(
        cx,
        sandbox,
        "mkdir merge-upload && printf remote-conflict > merge-upload/conflict.txt \
         && printf remote-preserved > merge-upload/unrelated.txt",
    )
    .await?;
    cx.cli([
        "sandbox",
        "upload",
        sandbox,
        utf8(&merge)?,
        "--no-git-ignore",
    ])
    .await?
    .success()?;
    // Upload overwrites conflicts and keeps unrelated files.
    exec(
        cx,
        sandbox,
        "test \"$(cat merge-upload/conflict.txt)\" = local-conflict \
         && test \"$(cat merge-upload/added.txt)\" = local-added \
         && test \"$(cat merge-upload/unrelated.txt)\" = remote-preserved",
    )
    .await
}

/// Check the containers the driver created for `sandbox`. The workload runs
/// the image ID captured after the fixture build, before sandbox creation, and
/// starts directly as the sandbox `identity` without a network or the
/// supervisor's credentials. The supervisor runs in a separate non-root
/// container.
fn container_checks(engine: &Engine, sandbox: &str, image: &TestImage, identity: &str) -> Result {
    let workload = engine.container_for_role(sandbox, "sandbox")?;
    let supervisor = engine.container_for_role(sandbox, "supervisor")?;
    testkit::ensure!(
        workload != supervisor,
        "{sandbox} has no separate supervisor container"
    );
    let launched = engine.inspect_container(&workload, "{{.Image}}")?;
    let digest = |id: &str| id.trim_start_matches("sha256:").to_string();
    testkit::ensure!(
        digest(&launched) == digest(&image.id),
        "workload launched image {launched}, expected the built image {}",
        image.id
    );
    let user = engine.inspect_container(&workload, "{{.Config.User}}")?;
    testkit::ensure!(
        user == identity,
        "workload starts as {user:?}, expected {identity}"
    );
    let network = engine.inspect_container(&workload, "{{.HostConfig.NetworkMode}}")?;
    testkit::ensure!(
        network == "none",
        "workload network mode is {network:?}, expected none"
    );
    let mounts = engine.inspect_container(
        &workload,
        "{{range .Mounts}}{{println .Destination}}{{end}}",
    )?;
    if let Some(mount) = mounts.lines().find(|mount| {
        mount.starts_with("/etc/openshell/tls") || mount.starts_with("/.openshell/supervisor")
    }) {
        return Err(Error::msg(format!(
            "workload mounts supervisor credentials at {mount}"
        )));
    }
    let supervisor_user = engine.inspect_container(&supervisor, "{{.Config.User}}")?;
    testkit::ensure!(
        !matches!(
            supervisor_user.split(':').next(),
            None | Some("" | "0" | "root")
        ),
        "supervisor runs as root ({supervisor_user:?})"
    );
    Ok(())
}

/// Run a shell script in `sandbox` through `sandbox exec`.
async fn exec(cx: &Context, sandbox: &str, script: &str) -> Result {
    cx.cli([
        "sandbox", "exec", "--name", sandbox, "--no-tty", "--", "sh", "-c", script,
    ])
    .await?
    .success()?;
    Ok(())
}

fn utf8(path: &std::path::Path) -> Result<&str> {
    path.to_str()
        .ok_or_else(|| Error::msg(format!("path {} is not UTF-8", path.display())))
}

/// A sandbox policy written to a temporary file for `sandbox create --policy`.
struct PolicyFile(tempfile::NamedTempFile);

impl PolicyFile {
    fn new(contents: &str) -> Result<Self> {
        let file = tempfile::NamedTempFile::new().map_err(|error| Error::from_error(&error))?;
        std::fs::write(file.path(), contents).map_err(|error| Error::from_error(&error))?;
        Ok(Self(file))
    }

    fn path(&self) -> Result<&str> {
        utf8(self.0.path())
    }
}

/// A built fixture's mutable tag and image ID captured before sandbox creation.
struct TestImage {
    tag: String,
    id: String,
}

/// The gateway's container engine. Images it builds for a scenario are
/// removed by `scenario` after sandbox cleanup.
struct Engine {
    command: Vec<String>,
    run_id: String,
    images: Vec<String>,
}

impl Engine {
    fn from_env(run_id: &str) -> Result<Self> {
        let command: Vec<String> = std::env::var(ENGINE_ENV)
            .map_err(|_| {
                Error::msg(format!(
                    "{ENGINE_ENV} must name the gateway's container engine"
                ))
            })?
            .split_whitespace()
            .map(str::to_string)
            .collect();
        testkit::ensure!(!command.is_empty(), "{ENGINE_ENV} is empty");
        Ok(Self {
            command,
            run_id: run_id.to_string(),
            images: Vec::new(),
        })
    }

    /// Build `containerfile` and capture its image ID before sandbox creation.
    fn build_image(&mut self, name: &str, containerfile: &str) -> Result<TestImage> {
        let context = tempfile::tempdir().map_err(|error| Error::from_error(&error))?;
        let file = context.path().join("Containerfile");
        std::fs::write(&file, containerfile).map_err(|error| Error::from_error(&error))?;
        let tag = format!("localhost/openshell-test-oci-{name}:{}", self.run_id);
        self.output(&[
            "build",
            "--file",
            utf8(&file)?,
            "--tag",
            &tag,
            utf8(context.path())?,
        ])?;
        // A failed build leaves no tag to remove.
        self.images.push(tag.clone());
        let id = self.output(&["image", "inspect", "--format", "{{.Id}}", &tag])?;
        Ok(TestImage { tag, id })
    }

    /// Remove every built image, returning one error per failed removal.
    fn remove_images(&self) -> Vec<String> {
        self.images
            .iter()
            .filter_map(|tag| self.output(&["image", "rm", tag]).err())
            .map(|error| format!("image cleanup failed: {error}"))
            .collect()
    }

    /// The one container with isolation `role` for `sandbox`. Docker and
    /// Podman label sandbox containers the same way.
    fn container_for_role(&self, sandbox: &str, role: &str) -> Result<String> {
        let ids = self.output(&[
            "ps",
            "-aq",
            "--filter",
            &format!("label=openshell.ai/sandbox-name={sandbox}"),
            "--filter",
            &format!("label=openshell.ai/isolation-role={role}"),
        ])?;
        match ids.split_whitespace().collect::<Vec<_>>().as_slice() {
            [id] => Ok((*id).to_string()),
            ids => Err(Error::msg(format!(
                "expected one {role} container for {sandbox}, found {ids:?}"
            ))),
        }
    }

    fn inspect_container(&self, id: &str, format: &str) -> Result<String> {
        self.output(&["container", "inspect", "--format", format, id])
    }

    /// Run the engine and return its trimmed standard output.
    fn output(&self, args: &[&str]) -> Result<String> {
        let command = format!("{} {}", self.command.join(" "), args.join(" "));
        let output = Command::new(&self.command[0])
            .args(&self.command[1..])
            .args(args)
            .output()
            .map_err(|error| Error::msg(format!("failed to run {command}: {error}")))?;
        testkit::ensure!(
            output.status.success(),
            "{command} failed ({}):\n{}{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }
}
