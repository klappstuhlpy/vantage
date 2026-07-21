//! The self-update helper.
//!
//! A container cannot stop and recreate itself: the process dies mid-operation
//! and nothing is left to finish the job. So Vantage launches a detached
//! one-shot container running the *new* image with the hidden `apply-update`
//! subcommand, and that container recreates Vantage.
//!
//! Running the new image rather than a third-party `docker:cli` keeps the
//! supply chain to a single publisher, and proves the new image at least starts
//! before it is trusted to replace the running one.

use anyhow::Context;
use kls_agent::exec::{HostCommand, Tool};

use super::Deployment;

/// The registry the published images live in. A constant for the same reason
/// the releases URL is: the image an update pulls must not be settable over
/// HTTP.
const IMAGE_REPO: &str = "ghcr.io/klappstuhlpy/vantage";

/// Absolute path to the binary inside the image. It must be absolute: the helper
/// does not set `--workdir`, and even if it did, a relative `./vantage` would
/// resolve against the wrong directory. Pinned to the image's `WORKDIR /app`
/// (see the Dockerfile) — change both together.
const BINARY: &str = "/app/vantage";

/// The two compose commands, in order, both scoped to the one service.
///
/// `--no-deps` is load-bearing: an unscoped `compose up` recreates every
/// service in the operator's project, so updating Vantage would restart
/// unrelated containers someone happened to define alongside it.
pub fn compose_args(service: &str) -> [Vec<&str>; 2] {
    [
        vec!["compose", "pull", service],
        vec!["compose", "up", "-d", "--no-deps", service],
    ]
}

/// The image reference for a target version.
pub fn image_for(version: &str) -> String {
    format!("{IMAGE_REPO}:{version}")
}

/// Starts the detached helper. Returns as soon as the helper is running —
/// Vantage is about to be stopped by it, so there is nothing further to await.
pub async fn launch(d: &Deployment, version: &str) -> anyhow::Result<()> {
    let image = image_for(version);

    // Pull first, while still running: if the new image cannot be fetched, fail
    // here with a clear error rather than after Vantage is already down.
    let pull = HostCommand::new(Tool::Docker)
        .args(["pull", image.as_str()])
        .output()
        .await
        .context("could not pull the new image")?;
    if !pull.status.success() {
        anyhow::bail!("pulling {image} failed: {}", String::from_utf8_lossy(&pull.stderr));
    }

    // The project directory is mounted at the same path inside the helper so
    // compose resolves the file's relative paths identically to the host. The
    // container's own workdir is left at the image default (`/app`, where the
    // binary is) — `run()` cd's into the project dir itself for the compose
    // commands, so it must not be overridden here or the absolute `BINARY` would
    // be the only thing that still resolves.
    let mount = format!("{0}:{0}", d.project_dir);
    let out = HostCommand::new(Tool::Docker)
        .args([
            "run",
            "--detach",
            "--rm",
            "--volume",
            "/var/run/docker.sock:/var/run/docker.sock",
            "--volume",
            mount.as_str(),
            image.as_str(),
            BINARY,
            "apply-update",
            d.project_dir.as_str(),
            d.service.as_str(),
        ])
        .output()
        .await
        .context("could not start the update helper")?;

    if !out.status.success() {
        anyhow::bail!(
            "update helper failed to start: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(())
}

/// The helper's own body, run inside the one-shot container.
pub async fn run(project_dir: &str, service: &str) -> anyhow::Result<()> {
    for args in compose_args(service) {
        let out = HostCommand::new(Tool::Docker)
            .args(args.iter().copied())
            .current_dir(project_dir)
            .output()
            .await
            .with_context(|| format!("docker {} failed to run", args.join(" ")))?;
        if !out.status.success() {
            anyhow::bail!(
                "docker {} failed: {}",
                args.join(" "),
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compose_commands_are_scoped_to_the_service() {
        let [pull, up] = compose_args("vantage");
        assert_eq!(pull, vec!["compose", "pull", "vantage"]);
        assert_eq!(up, vec!["compose", "up", "-d", "--no-deps", "vantage"]);
    }

    #[test]
    fn the_service_name_is_never_dropped() {
        for service in ["vantage", "control-plane"] {
            let [pull, up] = compose_args(service);
            assert!(pull.contains(&service), "pull lost its service");
            assert!(up.contains(&service), "up lost its service");
            assert!(up.contains(&"--no-deps"), "up would recreate sibling services");
        }
    }

    #[test]
    fn the_image_is_pinned_to_the_published_repo() {
        // The image an update pulls is a constant, not configuration — the same
        // rule the releases URL follows.
        assert_eq!(image_for("0.5.0"), "ghcr.io/klappstuhlpy/vantage:0.5.0");
        assert!(image_for("0.5.0").starts_with(IMAGE_REPO));
    }

    #[test]
    fn the_binary_path_is_absolute() {
        // A relative `./vantage` broke every update: the helper runs with no
        // `--workdir`, so the exec resolves against the container's cwd. Absolute
        // is the fix — keep it that way.
        assert!(BINARY.starts_with('/'), "the helper binary must be an absolute path");
    }
}
