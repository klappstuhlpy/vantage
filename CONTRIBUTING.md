# Contributing to Vantage

Thanks for your interest. Vantage is primarily a personal project, so before
investing time in a large change, please open an issue to discuss it — it may not
fit the direction, and it's better to find that out before you write the code.

Found a security issue? Do not open an issue or a PR. See [SECURITY.md](SECURITY.md).

## Building

```bash
cargo build
cargo test          # hermetic — in-memory database, no Docker or network needed
cargo fmt
cargo clippy
```

Vantage depends on two shared kernel crates, `kls-web-core` and `kls-agent`, which
live in the public [kls-core](https://github.com/klappstuhlpy/kls-core) repository
and are fetched over HTTPS. No credentials, SSH agent, or registry access is
needed: a clean checkout builds with a Rust toolchain alone.

Linux is recommended for real use — Docker, `/proc`/`/sys`, and the firewall
backends are all Linux-only, and on other platforms those integrations report as
unavailable and their pages degrade rather than work.

## Architecture

The [README](README.md#architecture) covers the layout. The rules that matter when
changing it:

- Each domain is a self-contained slice (`mod.rs` logic, `routes.rs` handlers,
  `storage.rs` persistence).
- Host mutations go through the `kls-agent` boundary, never a raw shell.
- Every host integration is optional; `None` must degrade gracefully, not panic.
- Add a migration by creating `sql/<N>.sql` with the next integer — `build.rs`
  discovers it and validates the sequence is gapless.

## Pull requests

- Keep a PR to a single concern.
- Run `cargo fmt`, `cargo clippy`, and `cargo test` before pushing.
- Add tests for new logic. Tests are co-located in `#[cfg(test)] mod tests`, use
  `Config::test_default()` with an in-memory database, and drive the router with
  `tower::ServiceExt::oneshot` rather than a real socket.
- Every user-visible change lands with its changelog bullet in the same PR, under
  `## [Unreleased]` in [CHANGELOG.md](CHANGELOG.md). Write it for an operator, at
  feature level, one sentence, no operational detail (ports, paths, rule specifics).
  Refactors, tests, CI, docs, and no-op dependency bumps don't get an entry.
- Commit messages follow `type(scope): summary` (e.g. `feat(docker): ...`).

## License

Vantage is licensed under the [AGPL-3.0](LICENSE). Contributions are accepted under
that same license — by submitting a PR you agree your work is licensed under it.
