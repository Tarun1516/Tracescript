//! Build script: populates `TRACESCRIPT_GIT_SHA` and `TRACESCRIPT_BUILD_DATE`
//! environment variables at compile time so they're baked into the binary.
//!
//! Cargo automatically runs `build.rs` before the main crate, and any env
//! variables set via `println!("cargo:rustc-env=...")` are visible in the
//! subsequent compilation.

use std::process::Command;

fn main() {
    let git_sha = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                String::from_utf8(o.stdout).ok()
            } else {
                None
            }
        })
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "no-git".to_string());
    println!("cargo:rustc-env=TRACESCRIPT_GIT_SHA={}", git_sha);

    let build_date = Command::new("date")
        .args(["-u", "+%Y-%m-%dT%H:%M:%SZ"])
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                String::from_utf8(o.stdout).ok()
            } else {
                None
            }
        })
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=TRACESCRIPT_BUILD_DATE={}", build_date);
}