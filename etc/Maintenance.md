---
title: "Repository Maintenance"
---
# Dependency Pinning
In order to keep development reproducible, we pin the versions of all dependencies that are used in Swanky (including Rust, all Nix dependencies, and all Cargo dependencies).

To upgrade the pinned dependencies, use `./swanky upgrade-deps`.
