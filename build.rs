use std::fs;
use std::path::Path;
use std::process::Command;

fn main() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    let root = Path::new(&manifest_dir);

    let version = fs::read_to_string(root.join("VERSION"))
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| std::env::var("CARGO_PKG_VERSION").expect("CARGO_PKG_VERSION"));

    let commit = Command::new("git")
        .args([
            "-C",
            root.to_str().expect("仓库路径必须是 UTF-8"),
            "rev-parse",
            "--short=12",
            "HEAD",
        ])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "unknown".to_string());

    let dirty = Command::new("git")
        .args([
            "-C",
            root.to_str().expect("仓库路径必须是 UTF-8"),
            "status",
            "--porcelain",
            "--",
            ".",
        ])
        .output()
        .ok()
        .is_some_and(|output| output.status.success() && !output.stdout.is_empty());

    let build_id = format!("{version}@{commit}{}", if dirty { "-dirty" } else { "" });
    println!("cargo:rustc-env=ROUTEPROXY_BUILD_ID={build_id}");

    // 一旦使用 rerun-if-changed，Cargo 的整包默认检测就失效，所以必须显式
    // 监听源码；只监听 .git 会漏掉 src/ 的修改，build id 会变旧。
    for path in ["VERSION", "Cargo.toml", "src"] {
        println!("cargo:rerun-if-changed={}", root.join(path).display());
    }

    // worktree 的 .git 是文件；用 git 查询真实目录，避免硬编码 .git/HEAD。
    for arg in ["--git-dir", "--git-common-dir"] {
        let output = Command::new("git")
            .args([
                "-C",
                root.to_str().expect("仓库路径必须是 UTF-8"),
                "rev-parse",
                arg,
            ])
            .output();
        let Ok(output) = output else { continue };
        if !output.status.success() {
            continue;
        }
        let value = String::from_utf8_lossy(&output.stdout);
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        let path = root.join(value);
        println!("cargo:rerun-if-changed={}", path.display());
    }
}
