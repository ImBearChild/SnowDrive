//! Process-level smoke tests for the `snowdrive` CLI (`snowdrive_main.c`).

use std::process::{Command, Output};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_snowdrive"))
        .args(args)
        .output()
        .expect("run snowdrive")
}

#[test]
fn help_exits_zero_and_lists_serve() {
    let out = run(&["--help"]);
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("serve"));
}

#[test]
fn no_subcommand_fails() {
    assert!(!run(&[]).status.success());
}

#[test]
fn serve_requires_iscsi() {
    let out = run(&["serve", "--disk", "ram=1M"]);
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("--iscsi"));
}

#[test]
fn serve_requires_block() {
    let out = run(&["serve", "--iscsi", "127.0.0.1:3260"]);
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("--disk"));
}

#[test]
fn serve_rejects_invalid_ram_size() {
    let out = run(&["serve", "--disk", "ram=bogus", "--iscsi", "127.0.0.1:3260"]);
    assert!(!out.status.success());
}

#[test]
fn serve_rejects_missing_file() {
    let out = run(&[
        "serve",
        "--disk",
        "img=/nonexistent/snowdrive-missing.img",
        "--iscsi",
        "127.0.0.1:3260",
    ]);
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("file not found"));
}

#[test]
fn serve_rejects_invalid_address() {
    let out = run(&["serve", "--disk", "ram=1M", "--iscsi", "not-an-address"]);
    assert!(!out.status.success());
}

#[test]
fn serve_rejects_unknown_option() {
    let out = run(&["serve", "--bogus", "x"]);
    assert!(!out.status.success());
}

#[test]
fn serve_rejects_work_buf_too_small() {
    let out = run(&[
        "serve",
        "--disk",
        "ram=1M",
        "--iscsi",
        "127.0.0.1:3260",
        "--work-buf-size",
        "1000",
    ]);
    assert!(!out.status.success());
}

/// SIGINT → graceful shutdown → exit 0: the accept
/// loop is woken, `serve()` returns, backends are sync()ed, process exits 0.
#[cfg(unix)]
#[test]
fn serve_exits_cleanly_on_sigint() {
    use std::io::BufRead;
    use std::sync::mpsc;
    use std::time::Duration;

    let mut child = Command::new(env!("CARGO_BIN_EXE_snowdrive"))
        .args(["serve", "--disk", "ram=1M", "--iscsi", "127.0.0.1:0"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn snowdrive");

    // Wait until the server announces readiness on stderr (the log line is
    // emitted after the signal handler is installed).
    let (ready_tx, ready_rx) = mpsc::channel();
    {
        let stderr = child.stderr.take().expect("child stderr");
        std::thread::spawn(move || {
            let mut line = String::new();
            let mut reader = std::io::BufReader::new(stderr);
            while reader.read_line(&mut line).map(|n| n > 0).unwrap_or(false) {
                if line.contains("listening") {
                    let _ = ready_tx.send(());
                    return;
                }
                line.clear();
            }
        });
    }

    if ready_rx.recv_timeout(Duration::from_secs(5)).is_err() {
        let _ = Command::new("kill")
            .arg("-KILL")
            .arg(child.id().to_string())
            .status();
        let _ = child.wait();
        panic!("snowdrive did not announce 'listening'");
    }

    let sent = Command::new("kill")
        .arg("-INT")
        .arg(child.id().to_string())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    assert!(sent, "kill -INT failed");

    let status = child.wait().expect("wait for snowdrive");
    assert!(status.success(), "snowdrive should exit 0 after SIGINT");
}

/// The same file path on two `--disk` LUNs emits a dual-mount warning on
/// stderr while the server still starts and exits 0 after SIGINT.
#[cfg(unix)]
#[test]
fn serve_warns_on_dual_mount() {
    use std::io::BufRead;
    use std::sync::mpsc;
    use std::time::Duration;

    let dir = std::env::temp_dir();
    let img = dir.join(format!("snowdrive_dual_{}.img", std::process::id()));
    std::fs::write(&img, [0u8; 512]).unwrap();
    let path = img.to_string_lossy().to_string();

    let mut child = Command::new(env!("CARGO_BIN_EXE_snowdrive"))
        .args([
            "serve",
            "--disk",
            &path,
            "--disk",
            &path,
            "--iscsi",
            "127.0.0.1:0",
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn snowdrive");

    // Collect dual-mount warnings until the server is ready (the warning is
    // emitted before bind, the "listening" line after the signal handler).
    let (ready_tx, ready_rx) = mpsc::channel();
    {
        let stderr = child.stderr.take().expect("child stderr");
        std::thread::spawn(move || {
            let mut line = String::new();
            let mut reader = std::io::BufReader::new(stderr);
            let mut warnings = Vec::new();
            while reader.read_line(&mut line).map(|n| n > 0).unwrap_or(false) {
                if line.contains("warning:") {
                    warnings.push(line.clone());
                }
                if line.contains("listening") {
                    let _ = ready_tx.send(warnings);
                    return;
                }
                line.clear();
            }
            let _ = ready_tx.send(warnings);
        });
    }

    let warnings = ready_rx
        .recv_timeout(Duration::from_secs(5))
        .unwrap_or_else(|_| {
            let _ = Command::new("kill")
                .arg("-KILL")
                .arg(child.id().to_string())
                .status();
            let _ = child.wait();
            panic!("snowdrive did not announce 'listening'");
        });
    assert!(
        warnings.iter().any(|w| w.contains(&path)),
        "expected a dual-mount warning for {path}, got {warnings:?}"
    );

    let sent = Command::new("kill")
        .arg("-INT")
        .arg(child.id().to_string())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    assert!(sent, "kill -INT failed");

    let status = child.wait().expect("wait for snowdrive");
    assert!(status.success(), "snowdrive should exit 0 after SIGINT");

    let _ = std::fs::remove_file(&img);
}

/// `serve --disk cd=<iso>` starts with a lazy CD-ROM LUN, announces
/// 'listening' and exits 0 after SIGINT (graceful shutdown syncs the
/// read-only backend).
#[cfg(unix)]
#[test]
fn serve_starts_with_cdblock() {
    use std::io::BufRead;
    use std::sync::mpsc;
    use std::time::Duration;

    let dir = std::env::temp_dir();
    let iso = dir.join(format!("snowdrive_cdblock_{}.iso", std::process::id()));
    // 2048 * 64 bytes = 64 sectors; sparse is fine (only capacity is read).
    let f = std::fs::File::create(&iso).unwrap();
    f.set_len(2048 * 64).unwrap();
    drop(f);
    let path = iso.to_string_lossy().to_string();

    let mut child = Command::new(env!("CARGO_BIN_EXE_snowdrive"))
        .args([
            "serve",
            "--disk",
            &format!("cd={path}"),
            "--iscsi",
            "127.0.0.1:0",
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn snowdrive");

    let (ready_tx, ready_rx) = mpsc::channel();
    {
        let stderr = child.stderr.take().expect("child stderr");
        std::thread::spawn(move || {
            let mut line = String::new();
            let mut reader = std::io::BufReader::new(stderr);
            while reader.read_line(&mut line).map(|n| n > 0).unwrap_or(false) {
                if line.contains("listening") {
                    let _ = ready_tx.send(());
                    return;
                }
                line.clear();
            }
        });
    }

    if ready_rx.recv_timeout(Duration::from_secs(5)).is_err() {
        let _ = Command::new("kill")
            .arg("-KILL")
            .arg(child.id().to_string())
            .status();
        let _ = child.wait();
        panic!("snowdrive did not announce 'listening'");
    }

    let sent = Command::new("kill")
        .arg("-INT")
        .arg(child.id().to_string())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    assert!(sent, "kill -INT failed");

    let status = child.wait().expect("wait for snowdrive");
    assert!(status.success(), "snowdrive should exit 0 after SIGINT");

    let _ = std::fs::remove_file(&iso);
}

/// `serve --cdrom <iso>` starts a flat CD-ROM LUN (full MMC), announces
/// 'listening' and exits 0 after SIGINT.
#[cfg(unix)]
#[test]
fn serve_starts_with_cdrom_flat() {
    use std::io::BufRead;
    use std::sync::mpsc;
    use std::time::Duration;

    let dir = std::env::temp_dir();
    let iso = dir.join(format!("snowdrive_cdrom_{}.iso", std::process::id()));
    let f = std::fs::File::create(&iso).unwrap();
    f.set_len(2048 * 64).unwrap();
    drop(f);
    let path = iso.to_string_lossy().to_string();

    let mut child = Command::new(env!("CARGO_BIN_EXE_snowdrive"))
        .args(["serve", "--cdrom", &path, "--iscsi", "127.0.0.1:0"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn snowdrive");

    let (ready_tx, ready_rx) = mpsc::channel();
    {
        let stderr = child.stderr.take().expect("child stderr");
        std::thread::spawn(move || {
            let mut line = String::new();
            let mut reader = std::io::BufReader::new(stderr);
            while reader.read_line(&mut line).map(|n| n > 0).unwrap_or(false) {
                if line.contains("listening") {
                    let _ = ready_tx.send(());
                    return;
                }
                line.clear();
            }
        });
    }

    if ready_rx.recv_timeout(Duration::from_secs(5)).is_err() {
        let _ = Command::new("kill")
            .arg("-KILL")
            .arg(child.id().to_string())
            .status();
        let _ = child.wait();
        panic!("snowdrive did not announce 'listening'");
    }

    let sent = Command::new("kill")
        .arg("-INT")
        .arg(child.id().to_string())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    assert!(sent, "kill -INT failed");

    let status = child.wait().expect("wait for snowdrive");
    assert!(status.success(), "snowdrive should exit 0 after SIGINT");

    let _ = std::fs::remove_file(&iso);
}

/// `serve --cdrom live=<dir>` scans the directory into a live ISO9660
/// CD-ROM, announces 'listening' and exits 0 after SIGINT.
#[cfg(unix)]
#[test]
fn serve_starts_with_cdrom_live() {
    use std::io::BufRead;
    use std::sync::mpsc;
    use std::time::Duration;

    let dir = std::env::temp_dir().join(format!("snowdrive_live_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("DATA.BIN"), vec![0x42u8; 2048]).unwrap();
    let path = dir.to_string_lossy().to_string();

    let mut child = Command::new(env!("CARGO_BIN_EXE_snowdrive"))
        .args([
            "serve",
            "--cdrom",
            &format!("live={path}"),
            "--iscsi",
            "127.0.0.1:0",
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn snowdrive");

    let (ready_tx, ready_rx) = mpsc::channel();
    {
        let stderr = child.stderr.take().expect("child stderr");
        std::thread::spawn(move || {
            let mut line = String::new();
            let mut reader = std::io::BufReader::new(stderr);
            while reader.read_line(&mut line).map(|n| n > 0).unwrap_or(false) {
                if line.contains("listening") {
                    let _ = ready_tx.send(());
                    return;
                }
                line.clear();
            }
        });
    }

    if ready_rx.recv_timeout(Duration::from_secs(5)).is_err() {
        let _ = Command::new("kill")
            .arg("-KILL")
            .arg(child.id().to_string())
            .status();
        let _ = child.wait();
        panic!("snowdrive did not announce 'listening'");
    }

    let sent = Command::new("kill")
        .arg("-INT")
        .arg(child.id().to_string())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    assert!(sent, "kill -INT failed");

    let status = child.wait().expect("wait for snowdrive");
    assert!(status.success(), "snowdrive should exit 0 after SIGINT");

    let _ = std::fs::remove_dir_all(&dir);
}

/// A `--cdrom bundle=<dir>` (bundle mode) is rejected with "not yet
/// supported" before the server binds.
#[test]
fn serve_rejects_bundle_cdrom() {
    let out = run(&["serve", "--cdrom", "bundle=/tmp", "--iscsi", "127.0.0.1:0"]);
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("not yet supported"));
}

/// The same file path as both `--disk` and `--cdrom` emits a dual-mount
/// warning on stderr before the server starts.
#[cfg(unix)]
#[test]
fn serve_warns_on_block_and_cdrom_dual_mount() {
    use std::io::BufRead;
    use std::sync::mpsc;
    use std::time::Duration;

    let dir = std::env::temp_dir();
    let img = dir.join(format!("snowdrive_dualcdrom_{}.iso", std::process::id()));
    // Not a valid ISO, but existence is all the CLI checks up front.
    std::fs::write(&img, [0u8; 2048]).unwrap();
    let path = img.to_string_lossy().to_string();

    let mut child = Command::new(env!("CARGO_BIN_EXE_snowdrive"))
        .args([
            "serve",
            "--disk",
            &format!("img={path}"),
            "--cdrom",
            &path,
            "--iscsi",
            "127.0.0.1:0",
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn snowdrive");

    let (ready_tx, ready_rx) = mpsc::channel();
    {
        let stderr = child.stderr.take().expect("child stderr");
        std::thread::spawn(move || {
            let mut line = String::new();
            let mut reader = std::io::BufReader::new(stderr);
            let mut warnings = Vec::new();
            while reader.read_line(&mut line).map(|n| n > 0).unwrap_or(false) {
                if line.contains("warning:") {
                    warnings.push(line.clone());
                }
                if line.contains("listening") {
                    let _ = ready_tx.send(warnings);
                    return;
                }
                line.clear();
            }
            let _ = ready_tx.send(warnings);
        });
    }

    let warnings = ready_rx
        .recv_timeout(Duration::from_secs(5))
        .unwrap_or_else(|_| {
            let _ = Command::new("kill")
                .arg("-KILL")
                .arg(child.id().to_string())
                .status();
            let _ = child.wait();
            panic!("snowdrive did not announce 'listening'");
        });
    assert!(
        warnings.iter().any(|w| w.contains(&path)),
        "expected a dual-mount warning for {path}, got {warnings:?}"
    );

    let sent = Command::new("kill")
        .arg("-INT")
        .arg(child.id().to_string())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    assert!(sent, "kill -INT failed");

    let status = child.wait().expect("wait for snowdrive");
    assert!(status.success(), "snowdrive should exit 0 after SIGINT");

    let _ = std::fs::remove_file(&img);
}

/// The same file path as both `--disk img=` and `--disk cd=` emits a
/// dual-mount warning on stderr before the server starts.
#[cfg(unix)]
#[test]
fn serve_warns_on_block_and_cdblock_dual_mount() {
    use std::io::BufRead;
    use std::sync::mpsc;
    use std::time::Duration;

    let dir = std::env::temp_dir();
    let img = dir.join(format!("snowdrive_dualcd_{}.img", std::process::id()));
    std::fs::write(&img, [0u8; 512]).unwrap();
    let path = img.to_string_lossy().to_string();

    let mut child = Command::new(env!("CARGO_BIN_EXE_snowdrive"))
        .args([
            "serve",
            "--disk",
            &format!("img={path}"),
            "--disk",
            &format!("cd={path}"),
            "--iscsi",
            "127.0.0.1:0",
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn snowdrive");

    let (ready_tx, ready_rx) = mpsc::channel();
    {
        let stderr = child.stderr.take().expect("child stderr");
        std::thread::spawn(move || {
            let mut line = String::new();
            let mut reader = std::io::BufReader::new(stderr);
            let mut warnings = Vec::new();
            while reader.read_line(&mut line).map(|n| n > 0).unwrap_or(false) {
                if line.contains("warning:") {
                    warnings.push(line.clone());
                }
                if line.contains("listening") {
                    let _ = ready_tx.send(warnings);
                    return;
                }
                line.clear();
            }
            let _ = ready_tx.send(warnings);
        });
    }

    let warnings = ready_rx
        .recv_timeout(Duration::from_secs(5))
        .unwrap_or_else(|_| {
            let _ = Command::new("kill")
                .arg("-KILL")
                .arg(child.id().to_string())
                .status();
            let _ = child.wait();
            panic!("snowdrive did not announce 'listening'");
        });
    assert!(
        warnings.iter().any(|w| w.contains(&path)),
        "expected a dual-mount warning for {path}, got {warnings:?}"
    );

    let sent = Command::new("kill")
        .arg("-INT")
        .arg(child.id().to_string())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    assert!(sent, "kill -INT failed");

    let status = child.wait().expect("wait for snowdrive");
    assert!(status.success(), "snowdrive should exit 0 after SIGINT");

    let _ = std::fs::remove_file(&img);
}
