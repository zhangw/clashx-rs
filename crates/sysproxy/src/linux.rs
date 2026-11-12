//! Linux system proxy management.
//!
//! Linux has no portable, user-scoped system proxy store, so this module does
//! not mutate anything: [`enable`] prints shell `export` lines and [`disable`]
//! prints `unset` lines on stdout. That is the documented contract — the caller
//! evaluates or sources the output. [`status`] only inspects the environment it
//! inherited and compares it with the values [`enable`] would print for a port.

pub fn enable(port: u16) {
    let proxy = format!("http://127.0.0.1:{port}");
    let socks = format!("socks5://127.0.0.1:{port}");

    println!("export http_proxy=\"{proxy}\"");
    println!("export HTTP_PROXY=\"{proxy}\"");
    println!("export https_proxy=\"{proxy}\"");
    println!("export HTTPS_PROXY=\"{proxy}\"");
    println!("export all_proxy=\"{socks}\"");
    println!("export ALL_PROXY=\"{socks}\"");
    println!("export no_proxy=\"localhost,127.0.0.1,::1\"");
    println!("export NO_PROXY=\"localhost,127.0.0.1,::1\"");
}

pub fn disable() {
    println!("unset http_proxy HTTP_PROXY");
    println!("unset https_proxy HTTPS_PROXY");
    println!("unset all_proxy ALL_PROXY");
    println!("unset no_proxy NO_PROXY");
}

#[expect(
    clippy::similar_names,
    reason = "locals mirror the environment variable names they read"
)]
pub fn status(port: u16) -> String {
    use std::fmt::Write as _;

    let expected_http = format!("http://127.0.0.1:{port}");
    let expected_socks = format!("socks5://127.0.0.1:{port}");

    let http_proxy = std::env::var("http_proxy")
        .or_else(|_| std::env::var("HTTP_PROXY"))
        .unwrap_or_default();
    let https_proxy = std::env::var("https_proxy")
        .or_else(|_| std::env::var("HTTPS_PROXY"))
        .unwrap_or_default();
    let all_proxy = std::env::var("all_proxy")
        .or_else(|_| std::env::var("ALL_PROXY"))
        .unwrap_or_default();
    let no_proxy = std::env::var("no_proxy")
        .or_else(|_| std::env::var("NO_PROXY"))
        .unwrap_or_default();

    let http_active = http_proxy == expected_http;
    let https_active = https_proxy == expected_http;
    let socks_active = all_proxy == expected_socks;

    // Writing to a String cannot fail; the `let _` keeps the formatter calls
    // concise without an unwrap in production code.
    let mut result = String::new();
    let _ = writeln!(
        result,
        "http_proxy:  {} (expected: {expected_http})",
        if http_active { "active" } else { "inactive" }
    );
    let _ = writeln!(
        result,
        "https_proxy: {} (expected: {expected_http})",
        if https_active { "active" } else { "inactive" }
    );
    let _ = writeln!(
        result,
        "all_proxy:   {} (expected: {expected_socks})",
        if socks_active { "active" } else { "inactive" }
    );
    let _ = writeln!(result, "no_proxy:    {no_proxy}");

    result
}
