use anyhow::Result;

pub fn enable(port: u16) -> Result<()> {
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

    Ok(())
}

pub fn disable() -> Result<()> {
    println!("unset http_proxy HTTP_PROXY");
    println!("unset https_proxy HTTPS_PROXY");
    println!("unset all_proxy ALL_PROXY");
    println!("unset no_proxy NO_PROXY");

    Ok(())
}

pub fn status(port: u16) -> Result<String> {
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

    let mut result = String::new();
    result.push_str(&format!(
        "http_proxy:  {} (expected: {expected_http})\n",
        if http_active { "active" } else { "inactive" }
    ));
    result.push_str(&format!(
        "https_proxy: {} (expected: {expected_http})\n",
        if https_active { "active" } else { "inactive" }
    ));
    result.push_str(&format!(
        "all_proxy:   {} (expected: {expected_socks})\n",
        if socks_active { "active" } else { "inactive" }
    ));
    result.push_str(&format!("no_proxy:    {no_proxy}\n"));

    Ok(result)
}
