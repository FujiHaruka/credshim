mod common;

use common::{output, spawn_run};
use credshim_testkit::{Echo, MockUpstream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[tokio::test]
async fn run_serves_a_forward_proxy() {
    let mock = MockUpstream::http().start().await;
    let home = tempfile::tempdir().unwrap();
    let proxy = spawn_run(home.path(), &["--listen", "127.0.0.1:0"]).await;
    let proxy_addr = proxy.addr.clone();

    let target = mock.url("127.0.0.1", "/cli");
    let mut tcp = TcpStream::connect(&proxy_addr).await.unwrap();
    tcp.write_all(
        format!("GET {target} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .await
    .unwrap();
    let mut response = String::new();
    tcp.read_to_string(&mut response).await.unwrap();

    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    let echo: Echo =
        serde_json::from_str(&response[response.find("\r\n\r\n").unwrap() + 4..]).unwrap();
    assert_eq!(echo.path, "/cli");
}

#[tokio::test]
async fn run_refuses_a_public_listen_address() {
    let home = tempfile::tempdir().unwrap();
    let output = output(home.path(), &["run", "--listen", "192.0.2.1:8787"]).await;

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("non-loopback"));
}
