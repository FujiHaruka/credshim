use std::process::Stdio;
use std::time::Duration;

use credshim_testkit::{Echo, MockUpstream};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::process::Command;

#[tokio::test]
async fn run_serves_a_forward_proxy() {
    let mock = MockUpstream::http().start().await;
    let mut child = Command::new(env!("CARGO_BIN_EXE_credshim"))
        .args(["run", "--listen", "127.0.0.1:0"])
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut stderr = BufReader::new(child.stderr.take().unwrap()).lines();
    let proxy_addr = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let line = stderr.next_line().await.unwrap().expect("proxy exited");
            if let Some(rest) = line.split("addr=").nth(1) {
                break rest.split_whitespace().next().unwrap().to_string();
            }
        }
    })
    .await
    .expect("proxy never reported its listen address");

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
    let output = Command::new(env!("CARGO_BIN_EXE_credshim"))
        .args(["run", "--listen", "0.0.0.0:0"])
        .output()
        .await
        .unwrap();

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("non-loopback"));
}
