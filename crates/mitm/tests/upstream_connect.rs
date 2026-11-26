use std::net::SocketAddr;
use std::time::Duration;

use credshim_mitm::upstream::connect_first;
use tokio::net::{TcpListener, TcpSocket};

const STAGGER: Duration = Duration::from_millis(100);

struct RefusingPort {
    addr: SocketAddr,
    _socket: TcpSocket,
}

fn refusing_port() -> RefusingPort {
    let socket = TcpSocket::new_v4().unwrap();
    socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    RefusingPort {
        addr: socket.local_addr().unwrap(),
        _socket: socket,
    }
}

#[tokio::test]
async fn an_unreachable_first_address_falls_over_to_one_that_answers() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let reachable = listener.local_addr().unwrap();
    let unreachable: SocketAddr = "192.0.2.1:443".parse().unwrap();

    let stream = tokio::time::timeout(
        Duration::from_secs(5),
        connect_first(&[unreachable, reachable], STAGGER),
    )
    .await
    .expect("the reachable address is tried without waiting for the unreachable one")
    .unwrap();

    assert_eq!(stream.peer_addr().unwrap(), reachable);
}

#[tokio::test]
async fn a_refused_first_address_falls_over_to_one_that_answers() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let reachable = listener.local_addr().unwrap();
    let refused = refusing_port();

    let stream = connect_first(&[refused.addr, reachable], STAGGER)
        .await
        .unwrap();

    assert_eq!(stream.peer_addr().unwrap(), reachable);
}

#[tokio::test]
async fn when_every_address_is_refused_the_connect_fails() {
    let first = refusing_port();
    let second = refusing_port();

    let result = tokio::time::timeout(
        Duration::from_secs(5),
        connect_first(&[first.addr, second.addr], STAGGER),
    )
    .await
    .expect("refused addresses fail without waiting for a timeout");

    assert!(result.is_err());
}
