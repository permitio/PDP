//! An in-process stand-in for a Redis server, so tests can exercise the Redis cache backend
//! without a `redis-server` binary. It speaks enough RESP2 for the commands `RedisCache`
//! sends.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, PoisonError};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::OwnedReadHalf;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

type Store = Arc<Mutex<HashMap<Vec<u8>, Vec<u8>>>>;

pub(crate) struct FakeRedis {
    addr: SocketAddr,
    store: Store,
    accept_task: JoinHandle<()>,
}

impl Drop for FakeRedis {
    fn drop(&mut self) {
        self.accept_task.abort();
    }
}

impl FakeRedis {
    pub(crate) async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind the fake Redis listener");
        let addr = listener.local_addr().expect("read the fake Redis address");
        let store = Store::default();
        let accept_store = store.clone();
        let accept_task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(serve_connection(stream, accept_store.clone()));
            }
        });
        Self {
            addr,
            store,
            accept_task,
        }
    }

    pub(crate) fn url(&self) -> String {
        format!("redis://{}/", self.addr)
    }

    /// How many keys the server holds.
    pub(crate) fn key_count(&self) -> usize {
        self.store
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }
}

async fn serve_connection(stream: TcpStream, store: Store) {
    let (read, mut write) = stream.into_split();
    let mut reader = BufReader::new(read);
    while let Ok(Some(command)) = read_command(&mut reader).await {
        let reply = execute(&store, &command);
        if write.write_all(&reply).await.is_err() {
            return;
        }
    }
}

/// Reads one command, sent as a RESP array of bulk strings. `None` means the client hung up.
async fn read_command(reader: &mut BufReader<OwnedReadHalf>) -> io::Result<Option<Vec<Vec<u8>>>> {
    let mut line = String::new();
    if reader.read_line(&mut line).await? == 0 {
        return Ok(None);
    }
    let arg_count = parse_header(&line, '*')?;
    let mut args = Vec::with_capacity(arg_count);
    for _ in 0..arg_count {
        line.clear();
        reader.read_line(&mut line).await?;
        let len = parse_header(&line, '$')?;
        let mut arg = vec![0; len + 2];
        reader.read_exact(&mut arg).await?;
        arg.truncate(len);
        args.push(arg);
    }
    Ok(Some(args))
}

fn parse_header(line: &str, marker: char) -> io::Result<usize> {
    line.trim_end()
        .strip_prefix(marker)
        .and_then(|len| len.parse().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, format!("bad RESP: {line}")))
}

fn execute(store: &Store, command: &[Vec<u8>]) -> Vec<u8> {
    let Some((name, args)) = command.split_first() else {
        return b"-ERR empty command\r\n".to_vec();
    };
    let name = String::from_utf8_lossy(name).to_ascii_uppercase();
    let mut store = store.lock().unwrap_or_else(PoisonError::into_inner);
    match (name.as_str(), args) {
        ("PING", _) => b"+PONG\r\n".to_vec(),
        ("CLIENT", _) => b"+OK\r\n".to_vec(),
        ("GET", [key]) => bulk(store.get(key)),
        ("SET", [key, value, ..]) | ("SETEX", [key, _, value]) => {
            store.insert(key.clone(), value.clone());
            b"+OK\r\n".to_vec()
        }
        _ => format!("-ERR unsupported command '{name}'\r\n").into_bytes(),
    }
}

fn bulk(value: Option<&Vec<u8>>) -> Vec<u8> {
    let Some(value) = value else {
        return b"$-1\r\n".to_vec();
    };
    let mut reply = format!("${}\r\n", value.len()).into_bytes();
    reply.extend_from_slice(value);
    reply.extend_from_slice(b"\r\n");
    reply
}
