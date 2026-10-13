//! An in-process stand-in for a Redis server, so tests can exercise the Redis cache backend
//! without a `redis-server` binary. It speaks enough RESP2 for the commands `RedisCache`
//! sends, records every command it receives, and can be paused or stopped the way a real
//! server is under `docker pause` or `docker stop`.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::OwnedReadHalf;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinHandle;

/// How the server treats connections and commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    /// Answers every command.
    Serving,
    /// Accepts connections and commands but answers nothing until it serves again, like a
    /// container under `docker pause` or a port that drops packets. Held commands are answered
    /// in order on resume, as a real server's would be.
    Paused,
    /// Closes every connection, like a stopped server.
    Stopped,
}

struct Shared {
    mode: watch::Sender<Mode>,
    /// The name of every command received, in order, including commands still held.
    received: watch::Sender<Vec<String>>,
    store: Mutex<HashMap<Vec<u8>, Vec<u8>>>,
}

pub(crate) struct FakeRedis {
    addr: SocketAddr,
    shared: Arc<Shared>,
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
        let shared = Arc::new(Shared {
            mode: watch::Sender::new(Mode::Serving),
            received: watch::Sender::new(Vec::new()),
            store: Mutex::new(HashMap::new()),
        });
        let accept_shared = shared.clone();
        let accept_task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                if *accept_shared.mode.borrow() == Mode::Stopped {
                    continue;
                }
                tokio::spawn(serve_connection(stream, accept_shared.clone()));
            }
        });
        Self {
            addr,
            shared,
            accept_task,
        }
    }

    pub(crate) fn url(&self) -> String {
        format!("redis://{}/", self.addr)
    }

    pub(crate) fn set_mode(&self, mode: Mode) {
        self.shared.mode.send_replace(mode);
    }

    /// How many commands named `name` (upper case, e.g. `"MGET"`) the server has received.
    pub(crate) fn command_count(&self, name: &str) -> usize {
        count(&self.shared.received.borrow(), name)
    }

    /// How many commands of any kind the server has received.
    pub(crate) fn total_commands(&self) -> usize {
        self.shared.received.borrow().len()
    }

    /// Waits until the server has received at least `at_least` commands named `name`.
    ///
    /// # Panics
    ///
    /// Panics if that takes more than five seconds.
    pub(crate) async fn wait_for_commands(&self, name: &str, at_least: usize) {
        let mut received = self.shared.received.subscribe();
        let wait = received.wait_for(|received| count(received, name) >= at_least);
        let waited = tokio::time::timeout(Duration::from_secs(5), wait).await;
        assert!(
            matches!(waited, Ok(Ok(_))),
            "the fake Redis did not receive {at_least} {name} command(s)"
        );
    }

    /// How many keys the server holds.
    pub(crate) fn key_count(&self) -> usize {
        self.shared
            .store
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }
}

fn count(received: &[String], name: &str) -> usize {
    let mut total = 0;
    for command in received {
        if command == name {
            total += 1;
        }
    }
    total
}

async fn serve_connection(stream: TcpStream, shared: Arc<Shared>) {
    let mut mode = shared.mode.subscribe();
    let (read, mut write) = stream.into_split();
    let mut reader = BufReader::new(read);
    loop {
        let command = tokio::select! {
            command = read_command(&mut reader) => command,
            _ = mode.wait_for(|mode| *mode == Mode::Stopped) => return,
        };
        let Ok(Some(command)) = command else {
            return;
        };
        shared.record(&command);
        let running = match mode.wait_for(|mode| *mode != Mode::Paused).await {
            Ok(mode) => *mode,
            Err(_) => return,
        };
        if running == Mode::Stopped {
            return;
        }
        let reply = shared.execute(&command);
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

fn command_name(command: &[Vec<u8>]) -> String {
    match command.first() {
        Some(name) => String::from_utf8_lossy(name).to_ascii_uppercase(),
        None => String::new(),
    }
}

impl Shared {
    fn record(&self, command: &[Vec<u8>]) {
        let name = command_name(command);
        self.received.send_modify(|received| received.push(name));
    }

    fn execute(&self, command: &[Vec<u8>]) -> Vec<u8> {
        let name = command_name(command);
        let args = command.get(1..).unwrap_or_default();
        let mut store = self.store.lock().unwrap_or_else(PoisonError::into_inner);
        match (name.as_str(), args) {
            ("PING", _) => b"+PONG\r\n".to_vec(),
            ("CLIENT", _) => b"+OK\r\n".to_vec(),
            ("GET", [key]) => bulk(store.get(key)),
            ("MGET", keys) => {
                let mut reply = format!("*{}\r\n", keys.len()).into_bytes();
                for key in keys {
                    reply.extend(bulk(store.get(key)));
                }
                reply
            }
            ("SET", [key, value, ..]) | ("SETEX", [key, _, value]) => {
                store.insert(key.clone(), value.clone());
                b"+OK\r\n".to_vec()
            }
            ("DEL", keys) => {
                let mut removed = 0;
                for key in keys {
                    if store.remove(key).is_some() {
                        removed += 1;
                    }
                }
                format!(":{removed}\r\n").into_bytes()
            }
            _ => format!("-ERR unsupported command '{name}'\r\n").into_bytes(),
        }
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
