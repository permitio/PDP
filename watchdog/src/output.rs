//! Capturing a supervised child's stdout/stderr.
//!
//! By default a watched child inherits the parent's file descriptors, so its
//! output goes straight to the parent's own stdout/stderr with nothing to say
//! which process produced it. Supplying a [`ChildOutputHandler`] through
//! [`CommandWatchdogOptions::output_handler`](crate::CommandWatchdogOptions::output_handler)
//! switches those two streams to pipes that the watchdog drains, handing the
//! caller one line at a time.
//!
//! The watchdog deliberately does no interpretation: it splits on `\n`, bounds
//! the line length, lossily decodes UTF-8, and passes the result on. What a
//! line *means* — its severity, its structure — is the caller's business,
//! because only the caller knows which program it started.

use std::sync::Arc;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, BufReader};

/// Which of a supervised child's two output streams a line came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChildStream {
    Stdout,
    Stderr,
}

impl ChildStream {
    /// A stable, lowercase name suitable for use as a log field value.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Stdout => "stdout",
            Self::Stderr => "stderr",
        }
    }
}

impl std::fmt::Display for ChildStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Receives each line a supervised child writes to stdout or stderr.
///
/// Supplying a handler through
/// [`CommandWatchdogOptions::output_handler`](crate::CommandWatchdogOptions::output_handler)
/// switches the child from inheriting the parent's file descriptors to pipes
/// the watchdog drains.
///
/// # Bounded work is fine; unbounded blocking is not
///
/// `on_line` is called from the task that keeps the child's pipe drained.
/// Bounded, synchronous work — a line-buffered write through a logger, which
/// is the expected implementation — does not meaningfully stall this seam.
/// What must not happen is `await`ing, an unbounded blocking call, or taking
/// a lock some other task may hold for a long time: for as long as `on_line`
/// has not returned, this task is not reading, and a pipe that stops being
/// read fills its kernel buffer (~64 KiB on Linux) and the child then blocks
/// in `write` for as long as the stall lasts — which presents as a hung
/// process and, under [`ServiceWatchdog`](crate::ServiceWatchdog), a failed
/// health check and a restart loop.
///
/// # Implementations must not panic
///
/// A panic kills the reader task outright, which is a different failure from
/// a stall: the task ending drops the `BufReader` and the pipe handle it
/// owns, closing the read end. A child that goes on writing to that fd no
/// longer blocks — it takes `SIGPIPE` and dies, and the supervisor
/// restart-loops it. Either way draining has stopped and the child is in
/// trouble, so handle every malformed input rather than unwrapping.
pub trait ChildOutputHandler: Send + Sync + 'static {
    fn on_line(&self, stream: ChildStream, line: &str);
}

/// Most bytes read from the child for a single line.
///
/// A child is free to write a gigabyte without ever emitting a newline, and a
/// reader that simply accumulated until one arrived would let it grow the
/// supervising process's memory without limit. Lines longer than this are
/// delivered truncated, marked with [`TRUNCATION_MARKER`], and the reader then
/// resynchronises on the next newline.
///
/// This bounds the bytes taken off the pipe, which is not the same as the
/// length of the `&str` the handler receives. Decoding is lossy, and each
/// invalid byte becomes a U+FFFD costing three, so a line of entirely invalid
/// UTF-8 arrives about three times this long. Memory stays bounded either way
/// — one line at a time, at a fixed multiple of this constant — but a handler
/// budgeting on the delivered length should budget for 3x.
pub const MAX_LINE_BYTES: usize = 16 * 1024;

/// Appended to a line that hit [`MAX_LINE_BYTES`], so a reader of the log can
/// tell a truncated line from a complete one.
pub const TRUNCATION_MARKER: &str = "…[truncated by watchdog]";

/// What [`read_line_bounded`] found.
///
/// `Eof` is distinct from an empty line: a child that writes a bare `\n`
/// produced a line, and conflating the two would end the stream early.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ReadOutcome {
    Eof,
    Line { truncated: bool },
}

/// Read one `\n`-terminated line into `out`, appending at most
/// [`MAX_LINE_BYTES`] and discarding any excess up to and including the
/// newline.
///
/// The trailing `\n` is not appended. `out` is expected to be empty on entry.
pub(crate) async fn read_line_bounded<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    out: &mut Vec<u8>,
) -> std::io::Result<ReadOutcome> {
    let mut truncated = false;
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            // EOF. Anything already buffered is a final, unterminated line —
            // often the very message that explains why the child exited, so it
            // must not be dropped.
            return Ok(if out.is_empty() {
                ReadOutcome::Eof
            } else {
                ReadOutcome::Line { truncated }
            });
        }
        match available.iter().position(|&b| b == b'\n') {
            Some(idx) => {
                append_bounded(out, &available[..idx], &mut truncated);
                reader.consume(idx + 1);
                return Ok(ReadOutcome::Line { truncated });
            }
            None => {
                let len = available.len();
                append_bounded(out, available, &mut truncated);
                reader.consume(len);
            }
        }
    }
}

/// Append `chunk` to `out`, stopping at [`MAX_LINE_BYTES`] and setting
/// `truncated` if anything had to be dropped. Bytes beyond the cap are
/// discarded rather than buffered, which is what bounds memory.
fn append_bounded(out: &mut Vec<u8>, chunk: &[u8], truncated: &mut bool) {
    let room = MAX_LINE_BYTES.saturating_sub(out.len());
    if chunk.len() > room {
        *truncated = true;
    }
    out.extend_from_slice(&chunk[..room.min(chunk.len())]);
}

/// Drain `reader` to EOF, handing each line to `handler`.
///
/// Returns when the stream ends, which for a child's pipe is when that
/// generation of the child exits — so each spawn's reader task retires on its
/// own and nothing accumulates across restarts.
pub(crate) async fn pump<R: AsyncRead + Unpin>(
    reader: R,
    stream: ChildStream,
    handler: Arc<dyn ChildOutputHandler>,
) {
    let mut reader = BufReader::new(reader);
    let mut buf = Vec::with_capacity(256);
    loop {
        buf.clear();
        let outcome = match read_line_bounded(&mut reader, &mut buf).await {
            Ok(outcome) => outcome,
            // `Interrupted` is transient (e.g. a delivered signal) and
            // `BufReader::fill_buf` does not retry it internally — retry it
            // here instead, so one signal does not permanently blind this
            // stream.
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            // Any other read error on a child's pipe means the pipe is gone.
            // There is nothing to recover and nowhere to report it that would
            // not risk a loop, so stop draining this stream.
            Err(_) => return,
        };
        match outcome {
            ReadOutcome::Eof => return,
            ReadOutcome::Line { truncated } => {
                // A child writing CRLF would otherwise leave a stray control
                // character at the end of every message.
                let bytes = match buf.last() {
                    Some(b'\r') => &buf[..buf.len() - 1],
                    _ => &buf[..],
                };
                let mut line = String::from_utf8_lossy(bytes).into_owned();
                if truncated {
                    line.push_str(TRUNCATION_MARKER);
                }
                handler.on_line(stream, &line);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tokio::io::BufReader;

    /// Collects everything a handler is given, so a test can assert on the
    /// exact sequence of (stream, line) pairs.
    #[derive(Default)]
    struct Collector(Mutex<Vec<(ChildStream, String)>>);

    impl ChildOutputHandler for Collector {
        fn on_line(&self, stream: ChildStream, line: &str) {
            self.0
                .lock()
                .expect("lock")
                .push((stream, line.to_string()));
        }
    }

    impl Collector {
        fn lines(&self) -> Vec<(ChildStream, String)> {
            self.0.lock().expect("lock").clone()
        }
    }

    #[tokio::test]
    async fn splits_on_newlines_and_strips_them() {
        let collector = Arc::new(Collector::default());
        pump(
            &b"one\ntwo\nthree\n"[..],
            ChildStream::Stdout,
            collector.clone(),
        )
        .await;
        assert_eq!(
            collector.lines(),
            vec![
                (ChildStream::Stdout, "one".to_string()),
                (ChildStream::Stdout, "two".to_string()),
                (ChildStream::Stdout, "three".to_string()),
            ]
        );
    }

    /// A child that exits without a trailing newline must not have its last
    /// line swallowed — that line is often the panic or usage error which
    /// explains why it exited.
    #[tokio::test]
    async fn a_final_unterminated_line_is_still_delivered() {
        let collector = Arc::new(Collector::default());
        pump(
            &b"first\nlast without newline"[..],
            ChildStream::Stderr,
            collector.clone(),
        )
        .await;
        assert_eq!(
            collector.lines(),
            vec![
                (ChildStream::Stderr, "first".to_string()),
                (ChildStream::Stderr, "last without newline".to_string()),
            ]
        );
    }

    #[tokio::test]
    async fn an_empty_stream_yields_no_lines() {
        let collector = Arc::new(Collector::default());
        pump(&b""[..], ChildStream::Stdout, collector.clone()).await;
        assert!(collector.lines().is_empty());
    }

    /// A trailing `\r` from a child that writes CRLF must not become part of
    /// the message, or every line ends in a stray control character.
    #[tokio::test]
    async fn a_trailing_carriage_return_is_stripped() {
        let collector = Arc::new(Collector::default());
        pump(
            &b"crlf line\r\n"[..],
            ChildStream::Stdout,
            collector.clone(),
        )
        .await;
        assert_eq!(
            collector.lines(),
            vec![(ChildStream::Stdout, "crlf line".to_string())]
        );
    }

    /// The whole point of the cap: one child line that never terminates must
    /// not be able to grow the supervisor's memory. The over-long line is
    /// delivered truncated, and the stream keeps working afterwards.
    #[tokio::test]
    async fn an_over_long_line_is_truncated_and_the_stream_recovers() {
        let mut input = vec![b'x'; MAX_LINE_BYTES * 3];
        input.extend_from_slice(b"\nnext line\n");
        let collector = Arc::new(Collector::default());
        pump(&input[..], ChildStream::Stdout, collector.clone()).await;

        let lines = collector.lines();
        assert_eq!(
            lines.len(),
            2,
            "expected the truncated line then the next one, got {lines:?}"
        );
        assert!(
            lines[0].1.len() <= MAX_LINE_BYTES + TRUNCATION_MARKER.len(),
            "truncated line must be bounded, got {} bytes",
            lines[0].1.len()
        );
        assert!(
            lines[0].1.ends_with(TRUNCATION_MARKER),
            "a truncated line must say so, got {:?}",
            lines[0].1
        );
        assert_eq!(
            lines[1].1, "next line",
            "the reader must resynchronise on the next newline rather than \
             emitting the discarded remainder as its own line"
        );
    }

    /// A child may write arbitrary bytes (a binary blob, a broken locale). It
    /// must not silence the stream.
    #[tokio::test]
    async fn invalid_utf8_is_lossily_decoded_not_dropped() {
        let collector = Arc::new(Collector::default());
        pump(
            &b"before \xff\xfe after\n"[..],
            ChildStream::Stderr,
            collector.clone(),
        )
        .await;
        let lines = collector.lines();
        assert_eq!(lines.len(), 1);
        assert!(lines[0].1.starts_with("before "), "got {:?}", lines[0].1);
        assert!(lines[0].1.ends_with(" after"), "got {:?}", lines[0].1);
    }

    #[tokio::test]
    async fn read_line_bounded_reports_eof_separately_from_an_empty_line() {
        let mut reader = BufReader::new(&b"\n"[..]);
        let mut out = Vec::new();
        assert!(matches!(
            read_line_bounded(&mut reader, &mut out)
                .await
                .expect("read"),
            ReadOutcome::Line { truncated: false }
        ));
        assert!(out.is_empty(), "an empty line is an empty line, not EOF");

        out.clear();
        assert!(matches!(
            read_line_bounded(&mut reader, &mut out)
                .await
                .expect("read"),
            ReadOutcome::Eof
        ));
    }

    /// `ErrorKind::Interrupted` is transient (e.g. a delivered signal), and
    /// `AsyncBufReadExt::fill_buf` does not retry it internally. `pump` must,
    /// so one signal cannot permanently blind the stream.
    #[tokio::test]
    async fn an_interrupted_read_is_retried_not_treated_as_fatal() {
        use std::pin::Pin;
        use std::task::{Context, Poll};
        use tokio::io::ReadBuf;

        /// An `AsyncRead` that fails once with `Interrupted`, then reads out
        /// `data` normally.
        struct FlakyOnce {
            errored: bool,
            data: &'static [u8],
            pos: usize,
        }

        impl AsyncRead for FlakyOnce {
            fn poll_read(
                mut self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                buf: &mut ReadBuf<'_>,
            ) -> Poll<std::io::Result<()>> {
                if !self.errored {
                    self.errored = true;
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::Interrupted,
                        "simulated signal",
                    )));
                }
                let remaining = &self.data[self.pos..];
                let n = remaining.len().min(buf.remaining());
                buf.put_slice(&remaining[..n]);
                self.pos += n;
                Poll::Ready(Ok(()))
            }
        }

        let collector = Arc::new(Collector::default());
        pump(
            FlakyOnce {
                errored: false,
                data: b"after the blip\n",
                pos: 0,
            },
            ChildStream::Stdout,
            collector.clone(),
        )
        .await;
        assert_eq!(
            collector.lines(),
            vec![(ChildStream::Stdout, "after the blip".to_string())],
            "a transient Interrupted error must not end the stream"
        );
    }
}
