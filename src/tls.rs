use crate::config::Config;
use crate::error::{ChorusError, Error};
use crate::globals::GLOBALS;
use rustls::{Certificate, PrivateKey};
use std::fs::File;
use std::io::BufReader;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::{rustls, TlsAcceptor};

pub fn tls_acceptor(config: &Config) -> Result<TlsAcceptor, Error> {
    let certs: Vec<Certificate> =
        rustls_pemfile::certs(&mut BufReader::new(File::open(&config.certchain_pem_path)?))?
            .drain(..)
            .map(Certificate)
            .collect();

    let mut keys: Vec<PrivateKey> =
        rustls_pemfile::pkcs8_private_keys(&mut BufReader::new(File::open(&config.key_pem_path)?))?
            .drain(..)
            .rev()
            .map(PrivateKey)
            .collect();

    let key = match keys.pop() {
        Some(k) => k,
        None => return Err(ChorusError::NoPrivateKey.into()),
    };

    let tls_config = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    Ok(TlsAcceptor::from(Arc::new(tls_config)))
}

/// A stream that might be protected with TLS.
#[allow(clippy::large_enum_variant)] // not great though
#[derive(Debug)]
pub enum MaybeTlsStream<S> {
    /// Unencrypted socket stream.
    Plain(S),
    /// Encrypted socket stream using `rustls`.
    Rustls(tokio_rustls::server::TlsStream<S>),
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for MaybeTlsStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            MaybeTlsStream::Plain(ref mut s) => {
                // Count bytes for statistics
                let pre = buf.filled().len();
                let result = Pin::new(s).poll_read(cx, buf);
                let post = buf.filled().len();
                let count = post - pre;
                if count > 0 {
                    let _ = GLOBALS
                        .bytes_inbound
                        .fetch_add(count as u64, Ordering::SeqCst);
                }
                result
            }
            MaybeTlsStream::Rustls(s) => {
                // Count bytes for statistics
                let pre = buf.filled().len();
                let result = Pin::new(s).poll_read(cx, buf);
                let post = buf.filled().len();
                let count = post - pre;
                if count > 0 {
                    let _ = GLOBALS
                        .bytes_inbound
                        .fetch_add(count as u64, Ordering::SeqCst);
                }
                result
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for MaybeTlsStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        match self.get_mut() {
            MaybeTlsStream::Plain(ref mut s) => {
                // Count bytes for statistics
                let _ = GLOBALS
                    .bytes_outbound
                    .fetch_add(buf.len() as u64, Ordering::SeqCst);
                Pin::new(s).poll_write(cx, buf)
            }
            MaybeTlsStream::Rustls(s) => {
                // Count bytes for statistics
                let _ = GLOBALS
                    .bytes_outbound
                    .fetch_add(buf.len() as u64, Ordering::SeqCst);
                Pin::new(s).poll_write(cx, buf)
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        match self.get_mut() {
            MaybeTlsStream::Plain(ref mut s) => Pin::new(s).poll_flush(cx),
            MaybeTlsStream::Rustls(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        match self.get_mut() {
            MaybeTlsStream::Plain(ref mut s) => Pin::new(s).poll_shutdown(cx),
            MaybeTlsStream::Rustls(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}
