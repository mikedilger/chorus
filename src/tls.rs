use crate::config::Config;
use crate::error::{ChorusError, Error};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;
use tokio_rustls::{rustls, TlsAcceptor};

pub fn tls_acceptor(config: &Config) -> Result<TlsAcceptor, Error> {
    let cert_file = File::open(&config.certchain_pem_path)?;
    let mut certificates: Vec<CertificateDer<'static>> = Vec::new();
    for maybe_cert in rustls_pemfile::certs(&mut BufReader::new(cert_file)) {
        let cert = maybe_cert?;
        certificates.push(cert);
    }

    let key_file = File::open(&config.key_pem_path)?;
    let mut keys: Vec<PrivateKeyDer> = Vec::new();
    for maybe_key in rustls_pemfile::pkcs8_private_keys(&mut BufReader::new(key_file)) {
        let key = maybe_key?;
        keys.push(PrivateKeyDer::Pkcs8(key));
    }
    keys.reverse();

    let key = match keys.pop() {
        Some(k) => k,
        None => return Err(ChorusError::NoPrivateKey.into()),
    };

    let tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificates, key)?;

    Ok(TlsAcceptor::from(Arc::new(tls_config)))
}
