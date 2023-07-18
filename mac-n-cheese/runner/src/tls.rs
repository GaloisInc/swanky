use std::{
    fs::File,
    io::{BufReader, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::Path,
    sync::Arc,
    time::Duration,
};

use bufstream::BufStream;
use eyre::Context;
use mac_n_cheese_party::{self as party, either::PartyEither, Party};
use party::{either::PartyEitherCopy, WhichParty};
use rand::RngCore;
use rustls::{ClientConnection, ServerConnection, StreamOwned};
use vectoreyes::SimdBase;

use crate::{keys::Keys, MAC_N_CHEESE_RUNNER_VERSION};

pub struct TlsConnection<P: Party> {
    inner: BufStream<
        PartyEither<
            P,
            StreamOwned<ServerConnection, TcpStream>,
            StreamOwned<ClientConnection, TcpStream>,
        >,
    >,
    needs_flush_on_read: bool,
}
impl<P: Party> Write for TlsConnection<P> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.needs_flush_on_read = true;
        self.inner.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()?;
        self.needs_flush_on_read = false;
        Ok(())
    }
}
impl<P: Party> Read for TlsConnection<P> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.needs_flush_on_read {
            self.flush()?;
        }
        self.inner.read(buf)
    }
}

const PURPORTED_TLS_HOST_NAME: &str = "galois.macncheese.example.com";

const BUF_SIZE: usize = 16 * 1024; // Max TLS record size

// note: non standard tls setup
/// On the prover, `address` is the address to listen on. On the verifier, it's the address to
/// connect to.
// root_ca should be a list of files. probably not standard.
// tls_cert should have both public and private keys
// extra connections are in order
// TODO: set TCP keepalive?
pub fn initiate_tls<P: Party>(
    address: SocketAddr,
    root_cas: &Path,
    tls_cert: &Path,
    num_connections: PartyEitherCopy<P, (), usize>,
) -> eyre::Result<(Keys<P>, TlsConnection<P>, Vec<TcpStream>)> {
    let tls_root_store = {
        let mut tls_root_store = rustls::RootCertStore::empty();
        let mut f = BufReader::new(
            File::open(root_cas)
                .with_context(|| format!("Unable to open root CA file {:?}", root_cas))?,
        );
        tls_root_store.add_parsable_certificates(
            &rustls_pemfile::certs(&mut f)
                .with_context(|| format!("Unable to read root CAs from file {:?}", root_cas))?,
        );
        tls_root_store
    };
    let (tls_certs, tls_private_key) = {
        let mut f = BufReader::new(
            File::open(tls_cert)
                .with_context(|| format!("Unable to open TLS cert file {:?}", tls_cert))?,
        );
        let mut tls_certs: Vec<_> = Default::default();
        let mut key = None;
        for x in rustls_pemfile::read_all(&mut f)
            .with_context(|| format!("Unable to read TLS cert file {:?}", tls_cert))?
            .into_iter()
        {
            match x {
                rustls_pemfile::Item::X509Certificate(c) => tls_certs.push(rustls::Certificate(c)),
                rustls_pemfile::Item::RSAKey(k) => {
                    key = Some(k);
                }
                rustls_pemfile::Item::PKCS8Key(k) => {
                    key = Some(k);
                }
                _ => {
                    // Ignore unknown entries.
                }
            }
        }
        if let Some(key) = key {
            (tls_certs, rustls::PrivateKey(key))
        } else {
            eyre::bail!("No private key found in {:?}", tls_cert);
        }
    };
    Ok(match P::WHICH {
        WhichParty::Prover(e) => {
            let tls_config = rustls::ServerConfig::builder()
                .with_cipher_suites(&[rustls::cipher_suite::TLS13_AES_128_GCM_SHA256])
                .with_safe_default_kx_groups()
                .with_protocol_versions(&[&rustls::version::TLS13])
                .expect("building rustls server config")
                .with_client_cert_verifier(Arc::new(
                    rustls::server::AllowAnyAuthenticatedClient::new(tls_root_store),
                ))
                .with_single_cert(tls_certs, tls_private_key)
                .context("building rustls client config")?;
            let listener = TcpListener::bind(address)
                .with_context(|| format!("Tcp binding to {:?}", address))?;
            eprintln!("Waiting for connection on {address:?}");
            let (root_conn, _) = listener.accept().context("Accepting connection")?;
            root_conn.set_nodelay(true)?;
            let tls_root_conn = rustls::ServerConnection::new(Arc::new(tls_config))
                .context("rustls::ServerConnection::new")?;
            let mut root_conn = BufStream::new(PartyEither::prover_new(
                e,
                rustls::StreamOwned::new(tls_root_conn, root_conn),
            ));
            let runner_version = {
                let mut buf = [0; 8];
                root_conn.read_exact(&mut buf)?;
                u64::from_le_bytes(buf)
            };
            eyre::ensure!(
                runner_version == MAC_N_CHEESE_RUNNER_VERSION,
                "Verifier has version {runner_version}. Expected {MAC_N_CHEESE_RUNNER_VERSION}"
            );
            let num_connections = {
                let mut buf = [0; 8];
                root_conn.read_exact(&mut buf)?;
                usize::try_from(u64::from_le_bytes(buf))?
            };
            let keys = {
                let mut base_key = [0; 32];
                root_conn.read_exact(&mut base_key)?;
                Keys::from_base_key(&base_key)
            };
            let mut unsorted_connections = Vec::with_capacity(num_connections);
            for _ in 0..num_connections {
                let c = listener.accept()?.0;
                c.set_nodelay(true)?;
                unsorted_connections.push(c);
            }
            let mut sorted_connections: Vec<Option<TcpStream>> = Vec::new();
            sorted_connections.resize_with(num_connections, || None);
            for mut c in unsorted_connections.into_iter() {
                let mut token = [0; 16];
                c.read_exact(&mut token)?;
                let idx = keys.decode_connection_index_token(token.into(), num_connections)?;
                eyre::ensure!(
                    sorted_connections[idx].is_none(),
                    "Duplicate connection with index {idx}"
                );
                sorted_connections[idx] = Some(c);
            }
            let mut connections = Vec::with_capacity(num_connections);
            for (i, c) in sorted_connections.into_iter().enumerate() {
                if let Some(c) = c {
                    connections.push(c);
                } else {
                    // We panic here since this situation shouldn't ever occur.
                    // We've put every connection into a slot with no duplicates.
                    panic!("Connection {i} is missing");
                }
            }
            root_conn.flush()?;
            (
                keys,
                TlsConnection {
                    inner: root_conn,
                    needs_flush_on_read: false,
                },
                connections,
            )
        }
        WhichParty::Verifier(e) => {
            let tls_config = rustls::ClientConfig::builder()
                .with_cipher_suites(&[rustls::cipher_suite::TLS13_AES_128_GCM_SHA256])
                .with_safe_default_kx_groups()
                .with_protocol_versions(&[&rustls::version::TLS13])
                .expect("building rustls ClientConfig")
                .with_root_certificates(tls_root_store)
                .with_client_auth_cert(tls_certs, tls_private_key)
                .context("building rustls client config")?;
            let tls_root_conn = rustls::ClientConnection::new(
                Arc::new(tls_config),
                PURPORTED_TLS_HOST_NAME.try_into().unwrap(),
            )
            .context("setting up tls client connection")?;
            // TODO: configurable tcp connection timeouts
            let root_conn = loop {
                eprintln!("Connecting to {address:?}");
                match TcpStream::connect_timeout(&address, Duration::from_secs(2)) {
                    Ok(c) => break c,
                    Err(e) => {
                        eprintln!(
                            "Failed to connect to {:?} due to {}. Sleeping then trying again.",
                            address, e
                        );
                        std::thread::sleep(Duration::from_millis(500));
                    }
                }
            };
            eprintln!("Connected to prover!");
            root_conn.set_nodelay(true)?;
            let mut root_conn = BufStream::with_capacities(
                BUF_SIZE,
                BUF_SIZE,
                PartyEither::verifier_new(e, rustls::StreamOwned::new(tls_root_conn, root_conn)),
            );
            root_conn.write_all(&MAC_N_CHEESE_RUNNER_VERSION.to_le_bytes())?;
            let num_connections = num_connections.verifier_into(e);
            root_conn.write_all(&(num_connections as u64).to_le_bytes())?;
            let mut base_key = [0; 32];
            rand::rngs::OsRng::default().fill_bytes(&mut base_key);
            root_conn.write_all(&base_key)?;
            root_conn.flush()?;
            let keys = Keys::from_base_key(&base_key);
            let mut connections = Vec::with_capacity(num_connections);
            for _ in 0..num_connections {
                let c = TcpStream::connect(address)?;
                c.set_nodelay(true)?;
                connections.push(c);
            }
            for (i, c) in connections.iter_mut().enumerate() {
                c.write_all(&keys.produce_connection_index_token(i).as_array())?;
                c.flush()?;
            }
            root_conn.flush()?;
            (
                keys,
                TlsConnection {
                    inner: root_conn,
                    needs_flush_on_read: false,
                },
                connections,
            )
        }
    })
}
