use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use openssl::ssl::{SslConnector, SslMethod, SslStream, SslVersion};

pub(super) enum Stream {
    Plain(TcpStream),
    Tls {
        stream: Arc<Mutex<SslStream<DeadlineSocket>>>,
        read_timeout: Arc<Mutex<Option<Duration>>>,
    },
}

pub(super) struct DeadlineSocket {
    tcp: TcpStream,
    deadline: Option<Instant>,
}

impl DeadlineSocket {
    fn remaining(&self) -> io::Result<Option<Duration>> {
        self.deadline
            .map(|deadline| {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "VNC TLS handshake timed out",
                    ))
                } else {
                    Ok(remaining)
                }
            })
            .transpose()
    }
}
impl Read for DeadlineSocket {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if let Some(remaining) = self.remaining()? {
            self.tcp.set_read_timeout(Some(remaining))?;
        }
        self.tcp.read(bytes)
    }
}
impl Write for DeadlineSocket {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if let Some(remaining) = self.remaining()? {
            self.tcp.set_write_timeout(Some(remaining))?;
        }
        self.tcp.write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.tcp.flush()
    }
}

impl Stream {
    pub(super) fn new(tcp: TcpStream) -> Self {
        Self::Plain(tcp)
    }
    pub(super) fn try_clone(&self) -> io::Result<Self> {
        Ok(match self {
            Self::Plain(tcp) => Self::Plain(tcp.try_clone()?),
            Self::Tls {
                stream,
                read_timeout,
            } => Self::Tls {
                stream: Arc::clone(stream),
                read_timeout: Arc::clone(read_timeout),
            },
        })
    }
    pub(super) fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        match self {
            Self::Plain(tcp) => tcp.set_read_timeout(timeout),
            Self::Tls { read_timeout, .. } => {
                *read_timeout.lock().unwrap_or_else(PoisonError::into_inner) = timeout;
                Ok(())
            }
        }
    }
    pub(super) fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        match self {
            Self::Plain(tcp) => tcp.set_write_timeout(timeout),
            Self::Tls { stream, .. } => stream
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .get_ref()
                .tcp
                .set_write_timeout(timeout),
        }
    }
    pub(super) fn enable_tls(&mut self, host: &str, deadline: Instant) -> Result<(), String> {
        let Self::Plain(tcp) = self else {
            return Err("VNC attempted to negotiate TLS twice".into());
        };
        let mut connector =
            SslConnector::builder(SslMethod::tls_client()).map_err(|_| "VNC TLS is unavailable")?;
        connector
            .set_min_proto_version(Some(SslVersion::TLS1_2))
            .map_err(|_| "VNC requires TLS 1.2 or newer")?;
        let mut stream = connector.build().connect(host.trim_matches(['[', ']']), DeadlineSocket {
            tcp: tcp.try_clone().map_err(|_| "VNC could not retain its TLS socket")?,
            deadline: Some(deadline),
        }).map_err(|_| "VNC TLS certificate or handshake could not be verified; use the certificate hostname and a trusted CA")?;
        stream.get_mut().deadline = None;
        *self = Self::Tls {
            stream: Arc::new(Mutex::new(stream)),
            read_timeout: Arc::new(Mutex::new(None)),
        };
        Ok(())
    }
}

impl Read for Stream {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Plain(tcp) => tcp.read(bytes),
            Self::Tls {
                stream,
                read_timeout,
            } => {
                let timeout = *read_timeout.lock().unwrap_or_else(PoisonError::into_inner);
                let start = Instant::now();
                loop {
                    let remaining = timeout.map(|timeout| timeout.saturating_sub(start.elapsed()));
                    if remaining.is_some_and(|remaining| remaining.is_zero()) {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "VNC read timed out",
                        ));
                    }
                    let result = {
                        let mut stream = stream.lock().unwrap_or_else(PoisonError::into_inner);
                        stream.get_ref().tcp.set_read_timeout(Some(
                            remaining
                                .unwrap_or(Duration::from_millis(20))
                                .min(Duration::from_millis(20)),
                        ))?;
                        stream.read(bytes)
                    };
                    match result {
                        Err(error)
                            if matches!(
                                error.kind(),
                                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                            ) =>
                        {
                            // TLS record state is shared; idle reads yield it so input can be written.
                            std::thread::sleep(Duration::from_millis(1));
                        }
                        result => return result,
                    }
                }
            }
        }
    }
}
impl Write for Stream {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        match self {
            Self::Plain(tcp) => tcp.write(bytes),
            Self::Tls { stream, .. } => stream
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .write(bytes),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Plain(tcp) => tcp.flush(),
            Self::Tls { stream, .. } => stream
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .flush(),
        }
    }
}
