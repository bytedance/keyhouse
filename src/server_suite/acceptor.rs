use std::{
    convert::TryInto,
    io::{self, ErrorKind},
    mem::MaybeUninit,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    task::{Context, Poll},
    time::Duration,
};

use anyhow::Result;
use futures::Stream;
use hyper::server::accept::Accept;
use hyper::server::conn::{AddrIncoming, AddrStream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tonic::transport::server::Connected;

#[derive(Clone, Copy)]
pub enum ProxyMode {
    None,
    Accept,
    Require,
}

pub struct WrappedIncoming {
    inner: AddrIncoming,
    conn_count: Arc<AtomicU64>,
    proxy_mode: ProxyMode,
}

impl WrappedIncoming {
    pub fn new(
        addr: SocketAddr,
        nodelay: bool,
        keepalive: Option<Duration>,
        proxy_mode: ProxyMode,
    ) -> Result<Self> {
        let mut inner = AddrIncoming::bind(&addr)?;
        inner.set_nodelay(nodelay);
        inner.set_keepalive(keepalive);
        Ok(WrappedIncoming {
            inner,
            conn_count: Arc::new(AtomicU64::new(0)),
            proxy_mode,
        })
    }

    pub fn get_conn_count(&self) -> Arc<AtomicU64> {
        self.conn_count.clone()
    }
}

impl Stream for WrappedIncoming {
    type Item = Result<WrappedStream, std::io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match Pin::new(&mut self.inner).poll_accept(cx) {
            Poll::Ready(Some(Ok(stream))) => {
                self.conn_count.fetch_add(1, Ordering::SeqCst);
                Poll::Ready(Some(Ok(WrappedStream {
                    inner: Box::pin(stream),
                    conn_count: self.conn_count.clone(),
                    proxy_header: [0u8; PROXY_PACKET_HEADER_LEN + PROXY_PACKET_MAX_PROXY_ADDR_SIZE], // maybe uninit?
                    proxy_header_index: 0,
                    proxy_header_rewrite_index: 0,
                    proxy_header_target: if matches!(self.proxy_mode, ProxyMode::None) {
                        0
                    } else {
                        PROXY_PACKET_HEADER_LEN + PROXY_PACKET_MAX_PROXY_ADDR_SIZE
                    },
                    discovered_remote: None,
                    proxy_mode: self.proxy_mode,
                })))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

const PROXY_PACKET_HEADER_LEN: usize = 16;
const PROXY_PACKET_MAX_PROXY_ADDR_SIZE: usize = 36;
const PROXY_SIGNATURE: [u8; 12] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];

pub struct WrappedStream {
    inner: Pin<Box<AddrStream>>,
    conn_count: Arc<AtomicU64>,
    proxy_header: [u8; PROXY_PACKET_HEADER_LEN + PROXY_PACKET_MAX_PROXY_ADDR_SIZE],
    proxy_header_index: usize,
    proxy_header_rewrite_index: usize,
    proxy_header_target: usize,
    discovered_remote: Option<SocketAddr>,
    proxy_mode: ProxyMode,
}

impl Connected for WrappedStream {
    type ConnectInfo = Option<SocketAddr>;
    fn connect_info(&self) -> Self::ConnectInfo {
        Some(
            self.discovered_remote
                .unwrap_or_else(|| self.inner.remote_addr()),
        )
    }
}

impl AsyncRead for WrappedStream {
    #[inline]
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !matches!(self.proxy_mode, ProxyMode::None) && self.proxy_header_target > 0 {
            let index = self.proxy_header_index;
            let target = self.proxy_header_target;
            let mut proxy_header =
                [MaybeUninit::uninit(); PROXY_PACKET_HEADER_LEN + PROXY_PACKET_MAX_PROXY_ADDR_SIZE];
            let mut read_buf = ReadBuf::uninit(&mut proxy_header[index..target]);
            match self.inner.as_mut().poll_read(cx, &mut read_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {
                    (&mut self.proxy_header[index..index + read_buf.filled().len()])
                        .copy_from_slice(read_buf.filled());

                    self.proxy_header_index += read_buf.filled().len();

                    let signature_end = self.proxy_header_index.min(12);
                    if self.proxy_header[0..signature_end] != PROXY_SIGNATURE[0..signature_end] {
                        // re-emit everything / not a proxy connection
                        if matches!(self.proxy_mode, ProxyMode::Require) {
                            debug!("attempted non-proxy connection");
                            return Poll::Ready(Err(io::Error::new(
                                ErrorKind::InvalidData,
                                anyhow!("invalid proxy protocol version"),
                            )));
                        }
                        self.proxy_header_target = 0;
                    } else if self.proxy_header_index >= PROXY_PACKET_HEADER_LEN {
                        let version = (self.proxy_header[12] & 0xf0) >> 4;
                        if version != 2 {
                            debug!("invalid proxy protocol version: {}", version);
                            return Poll::Ready(Err(io::Error::new(
                                ErrorKind::InvalidData,
                                anyhow!("invalid proxy protocol version"),
                            )));
                        }
                        let command = self.proxy_header[12] & 0x0f;
                        if command > 0x01 {
                            // 0 and 1 are only valid values
                            debug!("invalid proxy protocol command: {}", command);
                            return Poll::Ready(Err(io::Error::new(
                                ErrorKind::InvalidData,
                                anyhow!("invalid proxy protocol command"),
                            )));
                        }
                        let is_proxy = command == 0x01;
                        let family = (self.proxy_header[13] & 0xf0) >> 4;
                        let protocol = self.proxy_header[13] & 0x0f;
                        if protocol != 0x01 {
                            // tcp/stream
                            debug!("invalid proxy protocol protocol target: {}", protocol);
                            return Poll::Ready(Err(io::Error::new(
                                ErrorKind::InvalidData,
                                anyhow!("invalid proxy protocol protocol target"),
                            )));
                        }
                        let is_ipv4 = family == 0x01;
                        let is_ipv6 = family == 0x02;
                        if !is_ipv4 && !is_ipv6 {
                            debug!("invalid proxy address family: {}", family);
                            return Poll::Ready(Err(io::Error::new(
                                ErrorKind::InvalidData,
                                anyhow!("invalid proxy address family"),
                            )));
                        }

                        let len =
                            u16::from_be_bytes([self.proxy_header[14], self.proxy_header[15]]);
                        let target_len = if !is_proxy {
                            0
                        } else if is_ipv4 {
                            12
                        } else {
                            // is_ipv6
                            36
                        };
                        if len != target_len {
                            debug!("invalid proxy address length: {}", target_len);
                            return Poll::Ready(Err(io::Error::new(
                                ErrorKind::InvalidData,
                                anyhow!("invalid proxy address length"),
                            )));
                        }
                        self.proxy_header_target = PROXY_PACKET_HEADER_LEN + len as usize;
                        if self.proxy_header_index as usize >= self.proxy_header_target {
                            if is_ipv4 {
                                let src_addr = &self.proxy_header
                                    [PROXY_PACKET_HEADER_LEN..PROXY_PACKET_HEADER_LEN + 4];
                                // let dest_addr = &self.proxy_header[PROXY_PACKET_HEADER_LEN + 4..PROXY_PACKET_HEADER_LEN + 8];
                                let src_port = &self.proxy_header
                                    [PROXY_PACKET_HEADER_LEN + 8..PROXY_PACKET_HEADER_LEN + 10];
                                let src_port = u16::from_be_bytes([src_port[0], src_port[1]]);
                                // let dest_port = &self.proxy_header[PROXY_PACKET_HEADER_LEN + 10..PROXY_PACKET_HEADER_LEN + 12];

                                self.discovered_remote = Some(SocketAddr::new(
                                    IpAddr::V4(Ipv4Addr::new(
                                        src_addr[0],
                                        src_addr[1],
                                        src_addr[2],
                                        src_addr[3],
                                    )),
                                    src_port,
                                ));
                            } else if is_ipv6 {
                                // ipv6
                                let src_addr = &self.proxy_header
                                    [PROXY_PACKET_HEADER_LEN..PROXY_PACKET_HEADER_LEN + 16];
                                // let dest_addr = &self.proxy_header[PROXY_PACKET_HEADER_LEN + 16..PROXY_PACKET_HEADER_LEN + 32];
                                let src_port = &self.proxy_header
                                    [PROXY_PACKET_HEADER_LEN + 32..PROXY_PACKET_HEADER_LEN + 34];
                                let src_port = u16::from_be_bytes([src_port[0], src_port[1]]);
                                // let dest_port = &self.proxy_header[PROXY_PACKET_HEADER_LEN + 34..PROXY_PACKET_HEADER_LEN + 36];
                                let src_addr: [u8; 16] =
                                    src_addr.try_into().expect("corrupt array length");
                                self.discovered_remote = Some(SocketAddr::new(
                                    IpAddr::V6(Ipv6Addr::from(src_addr)),
                                    src_port,
                                ));
                            } else if is_proxy {
                            }
                            self.proxy_header_rewrite_index = self.proxy_header_target;
                            self.proxy_header_target = 0;
                        }
                    }
                }
            }
        }
        if !matches!(self.as_ref().proxy_mode, ProxyMode::None)
            && self.proxy_header_target == 0
            && self.proxy_header_rewrite_index < self.proxy_header_index
        {
            let len = self.proxy_header_index - self.proxy_header_rewrite_index;
            let actual_len = if len < buf.remaining() {
                len
            } else {
                buf.remaining()
            };
            buf.put_slice(
                &self.proxy_header
                    [self.proxy_header_rewrite_index..self.proxy_header_rewrite_index + actual_len],
            );
            self.proxy_header_rewrite_index += actual_len;
            if buf.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }
        }

        self.inner.as_mut().poll_read(cx, buf)
    }
}

impl AsyncWrite for WrappedStream {
    #[inline]
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.inner.as_mut().poll_write(cx, buf)
    }

    #[inline]
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        self.inner.as_mut().poll_write_vectored(cx, bufs)
    }

    #[inline]
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.inner.as_mut().poll_flush(cx)
    }

    #[inline]
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.inner.as_mut().poll_shutdown(cx)
    }

    #[inline]
    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

impl Drop for WrappedStream {
    fn drop(&mut self) {
        self.conn_count.fetch_sub(1, Ordering::SeqCst);
    }
}
