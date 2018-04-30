use failure::Error;
use futures::stream::Stream;
use futures::{Async, Poll};
use pnetlink::socket::NetlinkProtocol;
use pnetlink::packet::route::RtMsgPacket;
use pnetlink::tokio::{NetlinkSocket, NetlinkCodec};
use tokio_core::reactor::Handle;
use tokio_io::{AsyncRead, codec::Framed};
use std::io;

pub struct RouteListener {
    inner: Framed<NetlinkSocket, NetlinkCodec>,
}

impl RouteListener {
    pub fn bind(handle: &Handle) -> io::Result<Self> {
        let sock = NetlinkSocket::bind(NetlinkProtocol::Route, 0, handle)?;

        Ok(RouteListener {
            inner: AsyncRead::framed(sock, NetlinkCodec {});
        })
    }
}

impl Stream for RouteListener {
    type Item = ();
    type Error = Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        match self.inner.poll() {
            Ok(Async::Ready(Some(packet)))
        }
    }
}