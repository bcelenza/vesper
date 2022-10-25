use std::{os::unix::prelude::FromRawFd, io::{Read, ErrorKind, Error}};

use async_trait::async_trait;
use etherparse::{SlicedPacket, InternetSlice};
use mio::{Poll, Events, net::UnixStream, Token, Interest};
use redbpf::{Error as BpfError, load::{Loaded, Loader, LoaderError}, HashMap};
use tracing::{debug, error, info};

use probes::{network::{PacketMetadata, TrafficClass, PacketMetadataKey}, common::{SocketPair, IPv6Address, SocketAddress}};

use crate::{processors::{dns::DnsProcessor, PacketProcessor, tls::TlsProcessor}};

use super::{Listener, ListenerError};

/// Given an expression that returns a Result type, return the value or log the error
/// and continue the loop.
macro_rules! continue_on_err {
    ($res:expr) => {
        match $res {
            Ok(val) => val,
            Err(e) => {
                error!("Encountered error: {:?}. Continuing.", e);
                continue;
            }
        }
    };
}

pub struct ConnectionListener {
    _loaded: Loaded,
}

pub struct ConnectionConfig;

impl ConnectionListener {
    pub fn new() -> Result<ConnectionListener, LoaderError> {
        let loaded = Loader::load(bytecode())?;
        Ok(ConnectionListener {
            _loaded: loaded,
        })
    }
}

#[async_trait]
impl Listener for ConnectionListener {
    type Config = ConnectionConfig;

    fn attach(&mut self, config: ConnectionConfig) -> Result<(), BpfError> {
        for tracepoint in self._loaded.tracepoints_mut() {
            tracepoint.attach_trace_point("syscalls", "sys_enter_connect").expect(format!("could not attatch tracepoint to {}", tracepoint.name()).as_str());
        }

        Ok(())
    }

    async fn listen(&mut self) -> Result<(), ListenerError> {
        loop {}
    }
}

fn bytecode() -> &'static [u8] {
    include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/target/bpf/programs/connection/connection.elf"
    ))
}