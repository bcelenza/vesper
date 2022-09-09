use std::{os::unix::prelude::FromRawFd, io::{Read, ErrorKind}};

use async_trait::async_trait;
use dns_parser::Packet;
use mio::{Poll, Events, net::UnixStream, Token, Interest};
use redbpf::{Error, load::{Loaded, Loader, LoaderError}};
use tracing::{error, info};

use super::{Listener, ListenerError};

pub struct NetworkListener {
    _loaded: Loaded,
    _fds: Vec<i32>,
}
pub struct NetworkConfig {
    pub interface: String,
}

#[async_trait]
impl Listener for NetworkListener {
    type Config = NetworkConfig;

    fn new() -> Result<NetworkListener, LoaderError> {
        let loaded = Loader::load(bytecode())?;
        Ok(NetworkListener {
            _loaded: loaded,
            _fds: Vec::new(),
        })
    }

    fn attach(&mut self, config: NetworkConfig) -> Result<(), Error> {
        let mut fds: Vec<i32> = Vec::new();
        for filter in self._loaded.socket_filters_mut() {
            let fd = filter.attach_socket_filter(&config.interface)?;
            fds.push(fd);
        }
        self._fds = fds;

        Ok(())
    }

    async fn listen(&self) -> Result<(), ListenerError> {
        let mut stream = unsafe { UnixStream::from_raw_fd(self._fds[0]) };
        let mut poll = match Poll::new() {
            Ok(poll) => poll,
            Err(_) => return Err(ListenerError),
        };
        let mut events = Events::with_capacity(1024);

        if poll.registry().register(&mut stream, Token(0), Interest::READABLE).is_err() {
            return Err(ListenerError)
        }


        loop {
            if let Err(e) = poll.poll(&mut events, None) {
                if e.kind() == ErrorKind::Interrupted {
                    return Ok(());
                } else {
                    error!("Could not poll for events: {}", e);
                    continue;
                }
            }

            for _ in &events {
                let mut buffer: Vec<u8> = Vec::with_capacity(64 * 1024);
                stream.read_to_end(&mut buffer);

                match Packet::parse(&buffer[42..]) {
                    Ok(packet) => info!("DNS packet: {:?}", packet),
                    Err(e) => error!("Could not parse DNS packet: {}", e)
                }
            }
        }
    }
}

fn bytecode() -> &'static [u8] {
    include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/target/bpf/programs/network/network.elf"
    ))
}