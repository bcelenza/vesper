use async_trait::async_trait;
use redbpf::Error;

pub mod connection;
pub mod network;

#[derive(Debug, Clone)]
pub struct ListenerError;

#[async_trait]
pub trait Listener {
    type Config;

    fn attach(&mut self, config: Self::Config) -> Result<(), Error>;
    async fn listen(&mut self) -> Result<(), ListenerError>;
}