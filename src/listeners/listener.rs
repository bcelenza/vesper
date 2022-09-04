use async_trait::async_trait;

use redbpf::{load::LoaderError, Error};

#[async_trait]
pub trait Listener {
    type Config;

    fn new() -> Result<Self, LoaderError> where Self: std::marker::Sized;
    fn attach(&mut self, config: Self::Config) -> Result<(), Error>;
    async fn listen(&mut self);
}
