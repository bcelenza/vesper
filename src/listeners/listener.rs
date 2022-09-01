use async_trait::async_trait;
use std::error::Error;

use redbpf::load::LoaderError;

#[async_trait]
pub trait Listener {
    type Config;

    fn new() -> Result<Self, LoaderError> where Self: std::marker::Sized;
    fn attach(&mut self, config: Self::Config) -> Result<(), Box<dyn Error>>;
    async fn listen(&mut self);
}
