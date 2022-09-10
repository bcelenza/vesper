use std::{fmt, time::SystemTime};

use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Error;

use self::dns::{QueryEvent, AnswerEvent};

pub mod dns;

#[derive(Debug)]
pub enum EventError<'a> {
    TranslationError(&'a str),
}

impl std::error::Error for EventError<'_> {}

impl fmt::Display for EventError<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug, Serialize)]
pub enum Event {
    DnsQuery(QueryEvent),
    DnsResponse(AnswerEvent)
}

impl Event {
    pub fn get_type(&self) -> String {
        match self {
            Self::DnsQuery(_) => String::from("DnsQuery"),
            Self::DnsResponse(_) => String::from("DnsResponse"),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct SocketAddress {
    ip: String,
    port: u16,
}

#[derive(Debug, Serialize)]
struct LogEvent {
    time: String,
    r#type: String,
    event: Event,
}

pub struct Logger;

impl Logger {
    pub fn log_event(event: Event) -> Result<(), Error> {
        let now: DateTime<Utc> = SystemTime::now().into();
        let log_event = LogEvent {
            time: now.to_rfc3339(),
            r#type: event.get_type(),
            event,
        };
        println!("{}", serde_json::to_string(&log_event)?);
        Ok(())
    }
}