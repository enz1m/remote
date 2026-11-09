#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct Packet {
    #[prost(oneof = "body::Body", tags = "8,11,18,19,25")]
    pub body: Option<body::Body>,
}
pub(super) mod body {
    #[derive(Clone, PartialEq, prost::Oneof)]
    pub enum Body {
        #[prost(message, tag = "8")]
        Punch(super::Punch),
        #[prost(message, tag = "11")]
        Punched(super::Punched),
        #[prost(message, tag = "18")]
        Request(super::Request),
        #[prost(message, tag = "19")]
        Relay(super::Relay),
        #[prost(message, tag = "25")]
        KeyExchange(super::KeyExchange),
    }
}
#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct Punch {
    #[prost(string, tag = "1")]
    pub id: String,
    #[prost(int32, tag = "2")]
    pub nat_type: i32,
    #[prost(string, tag = "3")]
    pub key: String,
    #[prost(string, tag = "6")]
    pub version: String,
    #[prost(bool, tag = "8")]
    pub force_relay: bool,
}
#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct Punched {
    #[prost(bytes = "vec", tag = "1")]
    pub address: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub key: Vec<u8>,
    #[prost(int32, tag = "3")]
    pub failure: i32,
    #[prost(string, tag = "4")]
    pub relay: String,
    #[prost(string, tag = "7")]
    pub reason: String,
}
#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct Request {
    #[prost(string, tag = "1")]
    pub id: String,
    #[prost(string, tag = "2")]
    pub uuid: String,
    #[prost(string, tag = "4")]
    pub relay: String,
    #[prost(bool, tag = "5")]
    pub secure: bool,
    #[prost(string, tag = "6")]
    pub key: String,
}
#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct Relay {
    #[prost(string, tag = "2")]
    pub uuid: String,
    #[prost(string, tag = "3")]
    pub server: String,
    #[prost(bytes = "vec", tag = "5")]
    pub key: Vec<u8>,
    #[prost(string, tag = "6")]
    pub refusal: String,
}
#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct KeyExchange {
    #[prost(bytes = "vec", repeated, tag = "1")]
    pub keys: Vec<Vec<u8>>,
}
