//! RustDesk wire fields used by the pinned direct desktop transport.

#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct Packet {
    #[prost(oneof = "body::Body", tags = "3,4,5,6,7,8,9,10,11,15,16,19,28")]
    pub body: Option<body::Body>,
}
pub(super) mod body {
    #[derive(Clone, PartialEq, prost::Oneof)]
    pub enum Body {
        #[prost(message, tag = "3")]
        Signed(super::SignedIdentity),
        #[prost(message, tag = "4")]
        Exchange(super::Exchange),
        #[prost(message, tag = "5")]
        Delay(super::Delay),
        #[prost(message, tag = "6")]
        Video(super::Video),
        #[prost(message, tag = "7")]
        Login(super::Login),
        #[prost(message, tag = "8")]
        Accepted(super::Accepted),
        #[prost(message, tag = "9")]
        Challenge(super::Challenge),
        #[prost(message, tag = "10")]
        Mouse(super::Mouse),
        #[prost(message, tag = "15")]
        Key(super::Key),
        #[prost(message, tag = "16")]
        Clipboard(super::Clipboard),
        #[prost(message, tag = "28")]
        Clipboards(super::Clipboards),
        #[prost(message, tag = "11")]
        Audio(super::AudioFrame),
        #[prost(message, tag = "19")]
        Misc(super::Misc),
    }
}
#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct Clipboard {
    #[prost(bool, tag = "1")]
    pub compress: bool,
    #[prost(bytes = "vec", tag = "2")]
    pub content: Vec<u8>,
    #[prost(int32, tag = "5")]
    pub format: i32,
}
#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct Clipboards {
    #[prost(message, repeated, tag = "1")]
    pub clipboards: Vec<Clipboard>,
}
#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct SignedIdentity {
    #[prost(bytes = "vec", tag = "1")]
    pub id: Vec<u8>,
}
#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct Identity {
    #[prost(string, tag = "1")]
    pub id: String,
    #[prost(bytes = "vec", tag = "2")]
    pub key: Vec<u8>,
    #[prost(uint32, tag = "4")]
    pub version: u32,
}
#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct Exchange {
    #[prost(bytes = "vec", tag = "1")]
    pub asymmetric_value: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub symmetric_value: Vec<u8>,
    #[prost(uint32, tag = "3")]
    pub version: u32,
}
#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct Challenge {
    #[prost(string, tag = "1")]
    pub salt: String,
    #[prost(string, tag = "2")]
    pub challenge: String,
}
#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct Login {
    #[prost(string, tag = "1")]
    pub username: String,
    #[prost(bytes = "vec", tag = "2")]
    pub password: Vec<u8>,
    #[prost(string, tag = "4")]
    pub my_id: String,
    #[prost(string, tag = "5")]
    pub my_name: String,
    #[prost(message, optional, tag = "6")]
    pub options: Option<Options>,
    #[prost(bool, tag = "9")]
    pub video_ack_required: bool,
    #[prost(uint64, tag = "10")]
    pub session_id: u64,
    #[prost(string, tag = "11")]
    pub version: String,
    #[prost(string, tag = "13")]
    pub platform: String,
}
#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct Options {
    #[prost(int32, tag = "1")]
    pub quality: i32,
    #[prost(int32, tag = "7")]
    pub disable_audio: i32,
    #[prost(int32, tag = "8")]
    pub disable_clipboard: i32,
    #[prost(int32, tag = "9")]
    pub enable_file_transfer: i32,
    #[prost(message, optional, tag = "10")]
    pub decoding: Option<Decoding>,
    #[prost(int32, tag = "11")]
    pub fps: i32,
    #[prost(int32, tag = "12")]
    pub disable_keyboard: i32,
    #[prost(int32, tag = "17")]
    pub disable_camera: i32,
}
#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct Decoding {
    #[prost(int32, tag = "1")]
    pub vp9: i32,
    #[prost(int32, tag = "2")]
    pub h264: i32,
    #[prost(int32, tag = "3")]
    pub h265: i32,
    #[prost(int32, tag = "5")]
    pub vp8: i32,
    #[prost(int32, tag = "6")]
    pub av1: i32,
    #[prost(int32, tag = "4")]
    pub prefer: i32,
}
#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct Accepted {
    #[prost(oneof = "accepted::Result", tags = "1,2")]
    pub result: Option<accepted::Result>,
}
pub(super) mod accepted {
    #[derive(Clone, PartialEq, prost::Oneof)]
    pub enum Result {
        #[prost(string, tag = "1")]
        Error(String),
        #[prost(message, tag = "2")]
        Peer(super::Peer),
    }
}
#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct Peer {
    #[prost(message, repeated, tag = "4")]
    pub displays: Vec<Display>,
    #[prost(int32, tag = "5")]
    pub current_display: i32,
}
#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct Display {
    #[prost(sint32, tag = "1")]
    pub x: i32,
    #[prost(sint32, tag = "2")]
    pub y: i32,
    #[prost(int32, tag = "3")]
    pub width: i32,
    #[prost(int32, tag = "4")]
    pub height: i32,
}
#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct Video {
    #[prost(oneof = "video::Format", tags = "6,10,11,12,13")]
    pub format: Option<video::Format>,
    #[prost(int32, tag = "14")]
    pub display: i32,
}
pub(super) mod video {
    #[derive(Clone, PartialEq, prost::Oneof)]
    pub enum Format {
        #[prost(message, tag = "6")]
        Vp9(super::Frames),
        #[prost(message, tag = "10")]
        H264(super::Frames),
        #[prost(message, tag = "12")]
        Vp8(super::Frames),
        #[prost(message, tag = "11")]
        H265(super::Frames),
        #[prost(message, tag = "13")]
        Av1(super::Frames),
    }
}
#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct Frames {
    #[prost(message, repeated, tag = "1")]
    pub frames: Vec<Frame>,
}
#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct Frame {
    #[prost(bytes = "vec", tag = "1")]
    pub data: Vec<u8>,
    #[prost(bool, tag = "2")]
    pub key: bool,
}
#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct Delay {
    #[prost(int64, tag = "1")]
    pub time: i64,
    #[prost(bool, tag = "2")]
    pub from_client: bool,
}
#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct Mouse {
    #[prost(int32, tag = "1")]
    pub mask: i32,
    #[prost(sint32, tag = "2")]
    pub x: i32,
    #[prost(sint32, tag = "3")]
    pub y: i32,
    #[prost(int32, repeated, tag = "4")]
    pub modifiers: Vec<i32>,
}
#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct Key {
    #[prost(bool, tag = "1")]
    pub down: bool,
    #[prost(oneof = "key::Value", tags = "3,4")]
    pub value: Option<key::Value>,
    #[prost(int32, repeated, tag = "8")]
    pub modifiers: Vec<i32>,
}
pub(super) mod key {
    #[derive(Clone, PartialEq, prost::Oneof)]
    pub enum Value {
        #[prost(int32, tag = "3")]
        Control(i32),
        #[prost(uint32, tag = "4")]
        Character(u32),
    }
}

#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct AudioFrame {
    #[prost(bytes = "vec", tag = "1")]
    pub data: Vec<u8>,
}
#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct AudioFormat {
    #[prost(uint32, tag = "1")]
    pub sample_rate: u32,
    #[prost(uint32, tag = "2")]
    pub channels: u32,
}
#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct Permission {
    #[prost(int32, tag = "1")]
    pub permission: i32,
    #[prost(bool, tag = "2")]
    pub enabled: bool,
}
#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct Misc {
    #[prost(oneof = "misc::Value", tags = "6,7,8,9")]
    pub value: Option<misc::Value>,
}
pub(super) mod misc {
    #[derive(Clone, PartialEq, prost::Oneof)]
    pub enum Value {
        #[prost(message, tag = "6")]
        Permission(super::Permission),
        #[prost(message, tag = "7")]
        Options(super::Options),
        #[prost(message, tag = "8")]
        Audio(super::AudioFormat),
        #[prost(string, tag = "9")]
        Closed(String),
    }
}
