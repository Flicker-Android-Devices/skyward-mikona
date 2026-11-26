//! Wire protocol shared with the sandboxed `aera-browser-worker` process.

use anyhow::{ensure, Result};

pub const MAGIC: u32 = 0x4152_5032;
pub const WIDTH: u32 = 1080;
pub const HEIGHT: u32 = 2100;
pub const VIEW_WIDTH: i32 = 360;
pub const VIEW_HEIGHT: i32 = 700;
pub const FRAME_BYTES: usize = (WIDTH * HEIGHT * 4) as usize;
pub const FRAME_SLOTS: usize = 2;
pub const SHARED_BYTES: usize = FRAME_BYTES * FRAME_SLOTS;
pub const TEXT_CAP: usize = 2048;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Kind {
    Open = 1,
    Back = 2,
    Forward = 3,
    Reload = 4,
    Stop = 5,
    TouchDown = 6,
    TouchMove = 7,
    TouchUp = 8,
    Key = 9,
    Ack = 10,
    Close = 11,
    SetZoom = 12,
    DownloadCancel = 13,
    SetCookiePolicy = 14,
    ClearBrowsingData = 15,

    Frame = 32,
    Status = 33,
    Error = 34,
    KeyboardShow = 35,
    KeyboardHide = 36,
    DownloadStarted = 37,
    DownloadProgress = 38,
    DownloadFinished = 39,
    DownloadFailed = 40,
    DownloadCancelled = 41,
    BrowsingDataCleared = 42,
    BrowsingDataFailed = 43,
}

impl Kind {
    pub fn from_u32(v: u32) -> Option<Self> {
        Some(match v {
            1 => Self::Open,
            2 => Self::Back,
            3 => Self::Forward,
            4 => Self::Reload,
            5 => Self::Stop,
            6 => Self::TouchDown,
            7 => Self::TouchMove,
            8 => Self::TouchUp,
            9 => Self::Key,
            10 => Self::Ack,
            11 => Self::Close,
            12 => Self::SetZoom,
            13 => Self::DownloadCancel,
            14 => Self::SetCookiePolicy,
            15 => Self::ClearBrowsingData,
            32 => Self::Frame,
            33 => Self::Status,
            34 => Self::Error,
            35 => Self::KeyboardShow,
            36 => Self::KeyboardHide,
            37 => Self::DownloadStarted,
            38 => Self::DownloadProgress,
            39 => Self::DownloadFinished,
            40 => Self::DownloadFailed,
            41 => Self::DownloadCancelled,
            42 => Self::BrowsingDataCleared,
            43 => Self::BrowsingDataFailed,
            _ => return None,
        })
    }
}

/// Fixed-size control/status packet transferred over `SOCK_SEQPACKET`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Message {
    pub magic: u32,
    pub kind: u32,
    pub sequence: u32,
    pub x: i32,
    pub y: i32,
    pub value: u32,
    pub text: [u8; TEXT_CAP],
}

const _: () = assert!(std::mem::size_of::<Message>() == 2072);

impl Message {
    pub fn new(kind: Kind) -> Self {
        Self { magic: MAGIC, kind: kind as u32, sequence: 0, x: 0, y: 0, value: 0, text: [0; TEXT_CAP] }
    }

    pub fn with_text(kind: Kind, text: &str) -> Result<Self> {
        let bytes = text.as_bytes();
        ensure!(bytes.len() < TEXT_CAP, "browser message text exceeds {} bytes", TEXT_CAP - 1);
        let mut msg = Self::new(kind);
        msg.text[..bytes.len()].copy_from_slice(bytes);
        Ok(msg)
    }

    pub fn kind(&self) -> Option<Kind> {
        (self.magic == MAGIC).then(|| Kind::from_u32(self.kind)).flatten()
    }

    pub fn text_str(&self) -> &str {
        let len = self.text.iter().position(|&b| b == 0).unwrap_or(self.text.len());
        std::str::from_utf8(&self.text[..len]).unwrap_or_default()
    }

    pub fn as_bytes(&self) -> &[u8] {
        // SAFETY: Message is a plain `#[repr(C)]` struct of integers and bytes with no padding.
        unsafe { std::slice::from_raw_parts((self as *const Self).cast::<u8>(), std::mem::size_of::<Self>()) }
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != std::mem::size_of::<Self>() {
            return None;
        }
        let mut msg = Self::new(Kind::Status);
        // SAFETY: `bytes.len() == size_of::<Self>()` and all bit patterns are valid for `Message`.
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), (&mut msg as *mut Self).cast::<u8>(), std::mem::size_of::<Self>());
        }
        msg.text.contains(&0).then_some(msg).filter(|m| m.kind().is_some())
    }
}

/// Normalize a typed address to `http://`, `https://`, or built-in `aera://` URI.
pub fn normalize_address(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.len() > 2040 {
        return None;
    }
    if trimmed == "aera://start" || trimmed == "aera://test" {
        return Some(trimmed.to_string());
    }
    if trimmed.bytes().any(|b| b <= 32 || b == 127 || b == b'\\') {
        return None;
    }
    let with_scheme = if trimmed.contains("://") {
        trimmed.to_string()
    } else if trimmed.contains(':') {
        return None;
    } else {
        format!("https://{trimmed}")
    };
    let rest = with_scheme.strip_prefix("https://").or_else(|| with_scheme.strip_prefix("http://"))?;
    if with_scheme.len() >= TEXT_CAP {
        return None;
    }
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    Some(with_scheme)
}

/// Convert little-endian `WPE_PIXEL_FORMAT_ARGB8888` (`[B, G, R, A]`) into straight-alpha `[R, G, B, 255]`.
pub fn bgra_to_rgba(bgra: &[u8], rgba: &mut [u8]) {
    debug_assert_eq!(bgra.len(), rgba.len());
    let (src_chunks, _) = bgra.as_chunks::<4>();
    let (dst_chunks, _) = rgba.as_chunks_mut::<4>();
    for (src, dst) in src_chunks.iter().zip(dst_chunks.iter_mut()) {
        let v = u32::from_le_bytes(*src);
        let swizzled = (v & 0x0000_ff00) | ((v & 0x0000_00ff) << 16) | ((v >> 16) & 0x0000_00ff) | 0xff00_0000;
        *dst = swizzled.to_le_bytes();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_round_trip() {
        let mut msg = Message::with_text(Kind::Open, "https://example.com").unwrap();
        msg.sequence = 7;
        let back = Message::from_bytes(msg.as_bytes()).unwrap();
        assert_eq!(back.kind(), Some(Kind::Open));
        assert_eq!(back.sequence, 7);
        assert_eq!(back.text_str(), "https://example.com");
    }

    #[test]
    fn address_normalization_matches_worker_rules() {
        assert_eq!(normalize_address("example.com"), Some("https://example.com".into()));
        assert_eq!(normalize_address("http://localhost/a"), Some("http://localhost/a".into()));
        assert_eq!(normalize_address("aera://start"), Some("aera://start".into()));
        assert_eq!(normalize_address("javascript:alert(1)"), None);
        assert_eq!(normalize_address("file:///etc/passwd"), None);
        assert_eq!(normalize_address("https://user@example.com"), None);
    }

    #[test]
    fn bgra_swizzle_writes_opaque_rgba() {
        let bgra = [0x33, 0x22, 0x11, 0xaa, 0x99, 0x88, 0x77, 0xff];
        let mut rgba = [0u8; 8];
        bgra_to_rgba(&bgra, &mut rgba);
        assert_eq!(rgba, [0x11, 0x22, 0x33, 0xff, 0x77, 0x88, 0x99, 0xff]);
    }
}
