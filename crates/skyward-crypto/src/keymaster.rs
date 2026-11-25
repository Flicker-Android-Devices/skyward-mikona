//! Talking to the older HIDL key service (`android.hardware.keymaster@4.0`
//! and `4.1`) on phones without AIDL KeyMint.

#![cfg_attr(not(target_os = "android"), allow(dead_code))]

use anyhow::{bail, Context, Result};
#[cfg(target_os = "android")]
use skyward_binder::hidl;
use skyward_binder::hidl::{Answer, Message};

use crate::token::Token;

/// What the phone says about its key hardware.
pub struct Hardware {
    pub version: i32,
    pub security_level: i32,
    pub name: String,
    pub author: String,
}

/// First HIDL interface name tried (`4.1` extends `4.0` while keeping all `4.0`
/// transaction codes under `@4.0::IKeymasterDevice`).
pub const HARDWARE_SERVICE_4_1: &str = "android.hardware.keymaster@4.1::IKeymasterDevice";
pub const HARDWARE_SERVICE: &str = "android.hardware.keymaster@4.0::IKeymasterDevice";
const INSTANCE: &str = "default";

const GET_HARDWARE_INFO: u32 = 1;
const GET_KEY_CHARACTERISTICS: u32 = 9;
const EXPORT_KEY: u32 = 10;
const UPGRADE_KEY: u32 = 12;
const BEGIN: u32 = 16;
const UPDATE: u32 = 17;
const FINISH: u32 = 18;
const ABORT: u32 = 19;

const KEY_FORMAT_RAW: u32 = 3;
const ERROR_OK: i32 = 0;
const KEY_REQUIRES_UPGRADE: i32 = -62;

const PURPOSE_DECRYPT: u32 = 1;
const BLOCK_MODE_GCM: u64 = 32;
const PADDING_NONE: u64 = 1;

const TAG_BLOCK_MODE: i32 = 536_870_916;
const TAG_PADDING: i32 = 536_870_918;
const TAG_MAC_LENGTH: i32 = 805_307_371;
const TAG_APPLICATION_ID: i32 = -1_879_047_591;
const TAG_NONCE: i32 = -1_879_047_191;

const TAG_KIND: i32 = -268_435_456;
const KIND_ULONG: i32 = 1_342_177_280;
const KIND_ULONG_REP: i32 = -1_610_612_736;
const KIND_DATE: i32 = 1_610_612_736;
const KIND_BYTES: i32 = -1_879_048_192;
const KIND_BIGNUM: i32 = -2_147_483_648;

const NONCE_BYTES: usize = 12;
const PARAM_BYTES: usize = 32;
const CHARACTERISTICS_BYTES: usize = 32;
const AUTH_TOKEN_BYTES: usize = 56;
const VERIFICATION_TOKEN_BYTES: usize = 56;

/// Prefix Android's Keystore 2 compat layer prepends when persisting a key blob
/// from a Keymaster HAL (`\x00` for hardware keys, `\x01` for software keys).
const COMPAT_HW_PREFIX: &[u8] = b"pKMblob\0";
const COMPAT_SW_PREFIX: &[u8] = b"pKMblob\x01";

/// Strip Keystore 2's `km_compat` marker when present so the underlying
/// Keymaster HAL receives its raw key blob.
fn raw_blob(key_blob: &[u8]) -> Result<&[u8]> {
    if let Some(raw) = key_blob.strip_prefix(COMPAT_HW_PREFIX) {
        return Ok(raw);
    }
    if key_blob.starts_with(COMPAT_SW_PREFIX) {
        bail!("the key was wrapped in software, not by the phone's key hardware");
    }
    Ok(key_blob)
}

struct Param<'a> {
    tag: i32,
    scalar: u64,
    blob: &'a [u8],
}

impl<'a> Param<'a> {
    fn integer(tag: i32, value: u64) -> Self {
        Param { tag, scalar: value, blob: &[] }
    }

    fn bytes(tag: i32, blob: &'a [u8]) -> Self {
        Param { tag, scalar: 0, blob }
    }
}

#[derive(Debug)]
struct Rejected(i32);

impl std::fmt::Display for Rejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "keymaster returned error {}", self.0)
    }
}

impl std::error::Error for Rejected {}

fn check(error: i32, action: &str) -> Result<()> {
    if error == ERROR_OK {
        return Ok(());
    }
    Err(anyhow::Error::new(Rejected(error))).with_context(|| action.to_string())
}

fn is_upgrade_required(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| cause.downcast_ref::<Rejected>().is_some_and(|r| r.0 == KEY_REQUIRES_UPGRADE))
}

fn write_bytes_vec(msg: &mut Message, value: &[u8]) {
    let frame = msg.buffer(Message::vec_frame(value.len()).to_vec());
    msg.embedded(value.to_vec(), frame, 0);
}

fn write_params(msg: &mut Message, params: &[Param<'_>]) {
    let frame = msg.buffer(Message::vec_frame(params.len()).to_vec());
    let mut array = vec![0u8; params.len() * PARAM_BYTES];
    for (i, p) in params.iter().enumerate() {
        let base = i * PARAM_BYTES;
        array[base..base + 4].copy_from_slice(&p.tag.to_le_bytes());
        array[base + 8..base + 16].copy_from_slice(&p.scalar.to_le_bytes());
        array[base + 16..base + 32].copy_from_slice(&Message::vec_frame(p.blob.len()));
    }
    let parent = msg.embedded(array, frame, 0);
    for (i, p) in params.iter().enumerate() {
        msg.embedded(p.blob.to_vec(), parent, i * PARAM_BYTES + 16);
    }
}

fn write_auth_token(msg: &mut Message, note: Option<&Token>) {
    let mut buf = vec![0u8; AUTH_TOKEN_BYTES];
    let mac = match note {
        Some(n) => {
            buf[0..8].copy_from_slice(&n.challenge.to_le_bytes());
            buf[8..16].copy_from_slice(&n.user.to_le_bytes());
            buf[16..24].copy_from_slice(&n.authenticator.to_le_bytes());
            buf[24..28].copy_from_slice(&(n.kind as u32).to_le_bytes());
            buf[32..40].copy_from_slice(&n.when.to_le_bytes());
            n.mac.clone()
        }
        None => Vec::new(),
    };
    buf[40..56].copy_from_slice(&Message::vec_frame(mac.len()));
    let parent = msg.buffer(buf);
    msg.embedded(mac, parent, 40);
}

fn write_empty_verification_token(msg: &mut Message) {
    let mut buf = vec![0u8; VERIFICATION_TOKEN_BYTES];
    buf[16..32].copy_from_slice(&Message::vec_frame(0));
    buf[40..56].copy_from_slice(&Message::vec_frame(0));
    let parent = msg.buffer(buf);
    msg.embedded(Vec::new(), parent, 16);
    msg.embedded(Vec::new(), parent, 40);
}

fn gcm_params<'a>(app_id: &'a [u8], nonce: &'a [u8]) -> Vec<Param<'a>> {
    let mut params = vec![
        Param::integer(TAG_BLOCK_MODE, BLOCK_MODE_GCM),
        Param::integer(TAG_PADDING, PADDING_NONE),
        Param::integer(TAG_MAC_LENGTH, 128),
    ];
    if !app_id.is_empty() {
        params.push(Param::bytes(TAG_APPLICATION_ID, app_id));
    }
    params.push(Param::bytes(TAG_NONCE, nonce));
    params
}

fn upgrade_params<'a>(app_id: &'a [u8]) -> Vec<Param<'a>> {
    let mut params = Vec::new();
    if !app_id.is_empty() {
        params.push(Param::bytes(TAG_APPLICATION_ID, app_id));
    }
    params
}

fn vec_count(frame: &[u8], offset: usize) -> Result<usize> {
    let slice: [u8; 4] = frame
        .get(offset + 8..offset + 12)
        .and_then(|s| s.try_into().ok())
        .context("hidl_vec frame too short")?;
    Ok(u32::from_le_bytes(slice) as usize)
}

fn read_bytes_vec(read: &mut Answer) -> Result<Vec<u8>> {
    let frame = read.pointed().context("read bytes frame")?;
    let count = vec_count(frame, 0)?;
    let data = read.pointed().context("read bytes data")?;
    if data.len() < count {
        bail!("hidl_vec promised {count} bytes and gave {}", data.len());
    }
    Ok(data[..count].to_vec())
}

fn read_param_array(read: &mut Answer, count: usize, out: &mut Vec<(i32, i64)>) -> Result<()> {
    let raw = read.pointed().context("read KeyParameter array")?;
    if raw.len() < count * PARAM_BYTES {
        bail!("KeyParameter array has {} bytes for {count} entries", raw.len());
    }
    for chunk in raw.as_chunks::<PARAM_BYTES>().0.iter().take(count) {
        let tag = i32::from_le_bytes(chunk[0..4].try_into().expect("four bytes"));
        let num = i64::from_le_bytes(chunk[8..16].try_into().expect("eight bytes"));
        let blob = read.pointed().context("read KeyParameter blob")?;
        let value = match tag & TAG_KIND {
            KIND_ULONG | KIND_ULONG_REP | KIND_DATE => num,
            KIND_BYTES | KIND_BIGNUM => blob.len() as i64,
            _ => (num as u32) as i64,
        };
        out.push((tag, value));
    }
    Ok(())
}

fn skip_params_vec(read: &mut Answer) -> Result<()> {
    let frame = read.pointed().context("read outParams frame")?;
    let count = vec_count(frame, 0)?;
    let _ = read.pointed().context("read outParams array")?;
    for _ in 0..count {
        let _ = read.pointed().context("read outParams blob")?;
    }
    Ok(())
}

fn parse_hardware_info(read: &mut Answer) -> Result<Hardware> {
    read.status().context("ask the key service about itself")?;
    let security_level = read.i32().context("read keymaster security level")?;
    let name = read.pointed_text().context("read keymaster name")?;
    let author = read.pointed_text().context("read keymaster author")?;
    Ok(Hardware { version: 4, security_level, name, author })
}

fn parse_blob_reply(read: &mut Answer, action: &str) -> Result<Vec<u8>> {
    read.status().with_context(|| action.to_string())?;
    let error = read.i32().with_context(|| action.to_string())?;
    let blob = read_bytes_vec(read)?;
    check(error, action)?;
    Ok(blob)
}

fn parse_characteristics_reply(read: &mut Answer) -> Result<Vec<(i32, i64)>> {
    read.status().context("ask what the key may be used for")?;
    let error = read.i32().context("ask what the key may be used for")?;
    let frame = read.pointed().context("read KeyCharacteristics")?;
    if frame.len() < CHARACTERISTICS_BYTES {
        bail!("KeyCharacteristics is {} bytes, expected at least {CHARACTERISTICS_BYTES}", frame.len());
    }
    let sw_count = vec_count(frame, 0)?;
    let hw_count = vec_count(frame, 16)?;
    let mut out = Vec::with_capacity(sw_count + hw_count);
    read_param_array(read, sw_count, &mut out)?;
    read_param_array(read, hw_count, &mut out)?;
    check(error, "ask what the key may be used for")?;
    Ok(out)
}

fn parse_begin_reply(read: &mut Answer) -> Result<u64> {
    read.status().context("start a decryption")?;
    let error = read.i32().context("start a decryption")?;
    skip_params_vec(read)?;
    let handle = read.u64().context("read the operation handle")?;
    check(error, "start a decryption")?;
    Ok(handle)
}

fn parse_output_reply(read: &mut Answer, has_consumed: bool, action: &str) -> Result<Vec<u8>> {
    read.status().with_context(|| action.to_string())?;
    let error = read.i32().with_context(|| action.to_string())?;
    if has_consumed {
        read.i32().with_context(|| action.to_string())?;
    }
    skip_params_vec(read)?;
    let output = read_bytes_vec(read)?;
    check(error, action)?;
    Ok(output)
}

/// The older HIDL key service (`IKeymasterDevice@4.0` / `@4.1`).
#[cfg(target_os = "android")]
pub struct Keymaster<'a> {
    device: skyward_binder::driver::Handle<'a>,
}

#[cfg(target_os = "android")]
impl<'a> Keymaster<'a> {
    pub fn find(hardware: &'a skyward_binder::driver::Binder) -> Result<Option<Keymaster<'a>>> {
        if let Some(device) = hidl::find(hardware, HARDWARE_SERVICE_4_1, INSTANCE)? {
            return Ok(Some(Keymaster { device }));
        }
        Ok(hidl::find(hardware, HARDWARE_SERVICE, INSTANCE)?.map(|device| Keymaster { device }))
    }

    pub fn hardware(&self) -> Result<Hardware> {
        let reply = self
            .device
            .transact(GET_HARDWARE_INFO, &Message::call(HARDWARE_SERVICE))
            .context("ask the key service about itself")?;
        parse_hardware_info(&mut Answer::new(reply.bytes()))
    }

    pub fn ephemeral_storage_key(&self, key: &[u8]) -> Result<Vec<u8>> {
        match self.export_raw(key) {
            Err(e) if is_upgrade_required(&e) => {
                let renewed = self
                    .upgrade(key, &[])
                    .context("renew the storage key for the firmware running now")?;
                self.export_raw(&renewed)
            }
            converted => converted,
        }
    }

    fn export_raw(&self, key: &[u8]) -> Result<Vec<u8>> {
        let key = raw_blob(key)?;
        let mut msg = Message::call(HARDWARE_SERVICE);
        msg.u32(KEY_FORMAT_RAW);
        write_bytes_vec(&mut msg, key);
        write_bytes_vec(&mut msg, &[]);
        write_bytes_vec(&mut msg, &[]);
        let reply = self.device.transact(EXPORT_KEY, &msg).context("make a storage key for this start")?;
        parse_blob_reply(&mut Answer::new(reply.bytes()), "make a storage key for this start")
    }

    pub fn authorizations(&self, key_blob: &[u8], app_id: &[u8]) -> Result<Vec<(i32, i64)>> {
        let key_blob = raw_blob(key_blob)?;
        let mut msg = Message::call(HARDWARE_SERVICE);
        write_bytes_vec(&mut msg, key_blob);
        write_bytes_vec(&mut msg, app_id);
        write_bytes_vec(&mut msg, &[]);
        let reply = self
            .device
            .transact(GET_KEY_CHARACTERISTICS, &msg)
            .context("ask what the key may be used for")?;
        parse_characteristics_reply(&mut Answer::new(reply.bytes()))
    }

    pub fn gcm_decrypt(&self, key_blob: &[u8], app_id: &[u8], nonce: &[u8], body: &[u8], note: Option<&Token>) -> Result<Vec<u8>> {
        let operation = match self.begin(key_blob, app_id, nonce, note) {
            Ok(op) => op,
            Err(e) if is_upgrade_required(&e) => {
                let renewed = self
                    .upgrade(key_blob, &upgrade_params(app_id))
                    .context("renew the key for the firmware running now")?;
                self.begin(&renewed, app_id, nonce, note)?
            }
            Err(e) => return Err(e),
        };
        match self.run_gcm(operation, body) {
            Ok(out) => Ok(out),
            Err(e) => {
                let _ = self.abort(operation);
                Err(e)
            }
        }
    }

    fn run_gcm(&self, operation: u64, body: &[u8]) -> Result<Vec<u8>> {
        let mut out = self.update(operation, body)?;
        out.extend_from_slice(&self.finish(operation)?);
        Ok(out)
    }

    pub fn usable(&self, key_blob: &[u8], app_id: &[u8]) -> Result<()> {
        let operation = self.begin(key_blob, app_id, &[0; NONCE_BYTES], None)?;
        self.abort(operation)
    }

    fn begin(&self, key_blob: &[u8], app_id: &[u8], nonce: &[u8], note: Option<&Token>) -> Result<u64> {
        let key_blob = raw_blob(key_blob)?;
        let mut msg = Message::call(HARDWARE_SERVICE);
        msg.u32(PURPOSE_DECRYPT);
        write_bytes_vec(&mut msg, key_blob);
        write_params(&mut msg, &gcm_params(app_id, nonce));
        write_auth_token(&mut msg, note);
        let reply = self.device.transact(BEGIN, &msg).context("start a decryption")?;
        parse_begin_reply(&mut Answer::new(reply.bytes()))
    }

    fn upgrade(&self, key_blob: &[u8], params: &[Param<'_>]) -> Result<Vec<u8>> {
        let key_blob = raw_blob(key_blob)?;
        let mut msg = Message::call(HARDWARE_SERVICE);
        write_bytes_vec(&mut msg, key_blob);
        write_params(&mut msg, params);
        let reply = self.device.transact(UPGRADE_KEY, &msg).context("renew the key")?;
        parse_blob_reply(&mut Answer::new(reply.bytes()), "renew the key")
    }

    fn update(&self, operation: u64, input: &[u8]) -> Result<Vec<u8>> {
        let mut msg = Message::call(HARDWARE_SERVICE);
        msg.u64(operation);
        write_params(&mut msg, &[]);
        write_bytes_vec(&mut msg, input);
        write_auth_token(&mut msg, None);
        write_empty_verification_token(&mut msg);
        let reply = self.device.transact(UPDATE, &msg).context("decrypt the key")?;
        parse_output_reply(&mut Answer::new(reply.bytes()), true, "decrypt the key")
    }

    fn finish(&self, operation: u64) -> Result<Vec<u8>> {
        let mut msg = Message::call(HARDWARE_SERVICE);
        msg.u64(operation);
        write_params(&mut msg, &[]);
        write_bytes_vec(&mut msg, &[]);
        write_bytes_vec(&mut msg, &[]);
        write_auth_token(&mut msg, None);
        write_empty_verification_token(&mut msg);
        let reply = self.device.transact(FINISH, &msg).context("finish decrypting the key")?;
        parse_output_reply(&mut Answer::new(reply.bytes()), false, "finish decrypting the key")
    }

    fn abort(&self, operation: u64) -> Result<()> {
        let mut msg = Message::call(HARDWARE_SERVICE);
        msg.u64(operation);
        let reply = self.device.transact(ABORT, &msg).context("drop the decryption")?;
        let mut read = Answer::new(reply.bytes());
        read.status().context("drop the decryption")?;
        let error = read.i32().context("drop the decryption")?;
        check(error, "drop the decryption")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ADDRESS: u32 = 0x7074_2a85;

    fn push_address(reply: &mut Vec<u8>, bytes: &[u8]) {
        reply.extend_from_slice(&ADDRESS.to_le_bytes());
        reply.extend_from_slice(&0u32.to_le_bytes());
        let ptr = if bytes.is_empty() { 0u64 } else { bytes.as_ptr() as u64 };
        reply.extend_from_slice(&ptr.to_le_bytes());
        reply.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
        reply.extend_from_slice(&0u64.to_le_bytes());
        reply.extend_from_slice(&0u64.to_le_bytes());
        assert_eq!(reply.len() % 4, 0);
    }

    fn push_text(reply: &mut Vec<u8>, text: &str, backing: &mut Vec<Box<[u8]>>) {
        let mut buf = text.as_bytes().to_vec();
        buf.push(0);
        let frame = Message::vec_frame(text.len()).to_vec().into_boxed_slice();
        let data = buf.into_boxed_slice();
        push_address(reply, &frame);
        push_address(reply, &data);
        backing.push(frame);
        backing.push(data);
    }

    #[test]
    fn begin_and_finish_replies_are_parsed_with_and_without_out_params() {
        let mut reply = Vec::new();
        reply.extend_from_slice(&0i32.to_le_bytes());
        reply.extend_from_slice(&ERROR_OK.to_le_bytes());
        let out_frame = Message::vec_frame(0);
        push_address(&mut reply, &out_frame);
        push_address(&mut reply, &[]);
        reply.extend_from_slice(&0xdead_beef_cafe_1234u64.to_le_bytes());
        assert_eq!(parse_begin_reply(&mut Answer::new(&reply)).unwrap(), 0xdead_beef_cafe_1234);

        let mut finish = Vec::new();
        finish.extend_from_slice(&0i32.to_le_bytes());
        finish.extend_from_slice(&ERROR_OK.to_le_bytes());
        push_address(&mut finish, &out_frame);
        push_address(&mut finish, &[]);
        let plain = b"plaintext";
        let out_bytes_frame = Message::vec_frame(plain.len());
        push_address(&mut finish, &out_bytes_frame);
        push_address(&mut finish, plain);
        assert_eq!(parse_output_reply(&mut Answer::new(&finish), false, "finish").unwrap(), plain);
    }

    #[test]
    fn begin_writes_key_parameters_and_auth_token_without_error() {
        let mut msg = Message::call(HARDWARE_SERVICE);
        msg.u32(PURPOSE_DECRYPT);
        write_bytes_vec(&mut msg, &[1, 2, 3]);
        write_params(&mut msg, &gcm_params(b"app", &[9; 12]));
        let token = Token {
            challenge: 11,
            user: 22,
            authenticator: 33,
            kind: 1,
            when: 44,
            mac: vec![0xAA; 32],
        };
        write_auth_token(&mut msg, Some(&token));
    }

    #[test]
    fn characteristics_reply_reads_both_enforced_lists_in_order() {
        let mut sw = vec![0u8; PARAM_BYTES];
        sw[0..4].copy_from_slice(&TAG_APPLICATION_ID.to_le_bytes());
        sw[16..32].copy_from_slice(&Message::vec_frame(3));

        let mut hw = vec![0u8; PARAM_BYTES];
        let tag_user_secure_id = KIND_ULONG_REP | 502;
        hw[0..4].copy_from_slice(&tag_user_secure_id.to_le_bytes());
        hw[8..16].copy_from_slice(&0x1234_5678_9abc_def0i64.to_le_bytes());

        let mut char_frame = [0u8; CHARACTERISTICS_BYTES];
        char_frame[0..16].copy_from_slice(&Message::vec_frame(1));
        char_frame[16..32].copy_from_slice(&Message::vec_frame(1));

        let mut reply = Vec::new();
        reply.extend_from_slice(&0i32.to_le_bytes()); // transport status
        reply.extend_from_slice(&ERROR_OK.to_le_bytes());
        push_address(&mut reply, &char_frame);
        push_address(&mut reply, &sw);
        let sw_blob = b"app";
        push_address(&mut reply, sw_blob);
        push_address(&mut reply, &hw);
        push_address(&mut reply, &[]);

        let out = parse_characteristics_reply(&mut Answer::new(&reply)).unwrap();
        assert_eq!(out, vec![(TAG_APPLICATION_ID, 3), (tag_user_secure_id, 0x1234_5678_9abc_def0)]);
    }

    #[test]
    fn hardware_info_reply_parses_security_level_name_and_author() {
        let mut backing = Vec::new();
        let mut reply = Vec::new();
        reply.extend_from_slice(&0i32.to_le_bytes());
        reply.extend_from_slice(&1i32.to_le_bytes());
        push_text(&mut reply, "KeymasterHAL", &mut backing);
        push_text(&mut reply, "QTI", &mut backing);

        let hw = parse_hardware_info(&mut Answer::new(&reply)).unwrap();
        assert_eq!(hw.version, 4);
        assert_eq!(hw.security_level, 1);
        assert_eq!(hw.name, "KeymasterHAL");
        assert_eq!(hw.author, "QTI");
    }

    #[test]
    fn upgrade_required_error_is_detected_without_losing_context() {
        let err = check(KEY_REQUIRES_UPGRADE, "start a decryption").unwrap_err();
        assert!(is_upgrade_required(&err));
    }

    #[test]
    fn strips_keystore2_compat_hw_prefix_and_rejects_sw_prefix() {
        assert_eq!(raw_blob(b"pKMblob\0inner").unwrap(), b"inner");
        assert_eq!(raw_blob(b"rawblob").unwrap(), b"rawblob");
        assert!(raw_blob(b"pKMblob\x01soft").is_err());
    }
}
