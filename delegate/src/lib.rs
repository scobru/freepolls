//! Identity delegate. Keeps one ed25519 signing key per calling web app (namespaced by the app's
//! contract id, supplied by the node) and signs messages on request, so the key survives sessions
//! even where the page has no storage. It also keeps a small per-app key/value store (the poll list,
//! the owner's invite links). Messages are JSON in the ApplicationMessage payload.
use ed25519_dalek::{Signer, SigningKey};
use freenet_stdlib::prelude::*;
use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "lowercase")]
enum Req {
    /// Store this secret (hex, 32 bytes) if no identity exists yet, then answer like `Pubkey`.
    Init { sk: String },
    Pubkey,
    Sign { msg: String },
    Put { key: String, value: String },
    Get { key: String },
}

const MAX_VALUE: usize = 256 * 1024;

fn slot(origin: &Option<MessageOrigin>) -> String {
    match origin {
        Some(MessageOrigin::WebApp(id)) => format!("sk/{}", id.encode()),
        _ => "sk/dev".into(), // no web app behind the request: a local client talking to the node directly
    }
}

/// Per-app store entry name; keys are short and plain so apps cannot collide with the identity slot.
fn kv_name(slot: &str, key: &str) -> Result<String, String> {
    if key.is_empty() || key.len() > 128 || !key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b':' || b == b'-') {
        return Err("bad key".into());
    }
    Ok(format!("{slot}/kv/{key}"))
}

fn key_of(ctx: &DelegateCtx, slot: &str) -> Result<SigningKey, String> {
    let b: [u8; 32] = ctx.get_secret(slot.as_bytes()).ok_or("no identity")?.try_into().map_err(|_| "corrupt secret")?;
    Ok(SigningKey::from_bytes(&b))
}

fn run(ctx: &mut DelegateCtx, slot: &str, req: Req) -> Result<Value, String> {
    match req {
        Req::Init { sk } => {
            if !ctx.has_secret(slot.as_bytes()) {
                let b: [u8; 32] = hex::decode(sk).map_err(|e| e.to_string())?.try_into().map_err(|_| "secret must be 32 bytes")?;
                if !ctx.set_secret(slot.as_bytes(), &b) {
                    return Err("could not store the secret".into());
                }
            }
            run(ctx, slot, Req::Pubkey)
        }
        Req::Pubkey => Ok(json!({ "pk": hex::encode(key_of(ctx, slot)?.verifying_key().to_bytes()) })),
        Req::Sign { msg } => Ok(json!({ "sig": hex::encode(key_of(ctx, slot)?.sign(msg.as_bytes()).to_bytes()) })),
        Req::Put { key, value } => {
            if value.len() > MAX_VALUE {
                return Err("value too large".into());
            }
            if !ctx.set_secret(kv_name(slot, &key)?.as_bytes(), value.as_bytes()) {
                return Err("could not store the value".into());
            }
            Ok(json!({ "ok": true }))
        }
        Req::Get { key } => {
            let v = ctx.get_secret(kv_name(slot, &key)?.as_bytes()).map(|b| String::from_utf8_lossy(&b).into_owned());
            Ok(json!({ "value": v }))
        }
    }
}

struct Identity;

#[delegate]
impl DelegateInterface for Identity {
    fn process(
        ctx: &mut DelegateCtx,
        _parameters: Parameters<'static>,
        origin: Option<MessageOrigin>,
        message: InboundDelegateMsg,
    ) -> Result<Vec<OutboundDelegateMsg>, DelegateError> {
        let InboundDelegateMsg::ApplicationMessage(m) = message else {
            return Err(DelegateError::Other("expected an application message".into()));
        };
        let reply = match serde_json::from_slice::<Req>(&m.payload) {
            Ok(req) => run(ctx, &slot(&origin), req).unwrap_or_else(|e| json!({ "err": e })),
            Err(e) => json!({ "err": e.to_string() }),
        };
        let bytes = serde_json::to_vec(&reply).map_err(|e| DelegateError::Deser(e.to_string()))?;
        Ok(vec![OutboundDelegateMsg::ApplicationMessage(ApplicationMessage::new(bytes).processed(true))])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kv_names_are_validated_and_namespaced() {
        assert_eq!(kv_name("sk/abc", "polls").unwrap(), "sk/abc/kv/polls");
        assert_eq!(kv_name("sk/abc", "inv:Ab1-x").unwrap(), "sk/abc/kv/inv:Ab1-x");
        assert!(kv_name("sk/abc", "").is_err());
        assert!(kv_name("sk/abc", "a/b").is_err()); // no path tricks into other slots
        assert!(kv_name("sk/abc", &"x".repeat(129)).is_err());
    }

    #[test]
    fn requests_parse() {
        assert!(matches!(serde_json::from_str::<Req>(r#"{"op":"pubkey"}"#), Ok(Req::Pubkey)));
        assert!(matches!(serde_json::from_str::<Req>(r#"{"op":"get","key":"polls"}"#), Ok(Req::Get { .. })));
        assert!(serde_json::from_str::<Req>(r#"{"op":"nope"}"#).is_err());
    }
}
