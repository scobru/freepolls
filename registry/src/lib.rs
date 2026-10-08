//! Public poll directory. One shared instance; parameters = admin ed25519 pubkey (32 bytes).
//! Anyone can list a poll by signing the entry with the poll owner's key and attaching a
//! proof-of-work nonce. The admin can block instances with a signed blocklist.
//! State is JSON; the newest MAX_ENTRIES entries are kept.
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use freenet_stdlib::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const POW_BITS: u32 = 18;
pub const MAX_ENTRIES: usize = 500;
const MAX_TITLE: usize = 120;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Entry {
    pub params: String, // poll parameters, hex: owner pubkey (32 bytes) || salt
    pub title: String,
    pub ts: u64,
    pub nonce: u64,
    pub sig: String, // hex, by the poll owner over `fpl1|<instance>|<params>|<title>|<ts>`
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct Blocklist {
    pub ts: u64,
    pub list: Vec<String>,
    pub sig: String, // hex, by admin over `fpb1|<ts>|<list joined by ,>`
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct RegState {
    pub entries: BTreeMap<String, Entry>, // poll instance id (base58) -> entry
    pub blocked: Blocklist,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Summary {
    pub entries: BTreeMap<String, u64>,
    pub blocked_ts: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Delta {
    #[serde(default)]
    pub entries: BTreeMap<String, Entry>,
    #[serde(default)]
    pub blocked: Option<Blocklist>,
}

type R<T> = Result<T, String>;

fn key(hexstr: &str) -> R<VerifyingKey> {
    let b: [u8; 32] = hex::decode(hexstr)
        .map_err(|e| e.to_string())?
        .try_into()
        .map_err(|_| "pubkey must be 32 bytes")?;
    VerifyingKey::from_bytes(&b).map_err(|e| e.to_string())
}

fn verify(k: &VerifyingKey, msg: &[u8], sig_hex: &str) -> R<()> {
    let sig = Signature::from_slice(&hex::decode(sig_hex).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    k.verify(msg, &sig).map_err(|_| "bad signature".to_string())
}

fn zero_bits(h: &[u8]) -> u32 {
    let mut n = 0;
    for b in h {
        n += b.leading_zeros();
        if *b != 0 {
            break;
        }
    }
    n
}

fn is_id(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_alphanumeric())
}

fn check_entry(instance: &str, e: &Entry) -> R<()> {
    if !is_id(instance) {
        return Err("bad instance id".into());
    }
    let t = e.title.chars().count();
    if t == 0 || t > MAX_TITLE || e.title.chars().any(char::is_control) {
        return Err("bad title".into());
    }
    let owner = e.params.get(..64).ok_or("params too short")?;
    let msg = format!("fpl1|{instance}|{}|{}|{}", e.params, e.title, e.ts);
    verify(&key(owner)?, msg.as_bytes(), &e.sig)?;
    let h = Sha256::digest(format!("{msg}|{}", e.nonce).as_bytes());
    if zero_bits(&h) < POW_BITS {
        return Err("insufficient proof of work".into());
    }
    Ok(())
}

fn check_blocklist(admin: &str, b: &Blocklist) -> R<()> {
    if b.ts == 0 && b.list.is_empty() && b.sig.is_empty() {
        return Ok(()); // initial empty state
    }
    if b.list.len() > 10_000 || !b.list.iter().all(|i| is_id(i)) {
        return Err("bad blocklist".into());
    }
    verify(&key(admin)?, format!("fpb1|{}|{}", b.ts, b.list.join(",")).as_bytes(), &b.sig)
}

/// Keep the newest `max` entries; deterministic, so merge order does not matter.
pub fn prune(entries: &mut BTreeMap<String, Entry>, max: usize) {
    if entries.len() <= max {
        return;
    }
    let mut order: Vec<_> = entries.iter().map(|(k, e)| (std::cmp::Reverse(e.ts), k.clone())).collect();
    order.sort();
    for (_, k) in order.into_iter().skip(max) {
        entries.remove(&k);
    }
}

pub fn validate(admin: &str, s: &RegState) -> R<()> {
    check_blocklist(admin, &s.blocked)?;
    if s.entries.len() > MAX_ENTRIES || s.entries.keys().any(|k| s.blocked.list.contains(k)) {
        return Err("state out of bounds".into());
    }
    s.entries.iter().try_for_each(|(k, e)| check_entry(k, e))
}

pub fn apply(admin: &str, s: &mut RegState, d: Delta) -> R<()> {
    if let Some(b) = d.blocked {
        if b.ts > s.blocked.ts {
            check_blocklist(admin, &b)?;
            s.blocked = b;
        }
    }
    for (inst, e) in d.entries {
        if s.blocked.list.contains(&inst) || s.entries.get(&inst).is_some_and(|old| old.ts >= e.ts) {
            continue; // blocked or not newer: ignore, so every merge order converges
        }
        check_entry(&inst, &e)?;
        s.entries.insert(inst, e);
    }
    let blocked = s.blocked.list.clone();
    s.entries.retain(|k, _| !blocked.contains(k));
    prune(&mut s.entries, MAX_ENTRIES);
    Ok(())
}

pub fn summarize(s: &RegState) -> Summary {
    Summary { entries: s.entries.iter().map(|(k, e)| (k.clone(), e.ts)).collect(), blocked_ts: s.blocked.ts }
}

pub fn delta(s: &RegState, sum: &Summary) -> Delta {
    Delta {
        entries: s
            .entries
            .iter()
            .filter(|(k, e)| sum.entries.get(*k).is_none_or(|&t| t < e.ts))
            .map(|(k, e)| (k.clone(), e.clone()))
            .collect(),
        blocked: (s.blocked.ts > sum.blocked_ts).then(|| s.blocked.clone()),
    }
}

// ---- Freenet glue ----

fn admin(p: &Parameters) -> String {
    hex::encode(p.as_ref())
}

fn de<T: for<'a> Deserialize<'a>>(b: &[u8]) -> Result<T, ContractError> {
    serde_json::from_slice(b).map_err(|e| ContractError::Deser(e.to_string()))
}

/// Empty bytes (e.g. subscribe with no summary) mean "nothing known yet".
fn de_or_default<T: for<'a> Deserialize<'a> + Default>(b: &[u8]) -> Result<T, ContractError> {
    if b.is_empty() { Ok(T::default()) } else { de(b) }
}

fn ser<T: Serialize>(v: &T) -> Result<Vec<u8>, ContractError> {
    serde_json::to_vec(v).map_err(|e| ContractError::Deser(e.to_string()))
}

struct Contract;

#[contract]
impl ContractInterface for Contract {
    fn validate_state(
        parameters: Parameters<'static>,
        state: State<'static>,
        _related: RelatedContracts<'static>,
    ) -> Result<ValidateResult, ContractError> {
        let s: RegState = de_or_default(state.as_ref())?;
        Ok(match validate(&admin(&parameters), &s) {
            Ok(()) => ValidateResult::Valid,
            Err(_) => ValidateResult::Invalid,
        })
    }

    fn update_state(
        parameters: Parameters<'static>,
        state: State<'static>,
        data: Vec<UpdateData<'static>>,
    ) -> Result<UpdateModification<'static>, ContractError> {
        let admin = admin(&parameters);
        let mut s: RegState = de_or_default(state.as_ref())?;
        for u in data {
            let d: Delta = match u {
                UpdateData::State(st) => {
                    let o: RegState = de(st.as_ref())?;
                    Delta { entries: o.entries, blocked: Some(o.blocked) }
                }
                UpdateData::Delta(d) => de(d.as_ref())?,
                UpdateData::StateAndDelta { delta, .. } => de(delta.as_ref())?,
                _ => return Err(ContractError::InvalidUpdate),
            };
            apply(&admin, &mut s, d).map_err(|_| ContractError::InvalidUpdate)?;
        }
        Ok(UpdateModification::valid(State::from(ser(&s)?)))
    }

    fn summarize_state(
        _parameters: Parameters<'static>,
        state: State<'static>,
    ) -> Result<StateSummary<'static>, ContractError> {
        Ok(StateSummary::from(ser(&summarize(&de_or_default(state.as_ref())?))?))
    }

    fn get_state_delta(
        _parameters: Parameters<'static>,
        state: State<'static>,
        summary: StateSummary<'static>,
    ) -> Result<StateDelta<'static>, ContractError> {
        Ok(StateDelta::from(ser(&delta(&de_or_default(state.as_ref())?, &de_or_default(summary.as_ref())?))?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn sk(n: u8) -> SigningKey {
        SigningKey::from_bytes(&[n; 32])
    }
    fn pk(k: &SigningKey) -> String {
        hex::encode(k.verifying_key().to_bytes())
    }

    /// Valid entry for `instance`, mining a real nonce (about 2^18 hashes).
    fn entry(instance: &str, owner: &SigningKey, title: &str, ts: u64) -> Entry {
        let o = format!("{}{}", pk(owner), "cd".repeat(16));
        let msg = format!("fpl1|{instance}|{o}|{title}|{ts}");
        let sig = hex::encode(owner.sign(msg.as_bytes()).to_bytes());
        let nonce = (0u64..)
            .find(|n| zero_bits(&Sha256::digest(format!("{msg}|{n}").as_bytes())) >= POW_BITS)
            .unwrap();
        Entry { params: o, title: title.into(), ts, nonce, sig }
    }

    fn block(admin: &SigningKey, ts: u64, list: &[&str]) -> Blocklist {
        let list: Vec<String> = list.iter().map(|s| s.to_string()).collect();
        let sig = hex::encode(admin.sign(format!("fpb1|{ts}|{}", list.join(",")).as_bytes()).to_bytes());
        Blocklist { ts, list, sig }
    }

    #[test]
    fn list_block_and_reject() {
        let admin_sk = sk(1);
        let a = pk(&admin_sk);
        let mut s = RegState::default();
        validate(&a, &s).unwrap(); // empty initial state

        let e = entry("PollA", &sk(2), "Lunch?", 10);
        apply(&a, &mut s, Delta { entries: [("PollA".into(), e.clone())].into(), blocked: None }).unwrap();
        validate(&a, &s).unwrap();

        // newer replaces, older ignored
        let newer = entry("PollA", &sk(2), "Lunch? v2", 20);
        apply(&a, &mut s, Delta { entries: [("PollA".into(), newer)].into(), blocked: None }).unwrap();
        assert_eq!(s.entries["PollA"].ts, 20);
        apply(&a, &mut s, Delta { entries: [("PollA".into(), e.clone())].into(), blocked: None }).unwrap();
        assert_eq!(s.entries["PollA"].ts, 20);

        // forged title and missing proof-of-work are rejected
        let mut forged = entry("PollB", &sk(3), "Hi", 5);
        forged.title = "Not signed".into();
        assert!(apply(&a, &mut s, Delta { entries: [("PollB".into(), forged)].into(), blocked: None }).is_err());
        let mut lazy = entry("PollB", &sk(3), "Hi", 5);
        lazy.nonce += 1; // almost surely no longer meets the difficulty (fails with probability 2^-18)
        assert!(check_entry("PollB", &lazy).is_err());

        // blocklist must be signed by the admin
        let fake = block(&sk(9), 1, &["PollA"]);
        assert!(apply(&a, &mut s, Delta { entries: Default::default(), blocked: Some(fake) }).is_err());
        let good = block(&admin_sk, 1, &["PollA"]);
        apply(&a, &mut s, Delta { entries: Default::default(), blocked: Some(good) }).unwrap();
        assert!(s.entries.is_empty());
        validate(&a, &s).unwrap();
        // blocked instance cannot come back, even with a valid entry
        let again = entry("PollA", &sk(2), "Again", 99);
        apply(&a, &mut s, Delta { entries: [("PollA".into(), again)].into(), blocked: None }).unwrap();
        assert!(s.entries.is_empty());

        // delta vs summary
        let c = entry("PollC", &sk(4), "C", 7);
        apply(&a, &mut s, Delta { entries: [("PollC".into(), c)].into(), blocked: None }).unwrap();
        let d = delta(&s, &Summary::default());
        assert!(d.entries.contains_key("PollC") && d.blocked.is_some());
        let d2 = delta(&s, &summarize(&s));
        assert!(d2.entries.is_empty() && d2.blocked.is_none());
    }

    #[test]
    fn prune_keeps_newest() {
        let fake = |ts| Entry { params: String::new(), title: String::new(), ts, nonce: 0, sig: String::new() };
        let mut m: BTreeMap<String, Entry> = (1..=5u64).map(|i| (format!("p{i}"), fake(i))).collect();
        prune(&mut m, 3);
        assert_eq!(m.keys().cloned().collect::<Vec<_>>(), ["p3", "p4", "p5"]);
    }
}
