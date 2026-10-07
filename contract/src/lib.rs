//! Form/poll contract. One contract instance per form; parameters = owner ed25519 pubkey (32 bytes).
//! State is JSON. Schema and answers travel as the exact signed strings, so no canonicalization needed.
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use freenet_stdlib::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Response {
    pub ts: u64,
    pub answers_json: String,
    pub sig: String, // hex
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct FormState {
    pub schema_json: String,
    pub schema_sig: String, // hex
    pub responses: BTreeMap<String, Response>, // respondent pubkey hex -> response
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Summary {
    pub has_schema: bool,
    pub responses: BTreeMap<String, u64>, // pubkey -> ts
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Delta {
    pub schema: Option<(String, String)>, // (schema_json, sig)
    pub responses: BTreeMap<String, Response>,
}

#[derive(Deserialize)]
struct Schema {
    questions: Vec<Question>,
    /// Invite-only poll: pubkeys (hex) allowed to answer. `None` = open poll.
    #[serde(default)]
    allowed: Option<Vec<String>>,
}

const MAX_INVITES: usize = 1000;

#[derive(Deserialize)]
struct Question {
    id: String,
    kind: String, // single | multi | text | avail
    #[serde(default)]
    options: Vec<String>,
    #[serde(default)]
    required: bool,
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

fn parse_schema(owner: &str, schema_json: &str, sig: &str) -> R<Schema> {
    verify(&key(owner)?, format!("fps1|{schema_json}").as_bytes(), sig)?;
    let schema: Schema = serde_json::from_str(schema_json).map_err(|e| e.to_string())?;
    if let Some(a) = &schema.allowed {
        if a.len() > MAX_INVITES {
            return Err("too many invites".into());
        }
        a.iter().try_for_each(|k| key(k).map(|_| ()))?;
    }
    Ok(schema)
}

fn check_answers(schema: &Schema, answers_json: &str) -> R<()> {
    let a: BTreeMap<String, Value> = serde_json::from_str(answers_json).map_err(|e| e.to_string())?;
    for id in a.keys() {
        if !schema.questions.iter().any(|q| &q.id == id) {
            return Err(format!("unknown question {id}"));
        }
    }
    for q in &schema.questions {
        let Some(v) = a.get(&q.id) else {
            if q.required {
                return Err(format!("missing {}", q.id));
            }
            continue;
        };
        let in_range = |v: &Value| v.as_u64().is_some_and(|i| (i as usize) < q.options.len());
        let ok = match q.kind.as_str() {
            "single" => in_range(v),
            "multi" => v.as_array().is_some_and(|l| l.iter().all(in_range)),
            // one value per slot: 0 = no, 1 = yes, 2 = maybe
            "avail" => v.as_array().is_some_and(|l| l.len() == q.options.len() && l.iter().all(|x| x.as_u64().is_some_and(|n| n <= 2))),
            "text" => v.as_str().is_some_and(|s| s.len() <= 2000),
            _ => false,
        };
        if !ok {
            return Err(format!("invalid answer for {}", q.id));
        }
    }
    Ok(())
}

fn check_response(owner: &str, schema: &Schema, who: &str, r: &Response) -> R<()> {
    if schema.allowed.as_ref().is_some_and(|a| !a.iter().any(|k| k == who)) {
        return Err("respondent not invited".into());
    }
    let msg = format!("fpr1|{owner}|{who}|{}|{}", r.ts, r.answers_json);
    verify(&key(who)?, msg.as_bytes(), &r.sig)?;
    check_answers(schema, &r.answers_json)
}

pub fn validate(owner: &str, s: &FormState) -> R<()> {
    let schema = parse_schema(owner, &s.schema_json, &s.schema_sig)?;
    s.responses.iter().try_for_each(|(who, r)| check_response(owner, &schema, who, r))
}

/// Merge a delta into state: schema is set once, per-respondent last-write-wins by ts.
pub fn apply(owner: &str, s: &mut FormState, d: Delta) -> R<()> {
    if let Some((json, sig)) = d.schema {
        if s.schema_json.is_empty() {
            parse_schema(owner, &json, &sig)?;
            s.schema_json = json;
            s.schema_sig = sig;
        }
    }
    let schema = parse_schema(owner, &s.schema_json, &s.schema_sig)?;
    for (who, r) in d.responses {
        if s.responses.get(&who).is_some_and(|old| old.ts >= r.ts) {
            continue;
        }
        check_response(owner, &schema, &who, &r)?;
        s.responses.insert(who, r);
    }
    Ok(())
}

pub fn summarize(s: &FormState) -> Summary {
    Summary {
        has_schema: !s.schema_json.is_empty(),
        responses: s.responses.iter().map(|(k, r)| (k.clone(), r.ts)).collect(),
    }
}

pub fn delta(s: &FormState, sum: &Summary) -> Delta {
    Delta {
        schema: (!sum.has_schema && !s.schema_json.is_empty())
            .then(|| (s.schema_json.clone(), s.schema_sig.clone())),
        responses: s
            .responses
            .iter()
            .filter(|(k, r)| sum.responses.get(*k).is_none_or(|&t| t < r.ts))
            .map(|(k, r)| (k.clone(), r.clone()))
            .collect(),
    }
}

// ---- Freenet glue ----

fn owner(p: &Parameters) -> Result<String, ContractError> {
    Ok(hex::encode(p.as_ref()))
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
        let s: FormState = de(state.as_ref())?;
        Ok(match validate(&owner(&parameters)?, &s) {
            Ok(()) => ValidateResult::Valid,
            Err(_) => ValidateResult::Invalid,
        })
    }

    fn update_state(
        parameters: Parameters<'static>,
        state: State<'static>,
        data: Vec<UpdateData<'static>>,
    ) -> Result<UpdateModification<'static>, ContractError> {
        let owner = owner(&parameters)?;
        let mut s: FormState = de_or_default(state.as_ref())?;
        for u in data {
            let d: Delta = match u {
                UpdateData::State(st) => {
                    let other: FormState = de(st.as_ref())?;
                    Delta {
                        schema: (!other.schema_json.is_empty()).then(|| (other.schema_json, other.schema_sig)),
                        responses: other.responses,
                    }
                }
                UpdateData::Delta(d) => de(d.as_ref())?,
                UpdateData::StateAndDelta { delta, .. } => de(delta.as_ref())?,
                _ => return Err(ContractError::InvalidUpdate),
            };
            apply(&owner, &mut s, d).map_err(|_| ContractError::InvalidUpdate)?;
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
    const SCHEMA: &str = r#"{"questions":[{"id":"q1","kind":"single","options":["a","b"],"required":true}]}"#;

    fn resp(owner: &str, who: &SigningKey, ts: u64, ans: &str) -> (String, Response) {
        let msg = format!("fpr1|{owner}|{}|{ts}|{ans}", pk(who));
        (pk(who), Response { ts, answers_json: ans.into(), sig: hex::encode(who.sign(msg.as_bytes()).to_bytes()) })
    }

    #[test]
    fn availability_answers() {
        let schema = Schema {
            questions: vec![Question { id: "d".into(), kind: "avail".into(), options: vec!["mon".into(), "tue".into(), "wed".into()], required: true }],
            allowed: None,
        };
        assert!(check_answers(&schema, r#"{"d":[1,0,2]}"#).is_ok());
        assert!(check_answers(&schema, r#"{"d":[1,0]}"#).is_err()); // wrong length
        assert!(check_answers(&schema, r#"{"d":[1,0,3]}"#).is_err()); // out of range
        assert!(check_answers(&schema, r#"{"d":"yes"}"#).is_err());
        assert!(check_answers(&schema, "{}").is_err()); // required
    }

    #[test]
    fn invite_only() {
        let o = sk(1);
        let op = pk(&o);
        let (invited, stranger) = (sk(2), sk(3));
        let schema = format!(
            r#"{{"questions":[{{"id":"q1","kind":"single","options":["a","b"],"required":true}}],"allowed":["{}"]}}"#,
            pk(&invited)
        );
        let sig = hex::encode(o.sign(format!("fps1|{schema}").as_bytes()).to_bytes());
        let mut s = FormState::default();
        let (k, r) = resp(&op, &invited, 1, r#"{"q1":0}"#);
        apply(&op, &mut s, Delta { schema: Some((schema, sig)), responses: [(k, r)].into() }).unwrap();
        validate(&op, &s).unwrap();
        let (k2, r2) = resp(&op, &stranger, 1, r#"{"q1":0}"#);
        assert!(apply(&op, &mut s, Delta { responses: [(k2, r2)].into(), ..Default::default() }).is_err());

        // malformed invite key rejected at schema level
        let bad = r#"{"questions":[],"allowed":["zz"]}"#;
        let bad_sig = hex::encode(o.sign(format!("fps1|{bad}").as_bytes()).to_bytes());
        assert!(parse_schema(&op, bad, &bad_sig).is_err());
    }

    #[test]
    fn merge_flow() {
        let o = sk(1);
        let op = pk(&o);
        let sig = hex::encode(o.sign(format!("fps1|{SCHEMA}").as_bytes()).to_bytes());
        let mut s = FormState::default();
        let mut d = Delta { schema: Some((SCHEMA.into(), sig)), ..Default::default() };
        let (k, r) = resp(&op, &sk(2), 1, r#"{"q1":0}"#);
        d.responses.insert(k.clone(), r);
        apply(&op, &mut s, d).unwrap();
        validate(&op, &s).unwrap();

        // newer replaces older, older ignored
        let (_, r2) = resp(&op, &sk(2), 5, r#"{"q1":1}"#);
        apply(&op, &mut s, Delta { responses: [(k.clone(), r2)].into(), ..Default::default() }).unwrap();
        assert_eq!(s.responses[&k].ts, 5);
        let (_, old) = resp(&op, &sk(2), 3, r#"{"q1":0}"#);
        apply(&op, &mut s, Delta { responses: [(k.clone(), old)].into(), ..Default::default() }).unwrap();
        assert_eq!(s.responses[&k].ts, 5);

        // bad answer, forged sig, wrong form rejected
        let (k3, bad) = resp(&op, &sk(3), 1, r#"{"q1":9}"#);
        assert!(apply(&op, &mut s, Delta { responses: [(k3.clone(), bad)].into(), ..Default::default() }).is_err());
        let (_, mut forged) = resp(&op, &sk(3), 1, r#"{"q1":0}"#);
        forged.ts = 2;
        assert!(apply(&op, &mut s, Delta { responses: [(k3, forged)].into(), ..Default::default() }).is_err());
        let (k4, other_form) = resp(&pk(&sk(9)), &sk(4), 1, r#"{"q1":0}"#);
        assert!(apply(&op, &mut s, Delta { responses: [(k4, other_form)].into(), ..Default::default() }).is_err());

        // delta vs summary
        let d = delta(&s, &Summary::default());
        assert!(d.schema.is_some() && d.responses.len() == 1);
        assert!(delta(&s, &summarize(&s)).responses.is_empty());
    }
}
