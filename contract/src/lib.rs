//! Form/poll contract. One contract instance per poll.
//! Parameters = owner (a whoiam persona, ed25519 pubkey, 32 bytes) || random salt (16 bytes) || app path
//! (`/v1/contract/web/<FreePolls id>/`). The salt makes every poll address unique, even for the same owner;
//! all signed messages are bound to the full parameters. The schema is signed by an app key the persona
//! delegated for that app path (see `whoiam-delegation`) and carries the delegation.
//! State is JSON. Schema and answers travel as the exact signed strings, so no canonicalization needed.
//! Open polls are rate-limited by ante (github.com/soudasuwa/ante): each respondent carries a proof of work signed
//! by their ante identity, bound to this poll and respondent key, and one ante identity counts as one respondent.
use ante_core::AnteProof;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use freenet_stdlib::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use whoiam_delegation::{check, Cert};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Response {
    pub ts: u64,
    pub answers_json: String,
    pub sig: String, // hex
    /// Open polls only: hex of the CBOR `AnteProof` for `vote_purpose`. Kept across answer updates (no new work).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub ante: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct FormState {
    pub schema_json: String,
    pub schema_sig: String, // hex, by the owner's delegated app key
    #[serde(default)]
    pub schema_cert: Option<Cert>, // the owner's delegation to that key
    pub responses: BTreeMap<String, Response>, // respondent pubkey hex -> response
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Summary {
    pub has_schema: bool,
    pub responses: BTreeMap<String, u64>, // pubkey -> ts
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Delta {
    pub schema: Option<(String, String, Cert)>, // (schema_json, sig, delegation)
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
pub const MIN_BITS: u32 = 18; // must match VOTE_BITS in ui/src/ante.ts

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

fn parse_schema(params: &str, schema_json: &str, sig: &str, cert: Option<&Cert>) -> R<Schema> {
    let raw = hex::decode(params).map_err(|e| e.to_string())?;
    let app = std::str::from_utf8(raw.get(48..).ok_or("params too short")?).map_err(|e| e.to_string())?;
    let app_key = check(&params[..64], app, cert.ok_or("schema without delegation")?)?;
    verify(&app_key, format!("fps1|{params}|{schema_json}").as_bytes(), sig)?;
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

/// What a respondent's ante proof commits to: this poll and this respondent key, not the answers.
pub fn vote_purpose(params: &str, who: &str) -> String {
    format!("freepolls:vote:v1:{params}:{who}")
}

/// Checks a response; for an open poll, returns the respondent's ante identity (hex).
fn check_response(params: &str, schema: &Schema, who: &str, r: &Response) -> R<Option<String>> {
    if schema.allowed.as_ref().is_some_and(|a| !a.iter().any(|k| k == who)) {
        return Err("respondent not invited".into());
    }
    let msg = format!("fpr1|{params}|{who}|{}|{}", r.ts, r.answers_json);
    verify(&key(who)?, msg.as_bytes(), &r.sig)?;
    check_answers(schema, &r.answers_json)?;
    if schema.allowed.is_some() {
        return Ok(None); // invite-only: the invite list already limits who answers
    }
    let proof: AnteProof = ante_core::from_cbor(&hex::decode(&r.ante).map_err(|e| e.to_string())?)?;
    if proof.purpose != vote_purpose(params, who) {
        return Err("ante proof is for another poll or respondent".into());
    }
    proof.verify(MIN_BITS).map_err(|e| e.to_string())?;
    Ok(Some(hex::encode(proof.identity_vk)))
}

/// The respondent (other than `who`) already counted for this ante identity, if any. State is already valid,
/// so its proofs are only decoded here, not verified again.
fn holder<'a>(s: &'a FormState, who: &str, ante: &str) -> Option<&'a String> {
    let id = |r: &Response| ante_core::from_cbor::<AnteProof>(&hex::decode(&r.ante).ok()?).ok().map(|p| hex::encode(p.identity_vk));
    s.responses.iter().find(|(k, r)| *k != who && id(r).as_deref() == Some(ante)).map(|(k, _)| k)
}

pub fn validate(params: &str, s: &FormState) -> R<()> {
    let schema = parse_schema(params, &s.schema_json, &s.schema_sig, s.schema_cert.as_ref())?;
    let mut seen = std::collections::BTreeSet::new();
    for (who, r) in &s.responses {
        if let Some(a) = check_response(params, &schema, who, r)? {
            if !seen.insert(a) {
                return Err("two respondents with one ante identity".into());
            }
        }
    }
    Ok(())
}

/// Merge a delta into state: schema is set once, per-respondent last-write-wins by ts.
pub fn apply(params: &str, s: &mut FormState, d: Delta) -> R<()> {
    if let Some((json, sig, cert)) = d.schema {
        if s.schema_json.is_empty() {
            parse_schema(params, &json, &sig, Some(&cert))?;
            s.schema_json = json;
            s.schema_sig = sig;
            s.schema_cert = Some(cert);
        }
    }
    let schema = parse_schema(params, &s.schema_json, &s.schema_sig, s.schema_cert.as_ref())?;
    for (who, r) in d.responses {
        if s.responses.get(&who).is_some_and(|old| old.ts >= r.ts) {
            continue;
        }
        if let Some(a) = check_response(params, &schema, &who, &r)? {
            // One respondent per ante identity; the smallest key wins, so every merge order converges.
            if let Some(other) = holder(s, &who, &a).cloned() {
                if other < who {
                    continue;
                }
                s.responses.remove(&other);
            }
        }
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
            .then(|| s.schema_cert.clone().map(|c| (s.schema_json.clone(), s.schema_sig.clone(), c)))
            .flatten(),
        responses: s
            .responses
            .iter()
            .filter(|(k, r)| sum.responses.get(*k).is_none_or(|&t| t < r.ts))
            .map(|(k, r)| (k.clone(), r.clone()))
            .collect(),
    }
}

// ---- Freenet glue ----

fn params_hex(p: &Parameters) -> Result<String, ContractError> {
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
        Ok(match validate(&params_hex(&parameters)?, &s) {
            Ok(()) => ValidateResult::Valid,
            Err(_) => ValidateResult::Invalid,
        })
    }

    fn update_state(
        parameters: Parameters<'static>,
        state: State<'static>,
        data: Vec<UpdateData<'static>>,
    ) -> Result<UpdateModification<'static>, ContractError> {
        let params = params_hex(&parameters)?;
        let mut s: FormState = de_or_default(state.as_ref())?;
        for u in data {
            let d: Delta = match u {
                UpdateData::State(st) => {
                    let other: FormState = de(st.as_ref())?;
                    Delta {
                        schema: other.schema_cert.filter(|_| !other.schema_json.is_empty()).map(|c| (other.schema_json, other.schema_sig, c)),
                        responses: other.responses,
                    }
                }
                UpdateData::Delta(d) => de(d.as_ref())?,
                UpdateData::StateAndDelta { delta, .. } => de(delta.as_ref())?,
                _ => return Err(ContractError::InvalidUpdate),
            };
            apply(&params, &mut s, d).map_err(|_| ContractError::InvalidUpdate)?;
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
    use whoiam_delegation::connect_message;

    const APP: &str = "/v1/contract/web/Polls1/";
    /// Poll parameters for owner `o`: persona || salt || app path.
    fn params(o: &SigningKey, salt: u8) -> String {
        format!("{}{}{}", pk(o), hex::encode([salt; 16]), hex::encode(APP))
    }
    /// The owner's schema, signed by an app key it delegated for `app`.
    fn schema_for(o: &SigningKey, params: &str, json: &str, app: &str) -> (String, String, Cert) {
        let app_key = sk(100);
        let (base, challenge) = (format!("http://127.0.0.1:7509{app}"), format!("wd1.{}.n1", pk(&app_key)));
        let csig = o.sign(&connect_message(o.verifying_key().as_bytes(), &base, &challenge, 1));
        let cert = Cert { base, challenge, ts: 1, sig: hex::encode(csig.to_bytes()) };
        (json.into(), hex::encode(app_key.sign(format!("fps1|{params}|{json}").as_bytes()).to_bytes()), cert)
    }
    fn schema(o: &SigningKey, params: &str, json: &str) -> (String, String, Cert) {
        schema_for(o, params, json, APP)
    }

    fn sk(n: u8) -> SigningKey {
        SigningKey::from_bytes(&[n; 32])
    }
    fn pk(k: &SigningKey) -> String {
        hex::encode(k.verifying_key().to_bytes())
    }
    const SCHEMA: &str = r#"{"questions":[{"id":"q1","kind":"single","options":["a","b"],"required":true}]}"#;

    /// A response with an ante proof from the ante identity `ante` (ignored by invite-only polls).
    fn resp_by(params: &str, who: &SigningKey, ante: &SigningKey, ts: u64, ans: &str) -> (String, Response) {
        let msg = format!("fpr1|{params}|{}|{ts}|{ans}", pk(who));
        let r = Response { ts, answers_json: ans.into(), sig: hex::encode(who.sign(msg.as_bytes()).to_bytes()), ante: proof(params, &pk(who), ante) };
        (pk(who), r)
    }
    fn resp(params: &str, who: &SigningKey, ts: u64, ans: &str) -> (String, Response) {
        resp_by(params, who, who, ts, ans)
    }

    /// Real 18-bit proofs are slow in debug builds: grind each (purpose, identity) once.
    fn proof(params: &str, who: &str, ante: &SigningKey) -> String {
        static CACHE: std::sync::Mutex<BTreeMap<String, String>> = std::sync::Mutex::new(BTreeMap::new());
        let (p, vk) = (vote_purpose(params, who), ante.verifying_key().to_bytes());
        CACHE.lock().unwrap().entry(format!("{p}|{}", hex::encode(vk))).or_insert_with(|| {
            let nonce = ante_core::pow::grind(&p, &vk, MIN_BITS).unwrap();
            hex::encode(ante_core::to_cbor(&AnteProof::create(ante, p.clone(), nonce, 1)))
        }).clone()
    }

    fn open_poll(o: &SigningKey) -> (String, FormState) {
        let op = params(o, 0xaa);
        let mut s = FormState::default();
        apply(&op, &mut s, Delta { schema: Some(schema(o, &op, SCHEMA)), ..Default::default() }).unwrap();
        (op, s)
    }

    /// The proof printed by ui/src/ante.test.ts (same purpose, key 7s, nonce ground there): the contract accepts it.
    #[test]
    fn a_proof_made_by_the_ui_code_verifies() {
        let ui = "a56b6964656e746974795f766b982018ea184a186c186318e2189c18520a18be18f51850187b13182e18c518f918951847187618ae18be18be187b18921842181e18ea186914184618d2182c67707572706f736578b366726565706f6c6c733a766f74653a76313a6162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261623a63646364636463646364636463646364636463646364636463646364636463646364636463646364636463646364636463646364636463646364636463646364656e6f6e63651a0003fdfb6274731b0000018bcfe56800697369676e61747572659840189318ae186018fa071843185f18e418bc18f918a718e11418c618ff18d518e018801848189a181f18cd18c90718b3186c18fe18b0181e071857182b185a1899182c18d9151838187b1831186a183218b318ed18ae18ac18a118f6183c18b9187f182a1899184018db18d9186118d618b6186b183a18e2189b0a";
        let p: AnteProof = ante_core::from_cbor(&hex::decode(ui).unwrap()).unwrap();
        assert_eq!(p.purpose, vote_purpose(&"ab".repeat(48), &"cd".repeat(32)));
        p.verify(MIN_BITS).unwrap();
    }

    #[test]
    fn open_polls_need_ante() {
        let (op, mut s) = open_poll(&sk(1));
        // no proof, or a proof made for another respondent, is refused
        let (k, mut bare) = resp(&op, &sk(2), 1, r#"{"q1":0}"#);
        bare.ante.clear();
        assert!(apply(&op, &mut s, Delta { responses: [(k.clone(), bare)].into(), ..Default::default() }).is_err());
        let (_, mut stolen) = resp(&op, &sk(2), 1, r#"{"q1":0}"#);
        stolen.ante = proof(&op, &pk(&sk(3)), &sk(2));
        assert!(apply(&op, &mut s, Delta { responses: [(k, stolen)].into(), ..Default::default() }).is_err());

        // one ante identity = one respondent, whatever the merge order: the smaller respondent key wins
        let a = sk(9);
        let (k2, r2) = resp_by(&op, &sk(2), &a, 1, r#"{"q1":0}"#);
        let (k3, r3) = resp_by(&op, &sk(3), &a, 1, r#"{"q1":1}"#);
        let (mut x, mut y) = (s.clone(), s.clone());
        apply(&op, &mut x, Delta { responses: [(k2.clone(), r2.clone())].into(), ..Default::default() }).unwrap();
        apply(&op, &mut x, Delta { responses: [(k3.clone(), r3.clone())].into(), ..Default::default() }).unwrap();
        apply(&op, &mut y, Delta { responses: [(k3, r3)].into(), ..Default::default() }).unwrap();
        apply(&op, &mut y, Delta { responses: [(k2, r2)].into(), ..Default::default() }).unwrap();
        assert_eq!(x, y);
        assert_eq!(x.responses.len(), 1);
        validate(&op, &x).unwrap();

        // changing the answer reuses the proof
        let k = x.responses.keys().next().unwrap().clone();
        let who = if k == pk(&sk(2)) { sk(2) } else { sk(3) };
        let (_, newer) = resp_by(&op, &who, &a, 5, r#"{"q1":1}"#);
        apply(&op, &mut x, Delta { responses: [(k.clone(), newer)].into(), ..Default::default() }).unwrap();
        assert_eq!(x.responses[&k].ts, 5);
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
        let op = params(&o, 0xaa);
        let (invited, stranger) = (sk(2), sk(3));
        let schema = format!(
            r#"{{"questions":[{{"id":"q1","kind":"single","options":["a","b"],"required":true}}],"allowed":["{}"]}}"#,
            pk(&invited)
        );
        let mut s = FormState::default();
        let (k, r) = resp(&op, &invited, 1, r#"{"q1":0}"#);
        apply(&op, &mut s, Delta { schema: Some(self::schema(&o, &op, &schema)), responses: [(k, r)].into() }).unwrap();
        validate(&op, &s).unwrap();
        let (k2, r2) = resp(&op, &stranger, 1, r#"{"q1":0}"#);
        assert!(apply(&op, &mut s, Delta { responses: [(k2, r2)].into(), ..Default::default() }).is_err());

        // malformed invite key rejected at schema level
        let bad = r#"{"questions":[],"allowed":["zz"]}"#;
        let (_, bad_sig, cert) = self::schema(&o, &op, bad);
        assert!(parse_schema(&op, bad, &bad_sig, Some(&cert)).is_err());
    }

    #[test]
    fn salted_params_bind_everything() {
        let o = sk(1);
        let (params_a, params_b) = (params(&o, 0xaa), params(&o, 0xbb));
        let (_, sig_a, cert) = schema(&o, &params_a, SCHEMA);
        // valid for its own params, rejected under the same owner's other poll (no cloning of signed schemas)
        parse_schema(&params_a, SCHEMA, &sig_a, Some(&cert)).unwrap();
        assert!(parse_schema(&params_b, SCHEMA, &sig_a, Some(&cert)).is_err());
        // no delegation, another persona, or a delegation for another app: refused
        assert!(parse_schema(&params_a, SCHEMA, &sig_a, None).is_err());
        let stranger = params(&sk(7), 0xaa);
        assert!(parse_schema(&stranger, SCHEMA, &sig_a, Some(&cert)).is_err());
        let (_, sig_x, other_app) = schema_for(&o, &params_a, SCHEMA, "/v1/contract/web/Other/");
        assert!(parse_schema(&params_a, SCHEMA, &sig_x, Some(&other_app)).is_err());
        // answers are bound to the poll too
        let mut s = FormState::default();
        let d = Delta { schema: Some((SCHEMA.into(), sig_a, cert)), ..Default::default() };
        apply(&params_a, &mut s, d).unwrap();
        let (k, r) = resp(&params_b, &sk(2), 1, r#"{"q1":0}"#);
        assert!(apply(&params_a, &mut s, Delta { responses: [(k, r)].into(), ..Default::default() }).is_err());
        assert!(parse_schema("abcd", SCHEMA, "00", None).is_err()); // too short
    }

    #[test]
    fn merge_flow() {
        let o = sk(1);
        let op = params(&o, 0xaa);
        let mut s = FormState::default();
        let mut d = Delta { schema: Some(schema(&o, &op, SCHEMA)), ..Default::default() };
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
        let (k4, other_form) = resp(&params(&sk(9), 1), &sk(4), 1, r#"{"q1":0}"#);
        assert!(apply(&op, &mut s, Delta { responses: [(k4, other_form)].into(), ..Default::default() }).is_err());

        // delta vs summary
        let d = delta(&s, &Summary::default());
        assert!(d.schema.is_some() && d.responses.len() == 1);
        assert!(delta(&s, &summarize(&s)).responses.is_empty());
    }
}
