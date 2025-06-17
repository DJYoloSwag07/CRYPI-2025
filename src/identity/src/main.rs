
use std::{
    fs,
    io::{self, Write},
    path::PathBuf,
    process::Command as SysCommand,
    cmp::Ordering,
    collections::HashMap,
};

use anyhow::{Result, bail, anyhow};
use ark_bn254::{Bn254, Fr};
use ark_ff::{Zero, One, PrimeField};
use ark_r1cs_std::{
    alloc::AllocVar,
    fields::fp::FpVar,
    fields::FieldVar,
    eq::EqGadget,
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_groth16::{Groth16, ProvingKey, VerifyingKey};
use ark_snark::SNARK;
use arkworks_native_gadgets::poseidon::{
    Poseidon, PoseidonParameters, sbox::PoseidonSbox, FieldHasher,
};
use arkworks_r1cs_gadgets::poseidon::{PoseidonGadget, FieldHasherGadget};
use arkworks_utils::{
    bytes_matrix_to_f, bytes_vec_to_f, poseidon_params::setup_poseidon_params, Curve,
};
use clap::Parser;
use fern;
use log::{debug, info, warn};
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use serde_json;
use url::Url;
use chrono::{Datelike, Utc, Local};
use dirs;
use hex;

// Initialize logging: console + file
fn init_logging() -> Result<()> {
    let home = dirs::home_dir().ok_or_else(|| anyhow!("Cannot determine home directory"))?;
    let log_dir = home.join(".identity");
    fs::create_dir_all(&log_dir)?;
    let log_file = log_dir.join("identity.log");

    fern::Dispatch::new()
        .format(|out, message, record| {
            out.finish(format_args!("[{date}][{level}] {msg}",
                date = Local::now().format("%Y-%m-%d %H:%M:%S"),
                level = record.level(),
                msg = message))
        })
        .level(log::LevelFilter::Debug)
        .chain(std::io::stderr())
        .chain(fern::log_file(log_file)?)
        .apply()?;
    info!("Logging initialized");
    Ok(())
}

// Poseidon params helper unchanged
fn poseidon() -> Poseidon<Fr> {
    let data = setup_poseidon_params(Curve::Bn254, 5, 3).unwrap();
    let params = PoseidonParameters {
        mds_matrix: bytes_matrix_to_f(&data.mds),
        round_keys:  bytes_vec_to_f(&data.rounds),
        full_rounds: data.full_rounds,
        partial_rounds: data.partial_rounds,
        sbox:        PoseidonSbox(data.exp),
        width:       data.width,
    };
    Poseidon::new(params)
}



// Circuit definition
pub struct IdentityCircuit {
    // Private identity data
    pub dob: Fr,
    pub license: Fr,
    pub nonce: Fr,
    pub expiration: Fr,
    pub first_name: Fr,
    pub last_name: Fr,

    // Public inputs (in this fixed order!)
    pub commitment: Fr,
    pub req_fname_flag: Fr,   // 0 or 1
    pub req_fname_val: Fr,
    pub req_lname_flag: Fr,
    pub req_lname_val: Fr,
    pub dob_before_flag: Fr,
    pub dob_before_val: Fr,
    pub dob_after_flag: Fr,
    pub dob_after_val: Fr,
    pub dob_equal_flag: Fr,
    pub dob_equal_val: Fr,
    pub req_license_flag: Fr,
    pub req_license_val: Fr,
}


impl ConstraintSynthesizer<Fr> for IdentityCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // witness allocations
        let dob_v = FpVar::new_witness(cs.clone(), || Ok(self.dob))?;
        let lic_v = FpVar::new_witness(cs.clone(), || Ok(self.license))?;
        let nonce_v = FpVar::new_witness(cs.clone(), || Ok(self.nonce))?;
        let exp_v = FpVar::new_witness(cs.clone(), || Ok(self.expiration))?;
        let fname_v = FpVar::new_witness(cs.clone(), || Ok(self.first_name))?;
        let lname_v = FpVar::new_witness(cs.clone(), || Ok(self.last_name))?;

        // recompute commitment
        let gadget = PoseidonGadget::<Fr>::from_native(&mut cs.clone(), poseidon())?;
        let r1 = gadget.hash(&[dob_v.clone(), lic_v.clone()])?;
        let r2 = gadget.hash(&[exp_v.clone(), nonce_v.clone()])?;
        let mid = gadget.hash(&[r1, r2])?;
        let h1 = gadget.hash(&[mid, fname_v.clone()])?;
        let final_hash = gadget.hash(&[h1, lname_v.clone()])?;

        // public: commitment
        let com_input = FpVar::new_input(cs.clone(), || Ok(self.commitment))?;
        com_input.enforce_equal(&final_hash)?;

        // always check expiration > today
        let today_days = Fr::from(chrono::Utc::now().num_days_from_ce() as u64);
        let today_v = FpVar::constant(today_days);
        exp_v.enforce_cmp(&today_v, Ordering::Greater, true)?;

        // now allocate all flags and values as public inputs
        let f_flag = FpVar::new_input(cs.clone(), || Ok(self.req_fname_flag))?;
        let f_val  = FpVar::new_input(cs.clone(), || Ok(self.req_fname_val))?;
        let l_flag = FpVar::new_input(cs.clone(), || Ok(self.req_lname_flag))?;
        let l_val  = FpVar::new_input(cs.clone(), || Ok(self.req_lname_val))?;
        let db_flag = FpVar::new_input(cs.clone(), || Ok(self.dob_before_flag))?;
        let db_val  = FpVar::new_input(cs.clone(), || Ok(self.dob_before_val))?;
        let da_flag = FpVar::new_input(cs.clone(), || Ok(self.dob_after_flag))?;
        let da_val  = FpVar::new_input(cs.clone(), || Ok(self.dob_after_val))?;
        let de_flag = FpVar::new_input(cs.clone(), || Ok(self.dob_equal_flag))?;
        let de_val  = FpVar::new_input(cs.clone(), || Ok(self.dob_equal_val))?;
        let r_flag = FpVar::new_input(cs.clone(), || Ok(self.req_license_flag))?;
        let r_val  = FpVar::new_input(cs.clone(), || Ok(self.req_license_val))?;

        // gated equality: (val - witness) * flag == 0
        let diff_fname = f_val.clone() - fname_v.clone();
        (diff_fname * f_flag.clone()).enforce_equal(&FpVar::constant(Fr::zero()))?;

        let diff_lname = l_val.clone() - lname_v.clone();
        (diff_lname * l_flag.clone()).enforce_equal(&FpVar::constant(Fr::zero()))?;

        let diff_lic = r_val.clone() - lic_v.clone();
        (diff_lic * r_flag.clone()).enforce_equal(&FpVar::constant(Fr::zero()))?;

        // gated comparisons using "big M" trick for < and >
        // choose M large (e.g. max days-since-CE)
        let max_days = Fr::from(u64::MAX);
        // effective before threshold = db_val * db_flag + max_days * (1 - db_flag)
        let one = FpVar::constant(Fr::one());
        let threshold_before = (db_val.clone() * db_flag.clone())
            + (FpVar::constant(max_days) * (one.clone() - db_flag.clone()));
        dob_v.enforce_cmp(&threshold_before, Ordering::Less, true)?;

        // effective after threshold = da_val * da_flag
        let threshold_after = da_val.clone() * da_flag.clone();
        dob_v.enforce_cmp(&threshold_after, Ordering::Greater, true)?;

        // gated equality for dob_equal
        let diff_eq = de_val.clone() - dob_v.clone();
        (diff_eq * de_flag.clone()).enforce_equal(&FpVar::constant(Fr::zero()))?;

        Ok(())
    }
}


#[derive(Serialize, Deserialize, Debug)]
pub struct IdentityData {
    dob: u64,
    license: u64,
    nonce: u64,
    first_name: String,
    last_name: String,
    expiration: u64,
}

fn hex_serialize_fr(f: &Fr) -> String {
    let mut buf = Vec::new();
    f.serialize(&mut buf).unwrap();
    hex::encode(buf)
}

fn ask_confirmation(origin: &str, checks: &[String]) -> Result<bool> {
    info!("Asking user confirmation for origin {}", origin);
    let mut msg = format!("{} is requesting:\n", origin);
    for c in checks { msg.push_str(&format!("  • {}\n", c)); }
    msg.push_str("\nProceed?");
    if let Ok(status) = SysCommand::new("zenity").arg("--question").arg("--text").arg(&msg).status() {
        info!("Zenity prompt status: {}", status.success());
        return Ok(status.success());
    }
    warn!("Zenity not available, falling back to CLI");
    eprintln!("{}\n(y/N): ", msg);
    io::stdout().flush()?;
    let mut buf = String::new(); io::stdin().read_line(&mut buf)?;
    let consent = buf.trim().eq_ignore_ascii_case("y");
    info!("User CLI response: {}", consent);
    Ok(consent)
}

fn load_or_generate_keys(home: &PathBuf) -> Result<(ProvingKey<Bn254>, VerifyingKey<Bn254>)> {
    info!("Loading or generating SNARK keys in {}", home.join(".identity").display());
    let sk_path = home.join(".identity/proving.key");
    let vk_path = home.join(".identity/verification.key");
    if sk_path.exists() && vk_path.exists() {
        info!("Found existing keys, loading");
        let pk_bytes = fs::read(&sk_path)?; let mut pk_slice = pk_bytes.as_slice();
        let pk = ProvingKey::<Bn254>::deserialize(&mut pk_slice)?;
        let vk_bytes = fs::read(&vk_path)?; let mut vk_slice = vk_bytes.as_slice();
        let vk = VerifyingKey::<Bn254>::deserialize(&mut vk_slice)?;
        return Ok((pk, vk));
    }
    info!("Keys not found, performing setup");
    let blank = IdentityCircuit {
        dob: Fr::zero(),
        license: Fr::zero(),
        nonce: Fr::zero(),
        expiration: Fr::zero(),
        first_name: Fr::zero(),
        last_name: Fr::zero(),
        commitment: Fr::zero(),

        req_fname_flag: Fr::zero(),
        req_fname_val:  Fr::zero(),
        req_lname_flag: Fr::zero(),
        req_lname_val:  Fr::zero(),
        dob_before_flag: Fr::zero(),
        dob_before_val:  Fr::zero(),
        dob_after_flag:  Fr::zero(),
        dob_after_val:   Fr::zero(),
        dob_equal_flag:  Fr::zero(),
        dob_equal_val:   Fr::zero(),
        req_license_flag: Fr::zero(),
        req_license_val:  Fr::zero(),
    };

    let mut rng = thread_rng();
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(blank, &mut rng)?;
    fs::create_dir_all(home.join(".identity"))?;
    fs::write(&sk_path, &{ let mut buf = Vec::new(); pk.serialize(&mut buf)?; buf })?;
    fs::write(&vk_path, &{ let mut buf = Vec::new(); vk.serialize(&mut buf)?; buf })?;
    info!("Generated new SNARK keys");
    Ok((pk, vk))
}
// Proof generation flow
fn run_prove(uri: &str) -> Result<()> {
    info!("run_prove called with URI: {}", uri);
    let url = Url::parse(uri).map_err(|e| anyhow!(format!("URL parse error `{}`: {}", uri, e)))?;
    let mut origin = String::new();
    let mut checks = Vec::new();
    let mut req_fname: Option<String> = None;
    let mut req_lname: Option<String> = None;
    let mut dob_before: Option<u64> = None;
    let mut dob_after: Option<u64> = None;
    let mut dob_equal: Option<u64> = None;
    let mut req_license: Option<u64> = None;

    for (k, v) in url.query_pairs() {
        match &*k {
            "origin" => { origin = v.into_owned(); info!("Parsed origin: {}", origin); }
            "first_name" => {
                let val = v.into_owned(); req_fname = Some(val.clone()); checks.push(format!("first_name == {}", val));
                debug!("Parsed first_name constraint: {}", val);
            }
            "last_name" => {
                let val = v.into_owned(); req_lname = Some(val.clone()); checks.push(format!("last_name == {}", val));
                debug!("Parsed last_name constraint: {}", val);
            }
            "dob_before" => {
                let n = v.parse()?; dob_before = Some(n); checks.push(format!("dob_before {}", n));
                debug!("Parsed dob_before constraint: {}", n);
            }
            "dob_after" => {
                let n = v.parse()?; dob_after = Some(n); checks.push(format!("dob_after {}", n));
                debug!("Parsed dob_after constraint: {}", n);
            }
            "dob_equal" => {
                let n = v.parse()?; dob_equal = Some(n); checks.push(format!("dob_equal {}", n));
                debug!("Parsed dob_equal constraint: {}", n);
            }
            "license" => {
                let n = v.parse()?; req_license = Some(n); checks.push(format!("license == {}", n));
                debug!("Parsed license constraint: {}", n);
            }
            _ => { debug!("Ignoring unknown query parameter: {}", k); }
        }
    }
    if origin.is_empty() { bail!("`origin` param missing"); }

    if !ask_confirmation(&origin, &checks)? {
        warn!("User cancelled proof generation");
        eprintln!("▶ Cancelled by user");
        std::process::exit(1);
    }

    let home = dirs::home_dir().expect("no home dir");
    let id_path = home.join(".identity/identity.json");
    let id_json = if id_path.exists() {
        info!("Loading existing identity.json from {}", id_path.display());
        fs::read_to_string(&id_path)?
    } else {
        info!("Prompting user for path to identity.json");
        print!("path to your identity.json: "); io::stdout().flush()?;
        let mut input = String::new(); io::stdin().read_line(&mut input)?;
        let p = PathBuf::from(input.trim());
        let s = fs::read_to_string(&p)?;
        fs::create_dir_all(home.join(".identity"))?;
        fs::write(&id_path, &s)?;
        info!("Copied identity.json to {}", id_path.display());
        s
    };
    let identity: IdentityData = serde_json::from_str(&id_json)?;
    debug!("Loaded identity data: {:?}", identity);

    // Local checks before SNARK
    info!("Performing local checks before SNARK");
    let today_days = Utc::now().num_days_from_ce() as u64;
    if identity.expiration < today_days {
        bail!("Identity has expired (expiration: {}, today: {})", identity.expiration, today_days);
    }
    if let Some(ref fn_req) = req_fname {
        if identity.first_name != *fn_req {
            bail!("First name mismatch: required '{}' but found '{}'", fn_req, identity.first_name);
        }
    }
    if let Some(ref ln_req) = req_lname {
        if identity.last_name != *ln_req {
            bail!("Last name mismatch: required '{}' but found '{}'", ln_req, identity.last_name);
        }
    }
    if let Some(b) = dob_before {
        if identity.dob >= b {
            bail!("DOB check failed: {} is not before {}", identity.dob, b);
        }
    }
    if let Some(a) = dob_after {
        if identity.dob <= a {
            bail!("DOB check failed: {} is not after {}", identity.dob, a);
        }
    }
    if let Some(e) = dob_equal {
        if identity.dob != e {
            bail!("DOB check failed: {} is not equal to {}", identity.dob, e);
        }
    }
    if let Some(l_req) = req_license {
        if identity.license != l_req {
            bail!("License mismatch: required {} but found {}", l_req, identity.license);
        }
    }

    let (pk, _vk) = load_or_generate_keys(&home)?;

    // 1) re‐compute the Poseidon commitment and bind it to `com`
    let p_native = poseidon();
    let r1  = p_native.hash(&[Fr::from(identity.dob),       Fr::from(identity.license)])?;
    let r2  = p_native.hash(&[Fr::from(identity.expiration), Fr::from(identity.nonce)])?;
    let mid = p_native.hash(&[r1, r2])?;
    let h1  = p_native.hash(&[mid, Fr::from_le_bytes_mod_order(identity.first_name.as_bytes())])?;
    let com = p_native.hash(&[h1, Fr::from_le_bytes_mod_order(identity.last_name.as_bytes())])?;


    // Build circuit and generate proof
    info!("Building circuit and generating proof");
    let mut circuit = IdentityCircuit {
        // ─ witnesses ────────────────
        dob:         Fr::from(identity.dob),
        license:     Fr::from(identity.license),
        nonce:       Fr::from(identity.nonce),
        expiration:  Fr::from(identity.expiration),
        first_name:  Fr::from_le_bytes_mod_order(identity.first_name.as_bytes()),
        last_name:   Fr::from_le_bytes_mod_order(identity.last_name.as_bytes()),

        // ─ public inputs ───────────
        commitment: com,

        // first‐name
        req_fname_flag: if req_fname.is_some() { Fr::one() } else { Fr::zero() },
        req_fname_val:  req_fname
                           .as_ref()
                           .map(|s| Fr::from_le_bytes_mod_order(s.as_bytes()))
                           .unwrap_or_else(Fr::zero),

        // last‐name
        req_lname_flag: if req_lname.is_some() { Fr::one() } else { Fr::zero() },
        req_lname_val:  req_lname
                           .as_ref()
                           .map(|s| Fr::from_le_bytes_mod_order(s.as_bytes()))
                           .unwrap_or_else(Fr::zero),

        // dob_before
        dob_before_flag: if dob_before.is_some() { Fr::one() } else { Fr::zero() },
        dob_before_val:  dob_before.map(Fr::from).unwrap_or_else(Fr::zero),

        // dob_after
        dob_after_flag: if dob_after.is_some() { Fr::one() } else { Fr::zero() },
        dob_after_val:  dob_after.map(Fr::from).unwrap_or_else(Fr::zero),

        // dob_equal
        dob_equal_flag: if dob_equal.is_some() { Fr::one() } else { Fr::zero() },
        dob_equal_val:  dob_equal.map(Fr::from).unwrap_or_else(Fr::zero),

        // license
        req_license_flag: if req_license.is_some() { Fr::one() } else { Fr::zero() },
        req_license_val:  req_license.map(Fr::from).unwrap_or_else(Fr::zero),
    };
    let p_native = poseidon();
    let r1 = p_native.hash(&[Fr::from(identity.dob), Fr::from(identity.license)])?;
    let r2 = p_native.hash(&[Fr::from(identity.expiration), Fr::from(identity.nonce)])?;
    let mid = p_native.hash(&[r1, r2])?;
    let h1 = p_native.hash(&[mid, Fr::from_le_bytes_mod_order(identity.first_name.as_bytes())])?;
    let com = p_native.hash(&[h1, Fr::from_le_bytes_mod_order(identity.last_name.as_bytes())])?;
    circuit.commitment = com;
    let proof = Groth16::prove(&pk, circuit, &mut thread_rng())?;
    info!("Proof successfully generated");

    let mut cb_url = Url::parse(&origin)?;
    {
        let mut qp = cb_url.query_pairs_mut();
        qp.append_pair("proof", &hex::encode({ let mut buf = Vec::new(); proof.serialize(&mut buf)?; buf }));
        qp.append_pair("commitment", &hex_serialize_fr(&com));
        if let Some(ref fn_req) = req_fname { qp.append_pair("first_name", fn_req); }
        if let Some(ref ln_req) = req_lname { qp.append_pair("last_name", ln_req); }
        if let Some(b) = dob_before { qp.append_pair("dob_before", &b.to_string()); }
        if let Some(a) = dob_after { qp.append_pair("dob_after", &a.to_string()); }
        if let Some(e) = dob_equal { qp.append_pair("dob_equal", &e.to_string()); }
        if let Some(l) = req_license { qp.append_pair("license", &l.to_string()); }
    }
    info!("Invoking callback URL: {}", cb_url.as_str());
    SysCommand::new("xdg-open").arg(cb_url.as_str()).status()?;
    Ok(())
}

// Verification flow
fn run_verify(uri: &str) -> Result<()> {
    info!("run_verify called with URI: {}", uri);
    let url = Url::parse(uri).map_err(|e| anyhow!(format!("URL parse error `{}`: {}", uri, e)))?;
    let params: HashMap<String, String> = url.query_pairs().into_owned().collect();
    debug!("Verification parameters: {:?}", params);

    let proof_hex = params.get("proof").ok_or_else(|| anyhow!("`proof` param missing"))?;
    let commitment_hex = params.get("commitment").ok_or_else(|| anyhow!("`commitment` param missing"))?;
    let req_fname = params.get("first_name").cloned();
    let req_lname = params.get("last_name").cloned();
    let dob_before: Option<u64> =
        params.get("dob_before").and_then(|v| v.parse::<u64>().ok());
    let dob_after: Option<u64> =
        params.get("dob_after").and_then(|v| v.parse::<u64>().ok());
    let dob_equal: Option<u64> =
        params.get("dob_equal").and_then(|v| v.parse::<u64>().ok());
    let req_license: Option<u64> =
        params.get("license").and_then(|v| v.parse::<u64>().ok());

    let home = dirs::home_dir().expect("no home dir");
    let vk_path = home.join(".identity/verification.key");
    info!("Loading verification key from {}", vk_path.display());
    // let vk_bytes = fs::read(&vk_path)?;
    // let mut vk_slice = vk_bytes.as_slice();
    // let vk = VerifyingKey::<Bn254>::deserialize(&mut vk_slice)?;
    let (_pk, vk) = load_or_generate_keys(&home)?;

    let proof_bytes = hex::decode(proof_hex)?;
    let mut proof_slice = proof_bytes.as_slice();
    let proof = ark_groth16::Proof::<Bn254>::deserialize(&mut proof_slice)?;
    let com_bytes = hex::decode(commitment_hex)?;
    let mut com_slice = com_bytes.as_slice();
    let commitment_fr = Fr::deserialize(&mut com_slice)?;

    // after parsing: req_fname, req_lname, dob_before, dob_after, dob_equal, req_license
    let zero = Fr::zero();
    let one  = Fr::one();

    // flags and values, in exactly the same order your circuit expects:
    let pf = if req_fname.is_some() { one } else { zero };
    let pv = req_fname
        .as_ref()
        .map(|s| Fr::from_le_bytes_mod_order(s.as_bytes()))
        .unwrap_or(zero);

    let lf = if req_lname.is_some() { one } else { zero };
    let lv = req_lname
        .as_ref()
        .map(|s| Fr::from_le_bytes_mod_order(s.as_bytes()))
        .unwrap_or(zero);

    let dbf = if let Some(b) = dob_before { one } else { zero };
    let dbv = dob_before.map(Fr::from).unwrap_or(zero);

    let daf = if let Some(a) = dob_after { one } else { zero };
    let dav = dob_after.map(Fr::from).unwrap_or(zero);

    let def = if let Some(e) = dob_equal { one } else { zero };
    let dev = dob_equal.map(Fr::from).unwrap_or(zero);

    let rf  = if let Some(l) = req_license { one } else { zero };
    let rv  = req_license.map(Fr::from).unwrap_or(zero);

    // now assemble in the *exact* same sequence*:
    let public_inputs = vec![
        commitment_fr,
        pf, pv,
        lf, lv,
        dbf, dbv,
        daf, dav,
        def, dev,
        rf, rv,
    ];

    let verified = Groth16::<Bn254>::verify(&vk, &public_inputs, &proof)?;
    // let verified = Groth16::<Bn254>::verify(&vk, &[commitment_fr], &proof)?;
    info!("Proof verified: {}", verified);

    let mut validated = serde_json::Map::new();
    if let Some(v) = req_fname { validated.insert("first_name".to_string(), serde_json::json!(v)); }
    if let Some(v) = req_lname { validated.insert("last_name".to_string(), serde_json::json!(v)); }
    if let Some(v) = dob_before { validated.insert("dob_before".to_string(), serde_json::json!(v)); }
    if let Some(v) = dob_after { validated.insert("dob_after".to_string(), serde_json::json!(v)); }
    if let Some(v) = dob_equal { validated.insert("dob_equal".to_string(), serde_json::json!(v)); }
    if let Some(v) = req_license { validated.insert("license".to_string(), serde_json::json!(v)); }

    let result = serde_json::json!({
        "verified": verified,
        "validated": validated,
    });
    info!("Verification result: {}", result);
    println!("{}", result.to_string());
    Ok(())
}

#[derive(Parser, Debug)]
#[command(name = "identity")]
struct Cli {
    /// The identity:// URI for proving or verifying
    uri: String,
}

fn main() -> Result<()> {
    init_logging()?;
    info!("Starting Identity application");

    let args = Cli::parse();
    info!("Parsed CLI args: {:?}", args);

    let url = Url::parse(&args.uri).map_err(|e| anyhow!(format!("URL parse error `{}`: {}", args.uri, e)))?;
    let params: Vec<String> = url.query_pairs().map(|(k,_)| k.into_owned()).collect();

    if params.contains(&"proof".to_string()) && params.contains(&"commitment".to_string()) {
        run_verify(&args.uri)
    } else {
        run_prove(&args.uri)
    }
}
