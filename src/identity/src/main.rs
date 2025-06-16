use std::{
    fs,
    io::{self, Write},
    path::PathBuf,
    process::Command as SysCommand,
    cmp::Ordering,
};
use anyhow::{Result, bail};
use ark_bn254::{Bn254, Fr};
use ark_ff::{PrimeField, Zero};
use ark_r1cs_std::{
    alloc::AllocVar,
    fields::fp::FpVar,
    fields::FieldVar,
    eq::EqGadget,
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use arkworks_native_gadgets::poseidon::{
    Poseidon, PoseidonParameters, sbox::PoseidonSbox, FieldHasher,
};
use arkworks_r1cs_gadgets::poseidon::{PoseidonGadget, FieldHasherGadget};
use arkworks_utils::{
    bytes_matrix_to_f, bytes_vec_to_f, poseidon_params::setup_poseidon_params, Curve,
};
use clap::Parser;
use hex;
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use url::Url;
use chrono::{Datelike, Utc};
use ark_groth16::{Groth16, ProvingKey, VerifyingKey};
use dirs;

// Poseidon parameters helper
fn poseidon() -> Poseidon<Fr> {
    let data = setup_poseidon_params(Curve::Bn254, 5, 3).unwrap();
    let params = PoseidonParameters { 
        mds_matrix: bytes_matrix_to_f(&data.mds),
        round_keys: bytes_vec_to_f(&data.rounds),
        full_rounds: data.full_rounds,
        partial_rounds: data.partial_rounds,
        sbox: PoseidonSbox(data.exp),
        width: data.width,
    };
    Poseidon::new(params)
}

// Circuit
pub struct IdentityCircuit {
    dob: Option<Fr>,
    license: Option<Fr>,
    nonce: Option<Fr>,
    expiration: Option<Fr>,
    first_name: Option<Fr>,
    last_name: Option<Fr>,
    commitment: Fr,
    required_fname: Option<Fr>,
    required_lname: Option<Fr>,
    dob_before: Option<Fr>,
    dob_after: Option<Fr>,
    dob_equal: Option<Fr>,
    required_license: Option<Fr>,
}

impl ConstraintSynthesizer<Fr> for IdentityCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // Allocate witnesses
        let dob_v = FpVar::new_witness(cs.clone(), || Ok(self.dob.unwrap()))?;
        let lic_v = FpVar::new_witness(cs.clone(), || Ok(self.license.unwrap()))?;
        let nonce_v = FpVar::new_witness(cs.clone(), || Ok(self.nonce.unwrap()))?;
        let exp_v = FpVar::new_witness(cs.clone(), || Ok(self.expiration.unwrap()))?;
        let fname_v = FpVar::new_witness(cs.clone(), || Ok(self.first_name.unwrap()))?;
        let lname_v = FpVar::new_witness(cs.clone(), || Ok(self.last_name.unwrap()))?;

        // Poseidon hashing layers
        let gadget = PoseidonGadget::<Fr>::from_native(&mut cs.clone(), poseidon())?;
        let r1 = gadget.hash(&[dob_v.clone(), lic_v.clone()])?;
        let r2 = gadget.hash(&[exp_v.clone(), nonce_v.clone()])?;
        let mid = gadget.hash(&[r1, r2])?;
        let h1 = gadget.hash(&[mid, fname_v.clone()])?;
        let final_hash = gadget.hash(&[h1, lname_v.clone()])?;

        // Enforce public commitment
        let com_input = FpVar::new_input(cs.clone(), || Ok(self.commitment))?;
        com_input.enforce_equal(&final_hash)?;

        // Always enforce expiration >= today
        let today_days = Fr::from(Utc::now().num_days_from_ce() as u64);
        let today_v = FpVar::constant(today_days);
        exp_v.enforce_cmp(&today_v, Ordering::Greater, true)?; // inclusive => >=

        // Additional parameterized checks
        if let Some(f) = self.required_fname { FpVar::constant(f).enforce_equal(&fname_v)?; }
        if let Some(l) = self.required_lname { FpVar::constant(l).enforce_equal(&lname_v)?; }
        if let Some(b) = self.dob_before   { dob_v.enforce_cmp(&FpVar::constant(b), Ordering::Less, true)?; }
        if let Some(a) = self.dob_after    { dob_v.enforce_cmp(&FpVar::constant(a), Ordering::Greater, true)?; }
        if let Some(e) = self.dob_equal    { dob_v.enforce_equal(&FpVar::constant(e))?; }
        if let Some(rl) = self.required_license { lic_v.enforce_equal(&FpVar::constant(rl))?; }

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
    let mut msg = format!("{} is requesting:\n", origin);
    for c in checks { msg.push_str(&format!("  • {}\n", c)); }
    msg.push_str("\nProceed?");
    if let Ok(status) = SysCommand::new("zenity").arg("--question").arg("--text").arg(&msg).status() {
        return Ok(status.success());
    }
    eprintln!("{}\n(y/N): ", msg);
    io::stdout().flush()?;
    let mut buf = String::new();
    io::stdin().read_line(&mut buf)?;
    Ok(buf.trim().eq_ignore_ascii_case("y"))
}

#[derive(Parser)]
#[command(name = "identity")]
struct Cli { uri: String }

fn main() -> Result<()> {
    eprintln!("▶ Starting identity prover");
    let args = Cli::parse();
    eprintln!("▶ Raw URI: {}", args.uri);
    let url = Url::parse(&args.uri)
        .map_err(|e| anyhow::anyhow!("URL parse error `{}`: {}", args.uri, e))?;

    // Parse query parameters
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
            "origin"     => origin = v.into_owned(),
            "first_name" => { let val = v.clone().into_owned(); req_fname = Some(val.clone()); checks.push(format!("first_name == {}", val)); }
            "last_name"  => { let val = v.clone().into_owned(); req_lname = Some(val.clone()); checks.push(format!("last_name == {}", val)); }
            "dob_before" => { let n = v.parse()?; dob_before = Some(n); checks.push(format!("dob_before {}", n)); }
            "dob_after"  => { let n = v.parse()?; dob_after = Some(n); checks.push(format!("dob_after {}", n)); }
            "dob_equal"  => { let n = v.parse()?; dob_equal = Some(n); checks.push(format!("dob_equal {}", n)); }
            "license"    => { let n = v.parse()?; req_license = Some(n); checks.push(format!("license == {}", n)); }
            _ => {}
        }
    }
    if origin.is_empty() { bail!("`origin` param missing"); }
    eprintln!("▶ Parsed origin: {}", origin);
    eprintln!("▶ Parsed checks: {:?}", checks);

    // Confirm with user
    if !ask_confirmation(&origin, &checks)? {
        eprintln!("▶ Cancelled by user");
        std::process::exit(1);
    }

    // Load identity.json
    let home = dirs::home_dir().expect("no home dir");
    let id_path = home.join(".identity/identity.json");
    let id_json = if id_path.exists() {
        eprintln!("▶ Found existing identity.json at {}", id_path.display());
        fs::read_to_string(&id_path)?
    } else {
        eprintln!("▶ identity.json not found, prompting user for path");
        print!("path to your identity.json: ");
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let p = PathBuf::from(input.trim());
        let s = fs::read_to_string(&p)?;
        fs::create_dir_all(home.join(".identity"))?;
        fs::write(&id_path, &s)?;
        eprintln!("▶ Saved identity.json to {}", id_path.display());
        s
    };
    eprintln!("▶ Loaded identity data");
    let identity: IdentityData = serde_json::from_str(&id_json)?;

    // Local checks before SNARK
    eprintln!("▶ Performing local checks");
    let today_days = Utc::now().num_days_from_ce() as u64;
    eprintln!("▶ Today (days from CE): {}", today_days);
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
    eprintln!("▶ All local checks passed, proceeding to proof generation");

    // SNARK key setup
    eprintln!("▶ Loading or generating SNARK keys");
    let sk_path = home.join(".identity/proving.key");
    let vk_path = home.join(".identity/verification.key");
    let (pk, _vk) = if sk_path.exists() && vk_path.exists() {
        eprintln!("▶ Found existing proving & verification keys");
        let pk_bytes = fs::read(&sk_path)?;
        let mut pk_slice = pk_bytes.as_slice();
        let pk = ProvingKey::<Bn254>::deserialize(&mut pk_slice)?;
        let vk_bytes = fs::read(&vk_path)?;
        let mut vk_slice = vk_bytes.as_slice();
        let vk = VerifyingKey::<Bn254>::deserialize(&mut vk_slice)?;
        (pk, vk)
    } else {
        eprintln!("▶ Generating new SNARK keys (this may take a while)");
        let blank = IdentityCircuit {
            dob: None, license: None, nonce: None, expiration: None,
            first_name: None, last_name: None,
            commitment: Fr::zero(),
            required_fname: None, required_lname: None,
            dob_before: None, dob_after: None, dob_equal: None,
            required_license: None,
        };
        let mut rng = thread_rng();
        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(blank, &mut rng)?;
        fs::write(&sk_path, &{
            let mut buf = Vec::new(); pk.serialize(&mut buf)?; buf
        })?;
        fs::write(&vk_path, &{
            let mut buf = Vec::new(); vk.serialize(&mut buf)?; buf
        })?;
        eprintln!("▶ Keys generated and saved");
        (pk, vk)
    };

    // Build circuit and generate proof
    let mut circuit = IdentityCircuit {
        dob: Some(Fr::from(identity.dob)),
        license: Some(Fr::from(identity.license)),
        nonce: Some(Fr::from(identity.nonce)),
        expiration: Some(Fr::from(identity.expiration)),
        first_name: Some(Fr::from_le_bytes_mod_order(identity.first_name.as_bytes())),
        last_name: Some(Fr::from_le_bytes_mod_order(identity.last_name.as_bytes())),
        commitment: Fr::zero(),
        required_fname: req_fname.map(|s| Fr::from_le_bytes_mod_order(s.as_bytes())),
        required_lname: req_lname.map(|s| Fr::from_le_bytes_mod_order(s.as_bytes())),
        dob_before: dob_before.map(Fr::from),
        dob_after: dob_after.map(Fr::from),
        dob_equal: dob_equal.map(Fr::from),
        required_license: req_license.map(Fr::from),
    };

    eprintln!("▶ Computing commitment and generating proof");
    let p = poseidon();
    let r1  = p.hash(&[Fr::from(identity.dob), Fr::from(identity.license)])?;
    let r2  = p.hash(&[Fr::from(identity.expiration), Fr::from(identity.nonce)])?;
    let mid = p.hash(&[r1, r2])?;
    let h1  = p.hash(&[mid, Fr::from_le_bytes_mod_order(identity.first_name.as_bytes())])?;
    let com = p.hash(&[h1, Fr::from_le_bytes_mod_order(identity.last_name.as_bytes())])?;
    circuit.commitment = com;

    let proof = Groth16::prove(&pk, circuit, &mut thread_rng())?;
    eprintln!("▶ Proof successfully generated");

    // Callback with proof and commitment
    let mut buf = Vec::new(); proof.serialize(&mut buf)?;
    let proof_hex = hex::encode(buf);
    let com_hex   = hex_serialize_fr(&com);
    let callback = format!("{}?proof={}&commitment={}", origin, proof_hex, com_hex);
    eprintln!("▶ Sending proof back to origin");
    SysCommand::new("xdg-open").arg(&callback).status()?;

    Ok(())
}
