use std::io::{self, BufRead};
use anyhow::Result;
use ark_bn254::{Bn254, Fr};
use ark_ff::Zero;
use ark_groth16::{Groth16, Proof};
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, eq::EqGadget, fields::FieldVar};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use ark_snark::SNARK;
use arkworks_native_gadgets::poseidon::{
    Poseidon, PoseidonParameters, sbox::PoseidonSbox, FieldHasher
};
use arkworks_r1cs_gadgets::poseidon::{FieldHasherGadget, PoseidonGadget};
use arkworks_utils::{
    bytes_matrix_to_f, bytes_vec_to_f, poseidon_params::setup_poseidon_params, Curve
};
use hex;
use rand::thread_rng;
use serde::{Deserialize, Serialize};

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
    Poseidon::<Fr>::new(params)
}

pub struct IdentityCircuit {
    // Private inputs
    dob: Option<Fr>,
    license: Option<Fr>,
    nonce: Option<Fr>,
    // Public inputs
    commitment: Fr,
    threshold_date: Fr,
    required_license: Fr,
}

impl ConstraintSynthesizer<Fr> for IdentityCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let dob_var   = FpVar::new_witness(cs.clone(), || Ok(self.dob.unwrap()))?;
        let lic_var   = FpVar::new_witness(cs.clone(), || Ok(self.license.unwrap()))?;
        let nonce_var = FpVar::new_witness(cs.clone(), || Ok(self.nonce.unwrap()))?;

        let native = poseidon();
        let gadget = PoseidonGadget::<Fr>::from_native(&mut cs.clone(), native)?;

        let mid = gadget.hash(&[dob_var.clone(), lic_var.clone()])?;
        let final_hash = gadget.hash(&[mid.clone(), nonce_var.clone()])?;

        let com_var = FpVar::new_input(cs.clone(), || Ok(self.commitment))?;
        com_var.enforce_equal(&final_hash)?;

        let thresh_var = FpVar::new_input(cs.clone(), || Ok(self.threshold_date))?;
        let eighteen = Fr::from(18u64 * 365);
        let ok_age = dob_var + FpVar::constant(eighteen);
        ok_age.enforce_cmp(&thresh_var, core::cmp::Ordering::Less, true)?;

        let req_lic = FpVar::new_input(cs.clone(), || Ok(self.required_license))?;
        lic_var.enforce_equal(&req_lic)?;

        Ok(())
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub enum Request {
    Setup,
    Commit { dob: u64, license: u64, nonce: u64 },
    Prove  { dob: u64, license: u64, nonce: u64, commitment: String,
             threshold: u64, required_license: u64 },
    Verify { commitment: String, threshold: u64, required_license: u64, proof: String },
}

#[derive(Serialize, Deserialize, Debug)]
pub enum Response {
    Setup       { pk: String, vk: String },
    Commit      { commitment: String },
    Prove       { proof: String },
    VerifyOk,
    VerifyFail,
}

macro_rules! respond {
    ($resp:expr) => {{
        println!("{}", serde_json::to_string(&$resp).unwrap());
    }};
}

fn hex_serialize_fr(f: &Fr) -> String {
    let mut buf = Vec::new();
    f.serialize(&mut buf).unwrap();
    hex::encode(buf)
}

fn hex_deserialize_fr(s: &str) -> Fr {
    let data = hex::decode(s).unwrap();
    Fr::deserialize(&*data).unwrap()
}

fn main() -> Result<()> {
    let mut rng = thread_rng();

    let blank = IdentityCircuit {
        dob: None, license: None, nonce: None,
        commitment: Fr::zero(),
        threshold_date: Fr::zero(),
        required_license: Fr::zero(),
    };
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(blank, &mut rng)?;

    for line in io::stdin().lock().lines() {
        let req: Request = serde_json::from_str(&line?)?;
        match req {
            Request::Setup => {
                let mut pk_bytes = Vec::new();
                pk.serialize(&mut pk_bytes)?;
                let pk_hex = hex::encode(&pk_bytes);

                let mut vk_bytes = Vec::new();
                vk.serialize(&mut vk_bytes)?;
                let vk_hex = hex::encode(&vk_bytes);

                respond!(Response::Setup { pk: pk_hex, vk: vk_hex });
            }

            Request::Commit { dob, license, nonce } => {
                let d = Fr::from(dob);
                let l = Fr::from(license);
                let n = Fr::from(nonce);
                let p = poseidon();
                let mid = p.hash(&[d, l]).unwrap();
                let com = p.hash(&[mid, n]).unwrap();
                respond!(Response::Commit { commitment: hex_serialize_fr(&com) });
            }

            Request::Prove { dob, license, nonce, commitment, threshold, required_license } => {
                let d  = Fr::from(dob);
                let l  = Fr::from(license);
                let n  = Fr::from(nonce);
                let com_f = hex_deserialize_fr(&commitment);
                let thr_f = Fr::from(threshold);
                let req_f = Fr::from(required_license);

                let circuit = IdentityCircuit {
                    dob: Some(d),
                    license: Some(l),
                    nonce: Some(n),
                    commitment: com_f,
                    threshold_date: thr_f,
                    required_license: req_f,
                };
                let proof = Groth16::prove(&pk, circuit, &mut rng)?;
                let mut buf = Vec::new();
                proof.serialize(&mut buf)?;
                respond!(Response::Prove { proof: hex::encode(buf) });
            }

            Request::Verify { commitment, threshold, required_license, proof } => {
                let com_f = hex_deserialize_fr(&commitment);
                let thr_f = Fr::from(threshold);
                let req_f = Fr::from(required_license);

                let proof_bytes = hex::decode(proof).unwrap();
                let proof = Proof::<Bn254>::deserialize(&*proof_bytes).unwrap();
                let inputs = [com_f, thr_f, req_f];
                let ok = Groth16::verify(&vk, &inputs, &proof)?;
                respond!( if ok { Response::VerifyOk } else { Response::VerifyFail } );
            }
        }
    }

    Ok(())
}
