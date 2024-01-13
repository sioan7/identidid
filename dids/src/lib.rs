use didkit::{
    get_verification_method, Error, LinkedDataProofOptions, Source, VerifiableCredential,
    DID_METHODS, JWK, URI,
};

// pub fn generate_key

pub async fn flow_1() {
    let jwk = JWK::generate_ed25519().unwrap();

    println!(
        "--- Private key ---\n{}\n",
        serde_json::to_string(&jwk).unwrap()
    );
    println!(
        "--- Public key ---\n{}\n",
        serde_json::to_string(&jwk.to_public()).unwrap()
    );

    let did = DID_METHODS
        .generate(&Source::KeyAndPattern(&jwk, "key"))
        .ok_or(Error::UnableToGenerateDID)
        .unwrap();

    println!("--- DID ---\n{}\n", &did);

    let mut unsigned_vc_json = format!(
        r#"{{
            "@context": "https://www.w3.org/2018/credentials/v1",
            "id": "urn:uuid:`uuidgen`",
            "type": ["VerifiableCredential"],
            "issuer": "{did}",
            "issuanceDate": "2022-10-28T06:40:40Z",
            "credentialSubject": {{
                "id": "did:example:my-data-subject-identifier"
            }}
        }}"#
    );
    unsigned_vc_json.retain(|c| !c.is_whitespace());
    let unsigned_vc = unsigned_vc_json;

    let mut vc = VerifiableCredential::from_json_unsigned(&unsigned_vc).unwrap();

    println!("--- VC ---\n{}\n", serde_json::to_string(&vc).unwrap());

    let did_resolver = DID_METHODS.to_resolver();
    let vm = get_verification_method(&did, did_resolver)
        .await
        .ok_or(Error::UnableToGetVerificationMethod)
        .unwrap();

    println!("--- Verification Method ---\n{vm}\n");

    let issue_options = LinkedDataProofOptions {
        verification_method: Some(URI::String(vm)),
        ..Default::default()
    };

    let vc_proof = vc
        .generate_proof(&jwk, &issue_options, did_resolver)
        .await
        .unwrap();

    println!(
        "--- Proof ---\n{}\n",
        serde_json::to_string(&vc_proof).unwrap()
    );

    vc.add_proof(vc_proof);

    println!(
        "--- VC with proof ---\n{}\n",
        serde_json::to_string(&vc).unwrap()
    );

    let verification_result = vc.verify(Some(issue_options), did_resolver).await;

    println!(
        "--- Verification Result ---\n{}\n",
        serde_json::to_string(&verification_result).unwrap()
    );
}
