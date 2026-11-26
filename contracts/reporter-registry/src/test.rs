extern crate std;

use super::*;
#[allow(unused_imports)]
use soroban_sdk::{
    testutils::{Address as _, Events as _, Ledger as _, MockAuth, MockAuthInvoke},
    Address, Bytes, BytesN, Env, IntoVal, String,
};

#[allow(dead_code)]
fn upgrade_fixture_wasm() -> std::vec::Vec<u8> {
    const VENDORED: &[u8] =
        include_bytes!("../../upgrade-fixture-registry/testdata/upgrade_fixture_registry.wasm");
    let built = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("target/wasm32v1-none/release/upgrade_fixture_registry.wasm");
    std::fs::read(built).unwrap_or_else(|_| VENDORED.to_vec())
}

#[allow(dead_code)]
fn upload_upgrade_fixture(env: &Env) -> BytesN<32> {
    env.deployer()
        .upload_contract_wasm(Bytes::from_slice(env, &upgrade_fixture_wasm()))
}

fn setup() -> (Env, Address, ReporterRegistryClient<'static>) {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(1_700_000_000);
    let admin = Address::generate(&env);
    let id = env.register(ReporterRegistry, (admin.clone(),));
    let client = ReporterRegistryClient::new(&env, &id);
    (env, admin, client)
}

#[test]
fn constructor_sets_admin() {
    let (_env, admin, client) = setup();
    assert_eq!(client.admin(), admin);
}

#[test]
fn set_reporter_stores_role_and_name() {
    let (env, admin, client) = setup();
    let auditor = Address::generate(&env);
    client.set_reporter(
        &auditor,
        &Role::Auditor,
        &String::from_str(&env, "Acme Audit LLP"),
    );

    assert_eq!(env.auths()[0].0, admin);
    let info = client.get_reporter(&auditor).unwrap();
    assert_eq!(info.role, Role::Auditor);
    assert_eq!(info.name, String::from_str(&env, "Acme Audit LLP"));
    assert_eq!(info.added_at, 1_700_000_000);
    assert_eq!(client.role_of(&auditor), Some(Role::Auditor));
}

#[test]
fn set_reporter_emits_event() {
    let (env, _admin, client) = setup();
    let poster = Address::generate(&env);
    client.set_reporter(
        &poster,
        &Role::SupplyPoster,
        &String::from_str(&env, "indexer"),
    );
    assert_eq!(env.events().all().events().len(), 1);
}

#[test]
fn changing_role_keeps_added_at() {
    let (env, _admin, client) = setup();
    let who = Address::generate(&env);
    client.set_reporter(&who, &Role::Transcriber, &String::from_str(&env, "vol"));
    env.ledger().set_timestamp(1_800_000_000);
    client.set_reporter(
        &who,
        &Role::Auditor,
        &String::from_str(&env, "vol, now audit"),
    );
    let info = client.get_reporter(&who).unwrap();
    assert_eq!(info.role, Role::Auditor);
    assert_eq!(info.added_at, 1_700_000_000);
}

#[test]
fn empty_name_rejected() {
    let (env, _admin, client) = setup();
    let who = Address::generate(&env);
    let res = client.try_set_reporter(&who, &Role::Auditor, &String::from_str(&env, ""));
    assert_eq!(res, Err(Ok(RegistryError::InvalidName.into())));
}

#[test]
fn long_name_rejected() {
    let (env, _admin, client) = setup();
    let who = Address::generate(&env);
    let long = String::from_str(&env, &"x".repeat(65));
    let res = client.try_set_reporter(&who, &Role::Auditor, &long);
    assert_eq!(res, Err(Ok(RegistryError::InvalidName.into())));
}

#[test]
fn revoke_removes_reporter() {
    let (env, _admin, client) = setup();
    let who = Address::generate(&env);
    client.set_reporter(&who, &Role::Auditor, &String::from_str(&env, "a"));
    client.revoke(&who);
    assert_eq!(client.role_of(&who), None);
}

#[test]
fn revoke_unknown_fails() {
    let (env, _admin, client) = setup();
    let who = Address::generate(&env);
    let res = client.try_revoke(&who);
    assert_eq!(res, Err(Ok(RegistryError::ReporterNotFound.into())));
}

#[test]
fn unknown_reporter_has_no_role() {
    let (env, _admin, client) = setup();
    assert_eq!(client.role_of(&Address::generate(&env)), None);
}

#[test]
fn transfer_admin_requires_both() {
    let (env, admin, client) = setup();
    let next = Address::generate(&env);
    client.transfer_admin(&next);
    let auths = env.auths();
    assert!(auths.iter().any(|(a, _)| *a == admin));
    assert!(auths.iter().any(|(a, _)| *a == next));
    assert_eq!(client.admin(), next);
}

#[test]
#[should_panic]
fn set_reporter_without_auth_panics() {
    let env = Env::default();
    let admin = Address::generate(&env);
    let id = env.register(ReporterRegistry, (admin,));
    let client = ReporterRegistryClient::new(&env, &id);
    client.set_reporter(
        &Address::generate(&env),
        &Role::Auditor,
        &String::from_str(&env, "x"),
    );
}

#[test]
fn revoke_then_re_add_resets_added_at() {
    let (env, _admin, client) = setup();
    let who = Address::generate(&env);
    client.set_reporter(&who, &Role::Auditor, &String::from_str(&env, "first"));
    let first_added = client.get_reporter(&who).unwrap().added_at;
    env.ledger().set_timestamp(1_800_000_000);
    client.revoke(&who);
    client.set_reporter(&who, &Role::Transcriber, &String::from_str(&env, "second"));
    let second_added = client.get_reporter(&who).unwrap().added_at;
    assert_eq!(second_added, 1_800_000_000);
    assert_ne!(second_added, first_added);
}

#[test]
fn name_exactly_64_bytes_accepted() {
    let (env, _admin, client) = setup();
    let who = Address::generate(&env);
    let name_64 = String::from_str(&env, &"x".repeat(64));
    client.set_reporter(&who, &Role::Auditor, &name_64);
    assert_eq!(client.get_reporter(&who).unwrap().name, name_64);
}

#[test]
fn name_65_bytes_rejected() {
    let (env, _admin, client) = setup();
    let who = Address::generate(&env);
    let name_65 = String::from_str(&env, &"x".repeat(65));
    let res = client.try_set_reporter(&who, &Role::Auditor, &name_65);
    assert_eq!(res, Err(Ok(RegistryError::InvalidName.into())));
}

#[test]
fn revoke_without_admin_auth_fails() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let id = env.register(ReporterRegistry, (admin.clone(),));
    let client = ReporterRegistryClient::new(&env, &id);
    let who = Address::generate(&env);
    client.set_reporter(&who, &Role::Auditor, &String::from_str(&env, "a"));
    // Clear mocked auths for the next call
    env.mock_auths(&[]);
    let res = client.try_revoke(&who);
    assert!(res.is_err());
    // Reporter should still exist
    assert_eq!(client.role_of(&who), Some(Role::Auditor));
}

#[test]
fn transfer_admin_without_new_admin_auth_fails() {
    let env = Env::default();
    let admin = Address::generate(&env);
    let id = env.register(ReporterRegistry, (admin.clone(),));
    let client = ReporterRegistryClient::new(&env, &id);
    let next = Address::generate(&env);
    let res = client.try_transfer_admin(&next);
    assert!(res.is_err());
    assert_eq!(client.admin(), admin);
}

#[test]
fn reporter_can_update_metadata_uri() {
    let (env, _admin, client) = setup();
    let reporter = Address::generate(&env);
    client.set_reporter(&reporter, &Role::Auditor, &String::from_str(&env, "audit"));
    let uri = String::from_str(&env, "ipfs://reporter-metadata");

    client.update_reporter_uri(&reporter, &uri);

    assert_eq!(env.events().all().events().len(), 2);
}

#[test]
fn update_reporter_uri_rejects_unknown_reporter() {
    let (env, _admin, client) = setup();
    let reporter = Address::generate(&env);
    let uri = String::from_str(&env, "ipfs://metadata");

    assert_eq!(
        client.try_update_reporter_uri(&reporter, &uri),
        Err(Ok(RegistryError::ReporterNotFound.into()))
    );
}

#[test]
fn update_reporter_uri_rejects_empty_and_long_uris() {
    let (env, _admin, client) = setup();
    let reporter = Address::generate(&env);
    client.set_reporter(&reporter, &Role::Auditor, &String::from_str(&env, "audit"));

    assert_eq!(
        client.try_update_reporter_uri(&reporter, &String::from_str(&env, "")),
        Err(Ok(RegistryError::InvalidUri.into()))
    );
    assert_eq!(
        client.try_update_reporter_uri(&reporter, &String::from_str(&env, &"x".repeat(257))),
        Err(Ok(RegistryError::InvalidUri.into()))
    );
}

#[test]
fn reporter_can_replace_category_tags_and_query_them() {
    let (env, _admin, client) = setup();
    let first = Address::generate(&env);
    let second = Address::generate(&env);
    client.set_reporter(&first, &Role::Auditor, &String::from_str(&env, "first"));
    client.set_reporter(
        &second,
        &Role::Transcriber,
        &String::from_str(&env, "second"),
    );
    let bank = soroban_sdk::Symbol::new(&env, "bank");
    let dex = soroban_sdk::Symbol::new(&env, "dex");
    let mut first_tags = soroban_sdk::Vec::new(&env);
    first_tags.push_back(bank.clone());
    client.update_reporter_tags(&first, &first_tags);
    let mut second_tags = soroban_sdk::Vec::new(&env);
    second_tags.push_back(bank.clone());
    second_tags.push_back(dex.clone());
    client.update_reporter_tags(&second, &second_tags);

    let bank_reporters = client.get_reporters_by_category(&bank);
    assert_eq!(bank_reporters.len(), 2);
    assert_eq!(bank_reporters.get(0), Some(first.clone()));
    assert_eq!(bank_reporters.get(1), Some(second.clone()));

    let mut replacement = soroban_sdk::Vec::new(&env);
    replacement.push_back(dex.clone());
    client.update_reporter_tags(&first, &replacement);
    assert_eq!(client.get_reporters_by_category(&bank).len(), 1);
    assert_eq!(client.get_reporters_by_category(&dex).len(), 2);
    client.revoke(&second);
    assert_eq!(client.get_reporters_by_category(&bank).len(), 0);
    assert_eq!(client.get_reporters_by_category(&dex).len(), 1);
}

#[test]
fn update_reporter_tags_rejects_unknown_reporter_and_more_than_five() {
    let (env, _admin, client) = setup();
    let reporter = Address::generate(&env);
    let tags = soroban_sdk::Vec::new(&env);
    assert_eq!(
        client.try_update_reporter_tags(&reporter, &tags),
        Err(Ok(RegistryError::ReporterNotFound.into()))
    );

    client.set_reporter(&reporter, &Role::Auditor, &String::from_str(&env, "audit"));
    let mut too_many = soroban_sdk::Vec::new(&env);
    for name in ["bank", "custodian", "dex", "exchange", "fund", "issuer"] {
        too_many.push_back(soroban_sdk::Symbol::new(&env, name));
    }
    assert_eq!(
        client.try_update_reporter_tags(&reporter, &too_many),
        Err(Ok(RegistryError::TooManyTags.into()))
    );
}

#[test]
fn update_reporter_tags_rejects_duplicate_tags() {
    let (env, _admin, client) = setup();
    let reporter = Address::generate(&env);
    client.set_reporter(&reporter, &Role::Auditor, &String::from_str(&env, "audit"));
    let bank = soroban_sdk::Symbol::new(&env, "bank");
    let mut duplicates = soroban_sdk::Vec::new(&env);
    duplicates.push_back(bank.clone());
    duplicates.push_back(bank);

    assert_eq!(
        client.try_update_reporter_tags(&reporter, &duplicates),
        Err(Ok(RegistryError::DuplicateTag.into()))
    );
}

#[test]
fn update_reporter_uri_requires_reporter_auth() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let id = env.register(ReporterRegistry, (admin,));
    let client = ReporterRegistryClient::new(&env, &id);
    let reporter = Address::generate(&env);
    client.set_reporter(&reporter, &Role::Auditor, &String::from_str(&env, "audit"));
    env.mock_auths(&[]);

    let res = client.try_update_reporter_uri(&reporter, &String::from_str(&env, "ipfs://metadata"));
    assert!(res.is_err());
    assert_eq!(env.events().all().events().len(), 1);
}

#[test]
fn exactly_five_reporter_tags_are_accepted() {
    let (env, _admin, client) = setup();
    let reporter = Address::generate(&env);
    client.set_reporter(&reporter, &Role::Auditor, &String::from_str(&env, "audit"));
    let mut tags = soroban_sdk::Vec::new(&env);
    for name in ["bank", "custodian", "dex", "exchange", "fund"] {
        tags.push_back(soroban_sdk::Symbol::new(&env, name));
    }

    client.update_reporter_tags(&reporter, &tags);

    assert_eq!(tags.len(), 5);
    assert_eq!(
        client
            .get_reporters_by_category(&soroban_sdk::Symbol::new(&env, "fund"))
            .len(),
        1
    );
}
