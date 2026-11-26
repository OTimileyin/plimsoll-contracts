//! Reporter registry: decides which addresses may post reserve reports and
//! supply snapshots to the coverage ledger, and in which role.
#![no_std]

use plimsoll_types::{
    PendingUpgrade, ReporterInfo, Role, INSTANCE_EXTEND_TO, INSTANCE_THRESHOLD,
    PERSISTENT_EXTEND_TO, PERSISTENT_THRESHOLD, UPGRADE_DELAY_LEDGERS,
};
use soroban_sdk::{
    contract, contracterror, contractevent, contractimpl, contracttype, panic_with_error, Address,
    BytesN, ContractExecutable, Env, String, Symbol, Vec,
};

const MAX_NAME_LEN: u32 = 64;
const MAX_URI_LEN: u32 = 256;
const MAX_REPORTER_TAGS: u32 = 5;

#[contracttype]
#[derive(Clone)]
enum DataKey {
    Admin,
    Reporter(Address),
    ReporterUri(Address),
    ReporterTags(Address),
    Category(Symbol),
    PendingUpgrade,
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum RegistryError {
    ReporterNotFound = 1,
    InvalidName = 2,
    UpgradeNotProposed = 3,
    UpgradeDelayNotElapsed = 4,
    InvalidUri = 5,
    TooManyTags = 6,
    DuplicateTag = 7,
}

#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReporterSet {
    #[topic]
    pub reporter: Address,
    pub role: Role,
    pub name: String,
}

#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReporterRevoked {
    #[topic]
    pub reporter: Address,
}

#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReporterUriUpdated {
    #[topic]
    pub reporter: Address,
    pub uri: String,
}

#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReporterTagsUpdated {
    #[topic]
    pub reporter: Address,
    pub tags: Vec<Symbol>,
}

#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminTransferred {
    #[topic]
    pub new_admin: Address,
}

#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpgradeProposed {
    #[topic]
    pub wasm_hash: BytesN<32>,
    pub executable_at_ledger: u32,
}

#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpgradeExecuted {
    #[topic]
    pub wasm_hash: BytesN<32>,
}

#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpgradeCancelled {
    #[topic]
    pub wasm_hash: BytesN<32>,
}

#[contract]
pub struct ReporterRegistry;

fn admin(env: &Env) -> Address {
    env.storage()
        .instance()
        .get(&DataKey::Admin)
        .expect("admin is set in the constructor")
}

fn bump_instance(env: &Env) {
    env.storage()
        .instance()
        .extend_ttl(INSTANCE_THRESHOLD, INSTANCE_EXTEND_TO);
}

fn pending(env: &Env) -> Option<PendingUpgrade> {
    env.storage().instance().get(&DataKey::PendingUpgrade)
}

fn read_reporter_tags(env: &Env, reporter: &Address) -> Vec<Symbol> {
    let key = DataKey::ReporterTags(reporter.clone());
    let tags = env.storage().persistent().get::<_, Vec<Symbol>>(&key);
    if tags.is_some() {
        env.storage()
            .persistent()
            .extend_ttl(&key, PERSISTENT_THRESHOLD, PERSISTENT_EXTEND_TO);
    }
    tags.unwrap_or_else(|| Vec::new(env))
}

fn remove_address(values: &mut Vec<Address>, address: &Address) {
    if let Some(index) = values.first_index_of(address) {
        values.remove(index);
    }
}

#[contractimpl]
impl ReporterRegistry {
    pub fn __constructor(env: Env, admin: Address) {
        env.storage().instance().set(&DataKey::Admin, &admin);
        bump_instance(&env);
    }

    pub fn admin(env: Env) -> Address {
        admin(&env)
    }

    /// Add a reporter, or change an existing reporter's role and name.
    pub fn set_reporter(env: Env, reporter: Address, role: Role, name: String) {
        admin(&env).require_auth();
        if name.is_empty() || name.len() > MAX_NAME_LEN {
            panic_with_error!(&env, RegistryError::InvalidName);
        }
        let key = DataKey::Reporter(reporter.clone());
        let added_at = env
            .storage()
            .persistent()
            .get::<_, ReporterInfo>(&key)
            .map(|existing| existing.added_at)
            .unwrap_or_else(|| env.ledger().timestamp());
        let info = ReporterInfo {
            role,
            name: name.clone(),
            added_at,
        };
        env.storage().persistent().set(&key, &info);
        env.storage()
            .persistent()
            .extend_ttl(&key, PERSISTENT_THRESHOLD, PERSISTENT_EXTEND_TO);
        bump_instance(&env);
        ReporterSet {
            reporter,
            role,
            name,
        }
        .publish(&env);
    }

    pub fn revoke(env: Env, reporter: Address) {
        admin(&env).require_auth();
        let key = DataKey::Reporter(reporter.clone());
        if !env.storage().persistent().has(&key) {
            panic_with_error!(&env, RegistryError::ReporterNotFound);
        }
        env.storage().persistent().remove(&key);
        let tags = read_reporter_tags(&env, &reporter);
        for tag in tags.iter() {
            let category_key = DataKey::Category(tag.clone());
            let mut members = env
                .storage()
                .persistent()
                .get::<_, Vec<Address>>(&category_key)
                .unwrap_or_else(|| Vec::new(&env));
            remove_address(&mut members, &reporter);
            if members.is_empty() {
                env.storage().persistent().remove(&category_key);
            } else {
                env.storage().persistent().set(&category_key, &members);
                env.storage().persistent().extend_ttl(
                    &category_key,
                    PERSISTENT_THRESHOLD,
                    PERSISTENT_EXTEND_TO,
                );
            }
        }
        env.storage()
            .persistent()
            .remove(&DataKey::ReporterTags(reporter.clone()));
        env.storage()
            .persistent()
            .remove(&DataKey::ReporterUri(reporter.clone()));
        bump_instance(&env);
        ReporterRevoked { reporter }.publish(&env);
    }

    pub fn role_of(env: Env, reporter: Address) -> Option<Role> {
        Self::get_reporter(env, reporter).map(|info| info.role)
    }

    pub fn get_reporter(env: Env, reporter: Address) -> Option<ReporterInfo> {
        let key = DataKey::Reporter(reporter);
        let info = env.storage().persistent().get::<_, ReporterInfo>(&key);
        if info.is_some() {
            env.storage()
                .persistent()
                .extend_ttl(&key, PERSISTENT_THRESHOLD, PERSISTENT_EXTEND_TO);
        }
        info
    }

    /// Replace the reporter's metadata URI.
    pub fn update_reporter_uri(env: Env, reporter: Address, new_uri: String) {
        reporter.require_auth();
        let reporter_key = DataKey::Reporter(reporter.clone());
        if !env.storage().persistent().has(&reporter_key) {
            panic_with_error!(&env, RegistryError::ReporterNotFound);
        }
        if new_uri.is_empty() || new_uri.len() > MAX_URI_LEN {
            panic_with_error!(&env, RegistryError::InvalidUri);
        }
        env.storage().persistent().extend_ttl(
            &reporter_key,
            PERSISTENT_THRESHOLD,
            PERSISTENT_EXTEND_TO,
        );
        let key = DataKey::ReporterUri(reporter.clone());
        env.storage().persistent().set(&key, &new_uri);
        env.storage()
            .persistent()
            .extend_ttl(&key, PERSISTENT_THRESHOLD, PERSISTENT_EXTEND_TO);
        bump_instance(&env);
        ReporterUriUpdated {
            reporter,
            uri: new_uri,
        }
        .publish(&env);
    }

    /// Replace the reporter's category tags.
    pub fn update_reporter_tags(env: Env, reporter: Address, tags: Vec<Symbol>) {
        reporter.require_auth();
        let reporter_key = DataKey::Reporter(reporter.clone());
        if !env.storage().persistent().has(&reporter_key) {
            panic_with_error!(&env, RegistryError::ReporterNotFound);
        }
        if tags.len() > MAX_REPORTER_TAGS {
            panic_with_error!(&env, RegistryError::TooManyTags);
        }
        for i in 0..tags.len() {
            if let Some(tag) = tags.get(i) {
                for j in 0..i {
                    if tags.get(j) == Some(tag.clone()) {
                        panic_with_error!(&env, RegistryError::DuplicateTag);
                    }
                }
            } else {
                panic_with_error!(&env, RegistryError::DuplicateTag);
            }
        }
        env.storage().persistent().extend_ttl(
            &reporter_key,
            PERSISTENT_THRESHOLD,
            PERSISTENT_EXTEND_TO,
        );
        let previous = read_reporter_tags(&env, &reporter);
        for tag in previous.iter() {
            let category_key = DataKey::Category(tag.clone());
            let mut members = env
                .storage()
                .persistent()
                .get::<_, Vec<Address>>(&category_key)
                .unwrap_or_else(|| Vec::new(&env));
            remove_address(&mut members, &reporter);
            if members.is_empty() {
                env.storage().persistent().remove(&category_key);
            } else {
                env.storage().persistent().set(&category_key, &members);
                env.storage().persistent().extend_ttl(
                    &category_key,
                    PERSISTENT_THRESHOLD,
                    PERSISTENT_EXTEND_TO,
                );
            }
        }
        for tag in tags.iter() {
            let category_key = DataKey::Category(tag.clone());
            let mut members = env
                .storage()
                .persistent()
                .get::<_, Vec<Address>>(&category_key)
                .unwrap_or_else(|| Vec::new(&env));
            if !members.contains(&reporter) {
                members.push_back(reporter.clone());
            }
            env.storage().persistent().set(&category_key, &members);
            env.storage().persistent().extend_ttl(
                &category_key,
                PERSISTENT_THRESHOLD,
                PERSISTENT_EXTEND_TO,
            );
        }
        let key = DataKey::ReporterTags(reporter.clone());
        if tags.is_empty() {
            env.storage().persistent().remove(&key);
        } else {
            env.storage().persistent().set(&key, &tags);
            env.storage()
                .persistent()
                .extend_ttl(&key, PERSISTENT_THRESHOLD, PERSISTENT_EXTEND_TO);
        }
        bump_instance(&env);
        ReporterTagsUpdated { reporter, tags }.publish(&env);
    }

    pub fn get_reporters_by_category(env: Env, tag: Symbol) -> Vec<Address> {
        let key = DataKey::Category(tag);
        let members = env.storage().persistent().get::<_, Vec<Address>>(&key);
        if members.is_some() {
            env.storage()
                .persistent()
                .extend_ttl(&key, PERSISTENT_THRESHOLD, PERSISTENT_EXTEND_TO);
        }
        members.unwrap_or_else(|| Vec::new(&env))
    }

    pub fn transfer_admin(env: Env, new_admin: Address) {
        admin(&env).require_auth();
        new_admin.require_auth();
        env.storage().instance().set(&DataKey::Admin, &new_admin);
        bump_instance(&env);
        AdminTransferred { new_admin }.publish(&env);
    }

    /// Propose a wasm hash for installation after the upgrade delay. A new
    /// proposal replaces any pending one and restarts the clock.
    pub fn propose_upgrade(env: Env, wasm_hash: BytesN<32>) {
        admin(&env).require_auth();
        let executable_at_ledger = env
            .ledger()
            .sequence()
            .saturating_add(UPGRADE_DELAY_LEDGERS);
        env.storage().instance().set(
            &DataKey::PendingUpgrade,
            &PendingUpgrade {
                wasm_hash: wasm_hash.clone(),
                executable_at_ledger,
            },
        );
        bump_instance(&env);
        UpgradeProposed {
            wasm_hash,
            executable_at_ledger,
        }
        .publish(&env);
    }

    /// Install the pending wasm once its delay has elapsed.
    pub fn execute_upgrade(env: Env) {
        admin(&env).require_auth();
        let proposed = match pending(&env) {
            Some(proposed) => proposed,
            None => panic_with_error!(&env, RegistryError::UpgradeNotProposed),
        };
        if env.ledger().sequence() < proposed.executable_at_ledger {
            panic_with_error!(&env, RegistryError::UpgradeDelayNotElapsed);
        }
        env.storage().instance().remove(&DataKey::PendingUpgrade);
        bump_instance(&env);
        UpgradeExecuted {
            wasm_hash: proposed.wasm_hash.clone(),
        }
        .publish(&env);
        env.deployer()
            .update_current_contract(ContractExecutable::Wasm(proposed.wasm_hash));
    }

    /// Cancel the pending upgrade.
    pub fn cancel_upgrade(env: Env) {
        admin(&env).require_auth();
        let proposed = match pending(&env) {
            Some(proposed) => proposed,
            None => panic_with_error!(&env, RegistryError::UpgradeNotProposed),
        };
        env.storage().instance().remove(&DataKey::PendingUpgrade);
        bump_instance(&env);
        UpgradeCancelled {
            wasm_hash: proposed.wasm_hash,
        }
        .publish(&env);
    }

    /// The pending upgrade, if any.
    pub fn pending_upgrade(env: Env) -> Option<PendingUpgrade> {
        let proposed = pending(&env);
        if proposed.is_some() {
            bump_instance(&env);
        }
        proposed
    }
}

#[cfg(test)]
mod test;
