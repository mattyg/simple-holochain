use crate::utils::hash;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use serde::{Serialize, Deserialize};
use std::hash::Hash;
use ed25519_dalek::Signature;
use uuid::Uuid;


// Layer 1: Crdt of State Changes
//
// A CRDT is a data structure comprised of:
//
// 1. A set of state changes
//    1.1 A state change may depend on a set of prior state changes
// 2. A merge function that returns deterministic end state

trait DependOn<H: Hash>: Hash {
    fn get_dependency_hashes(&self) -> BTreeSet<H>;
}

trait StateChange<H: Hash>: DependOn<H> + Serialize {
    fn get_dependency_hashes(&self) -> BTreeSet<H>;
}

trait Crdt<H: Hash, S: StateChange<H>, E> {    
    fn get_state_changes(&self) -> HashSet<S>;
    fn insert_state_change(&self, state_change: S) -> H;
    fn merge(&self) -> E;
}

struct Crdt<S: StateChange> {
    // The full set of state changes
    state_changes: HashMap<S>,
}






// Layer 2: CRDT of Signed State Changes
//
// CRDT State changes are signed by a public key
// The signature or signing key *may* alter the Crdt's merge function behavior if desired

struct SignedStateChange<S: StateChange> {
    state_change: S,
    signature: Signature,
    signing_key: SigningKey,
}

trait SignedStateChange<H: Hash>: StateChange<H> {
    fn get_dependency_hashes(&self) -> BTreeSet<H>;

    fn get_signature(&self) -> Signature;
    fn get_signing_key(&self) -> SigningKey;
    fn is_signature_valid(&self) -> bool;
}

trait SignedCrdt: Crdt<H: Hash, S: SignedStateChange<H>> {
    fn get_state_changes(&self) -> HashMap<S>;
    fn insert_state_change(&self, state_change: S) -> H;
    fn merge(&self) -> E;

    fn get_signing_keys(&self) -> BTreeMap<SigningKey, BTreeSet<H>>;
}

struct SignedCrdt<H: Hash, S: SignedStateChange<H>> {
    // The full set of state changes
    state_changes: HashMap<S>,

    // A map of *signing key* -> all state change hashes signed by that key.
    //
    // All hashes included as *values* MUST exist in state_changes.
    signing_keys: BTreeMap<SigningKey, BTreeSet<H>>,
}






// Layer 3: CRDT of Addressed, Signed State Changes 
//
// We defined an Address to distinguish from a Hash:
// - A State Change only has one Hash (its own)
// - A State Change have multiple Addresses
// - The Hash and Addresses must both be deterministically generated from the State Change itself
//
// We can get a State change from any one of its Addresses.

struct Address(&[u8]);

trait Address {
    fn get_addresses(&self) -> Vec<Address>;
}

trait AddressedSignedStateChange<H: Hash>: SignedStateChange<H> + Address<H> {
    fn get_dependency_hashes(&self) -> BTreeSet<H>;
    fn get_signature(&self) -> Signature;
    fn get_signing_key(&self) -> SigningKey;
    fn is_signature_valid(&self) -> bool;

    fn get_addresses(&self) -> Vec<Address>;
}

trait AddressedSignedStateChangeCrdt<H: Hash>: AddressedSignedStateChange<H> {
    fn get_state_changes(&self) -> HashMap<S>;
    fn insert_state_change(&self, state_change: S) -> H;
    fn merge(&self) -> E;
    fn get_signing_keys(&self) -> BTreeMap<SigningKey, BTreeSet<H>>;

    fn get_address_hashes(&self) -> BTreeMap<A, BTreeSet<H>>;
}

struct AddressedSignedCrdt<H: Hash, S: AddressedSignedStateChange<H>> {
    // The full set of state changes
    state_changes: HashMap<S>,

    // A map of *signing key* -> all state change hashes signed by that key.
    //
    // All hashes in this map as *values* MUST exist in state_changes.
    signing_keys: BTreeMap<SigningKey, BTreeSet<H>>,

    // A map of Address -> Set of hashes stored there
    //
    // All hashes in this map as *values* MUST exist in state_changes
    address_hashes: BTreeMap<A, BTreeSet<H>>,
}





// Layer 4.1: CRDT of Validated, Addressed, Signed State Changes
//
// CRDT State changes are validated to determine if they should be included in the total set of state changes,
// used to derive the end state.
//
// We *could* simply ignore the invalid state changes via the CRDT merge function.
// But we view invalid state change as a form of *bad behavior*.
// In order to respond to such *bad behavior*, we must keep track of it separately from other state changes.

enum Validity<H: Hash> {
    Valid,

    // Invalid, noting the reason it is considered invalid
    Invalid(pub String)
}

enum ValidationStatus<H: Hash> {
    Validity(Validity),
    MissingDependencies(BTreeSet<H>)
}

trait ValidatedAddressedSignedStateChange<H: Hash>: AddressedSignedStateChange<H> + Validate<H> {
    fn get_dependency_hashes(&self) -> BTreeSet<H>;
    fn get_signature(&self) -> Signature;
    fn get_signing_key(&self) -> SigningKey;
    fn is_signature_valid(&self) -> bool;
    fn get_addresses(&self) -> Vec<Address>;

    fn validate(&self, dependencies: HashMap<dyn AddressedSignedStateChange<H>>) -> Validity;
}

trait ValidatedAddressedSignedStateCrdt: Crdt<H, S: ValidatedAddressedSignedStateChange<H>> {
    fn get_state_changes(&self) -> HashMap<S>;
    fn insert_state_change(&self, state_change: S) -> H;
    fn merge(&self) -> E;
    fn get_signing_keys(&self) -> BTreeMap<SigningKey, BTreeSet<H>>;
    fn get_address_hashes(&self) -> BTreeMap<A, BTreeSet<H>>;

    fn get_validation_validity(&self) -> BTreeMap<H, ValidationOutcome<H>>;
    fn get_validation_missing_dependencies(&self) -> BTreeMap<H, BTreeSet<H>>;
}

struct ValidatedAddressedSignedCrdt<H: Hash, S: ValidatedAddressedSignedStateChange<H>> {
    // The full set of state changes
    state_changes: HashMap<S>,

    // A map of *signing key* -> all state change hashes signed by that key.
    //
    // All hashes in this map as *values* MUST exist in state_changes.
    signing_keys: BTreeMap<SigningKey, BTreeSet<H>>,

    // A map of Address -> Set of hashes stored there
    //
    // All hashes in this map as *values* MUST exist in state_changes
    address_hashes: BTreeMap<A, BTreeSet<H>>,

    // A map of state change hash -> validity outcomes for that hash
    //
    // All hashes in this map as *keys*
    // MUST exist in EITHER in state_changes OR in validation_missing_dependencies as *keys*
    validation_validity: BTreeMap<H, Validity<H>>,

    // A map of state change hash -> set of missing state change hashes that are required for its validation
    //
    // All hashes in this map as *values* OR as *keys* MUST NOT exist in state_changes
    validation_missing_dependencies: BTreeMap<H, BTreeSet<H>>
}





// Layer 4.2: CRDT of Address-Validated, Signed State Changes 
//
// We unify the previous two concepts of Addressed and Validated.
//
// Instead of simply validating a State Change,
// we now validate a State Change *for* an Address.
//
// This allows us to have different validation logic for each Address,
// and thus to split up the logic into smaller discrete units,
// which can be run independantly.
//
// If we know that some other state changes have the same Address,
// then any validation logic which depends on those state changes,
// should run for that Address.

trait AddressValidatedAddressedSignedStateChange<H: Hash, A: Address>: AddressedSignedStateChange<H> + Validate<H> {
    fn get_dependency_hashes(&self) -> BTreeSet<H>;
    fn get_signature(&self) -> Signature;
    fn get_signing_key(&self) -> SigningKey;
    fn is_signature_valid(&self) -> bool;
    fn get_addresses(&self) -> Vec<Address>;

    fn validate_for_address(&self, address: A, dependencies: HashMap<dyn AddressValidatedAddressedSignedStateChange<H>>) -> Validity;
}

trait AddressValidatedAddressedSignedCrdt<H: Hash, A: Address>: AddressValidatedAddressedSignedStateChange<H> {
    fn get_state_changes(&self) -> HashMap<S>;
    fn insert_state_change(&self, state_change: S) -> H;
    fn merge(&self) -> E;
    fn get_signing_keys(&self) -> BTreeMap<SigningKey, BTreeSet<H>>;
    fn get_address_hashes(&self) -> BTreeMap<A, BTreeSet<H>>;

    fn get_validation_validity(&self) ->  BTreeMap<H, BTreeMap<A, Validity<H>>>;
    fn get_validation_missing_dependencies(&self) -> BTreeMap<H, BTreeMap<A, BTreeSet<H>>>;
    fn get_validation_validity_for_address(&self, address: A) ->  BTreeMap<A, Validity<H>>;
    fn get_validation_missing_dependencies_for_address(&self, address: A) -> BTreeMap<A, BTreeSet<H>>;
}

struct AddressValidatedAddressedSignedCrdt<H: Hash, S: AddressValidatedAddressedSignedStateChange<H>> {
    // The full set of state changes
    state_changes: HashMap<S>,

    // A map of *signing key* -> all state change hashes signed by that key.
    //
    // All hashes in this map as *values* MUST exist in state_changes.
    signing_keys: BTreeMap<SigningKey, BTreeSet<H>>,

    // A map of Address -> Set of hashes stored there
    //
    // All hashes in this map as *values* MUST exist in state_changes
    address_hashes: BTreeMap<A, BTreeSet<H>>,

    // A map of state change hash -> ( another map of Address -> validity outcomes for that hash )
    //
    // All hashes in this map as *keys*
    // MUST exist in EITHER in state_changes OR in validation_missing_dependencies as *keys*
    validation_validity: BTreeMap<H, BTreeMap<A, Validity<H>>>,

    // A map of state change hash -> ( another map of Address -> set of missing state change hashes that are required for its validation )
    //
    // All hashes in this map as *values* OR as *keys* MUST NOT exist in state_changes
    validation_missing_dependencies: BTreeMap<H, BTreeMap<A, BTreeSet<H>>>
}
