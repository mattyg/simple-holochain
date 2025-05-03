use std::collections::{BTreeMap, HashMap, HashSet};
use serde::{Serialize, Deserialize};
use std::hash::Hash;
use ed25519_dalek::Signature;

// Layer 0: Hash

pub fn hash<H: Hash>(val: H) {
    let mut hash_bytes = &[];
    val.hash(&mut hash_bytes);
    hash_bytes
}

// Layer 1: CRDT
//
// A CRDT is a data structure comprised of:
//
// 1. A set of state changes
//    1.1 A state change may depend on a set of prior state changes
// 2. A merge function that returns deterministic end state

trait DependOn<H: Hash> {
    fn get_dependencies(&self) -> HashSet<H>;
}

trait StateChange: Hash + Serialize + DependOn<Self> {}

trait Crdt<H: Hash, S: StateChange<H>, E> {
    /// The merge function that returns the final end state of this Crdt
    fn get_end_state(&self) -> E;

    /// Get the set of all state changes
    fn get_state_changes(&self) -> HashSet<S>;

    /// Add a state change to the set
    fn add_state_change(&self, state_change: S);

    /// Get the set of hashes of all state changes
    fn get_state_change_hashes(&self) -> HashSet<H> {
        self.get_state_changes().into_iter().map(|s| hash(s)).collect()
    }
}


// Layer 2: Signed CRDT State Changes
//
// CRDT State changes are signed by a public key
// The signature or signing key *may* alter the Crdt's merge function behavior if desired

trait Sign {
    fn get_signature(&self) -> Signature;

    fn get_signing_key(&self) -> SigningKey;

    fn is_signature_valid(&self) -> bool {
        self.get_signing_key().verify(&self, self.get_signature()).is_ok()
    }
}

trait SignedStateChange<H>: StateChange<H> + Sign {}
trait SignedCrdt: Crdt<H, S: SignedStateChange<H>> {}


// Layer 3: Validated Signed CRDT State Changes
//
// CRDT State changes are validated to determine if they should be included in the total set of state changes,
// used to derive the end state.
//
// We *could* simply ignore the invalid state changes via the CRDT merge function.
// But we view invalid state change as a form of *bad behavior*.
// In order to respond to such *bad behavior*, we must keep track of it separately from other state changes.

enum Validation<H: Hash> {
    Valid,
    Invalid,
    MissingDependencies(HashSet<H>)
}

trait Validate<H: Hash>: DependOn<H> {
    fn validate(&self) -> Validation<H>;
}

trait ValidatedSignedStateChange<H>: SignedStateChange<H> + Validate {}
trait ValidatedSignedCrdt: Crdt<H, S: ValidatedSignedStateChange<H>> {
    /// Get the set of all state changes by Validation status
    fn get_state_changes_by_validation(&self, validation: Validation<T>) -> HashSet<S> {
        self.get_state_changes().into_iter().flat_map(|s| match s.validate() {
            validation => Some(s),
            _ => None,
        }).collect()
    }

    /// Get the set of all valid state changes
    fn get_valid_state_changes(&self) -> HashSet<S> {
        self.get_state_changes_by_validation(Validation::Valid)
    }

    /// Get the set of all invalid state changes
    fn get_invalid_state_changes(&self) -> HashSet<S> {
        self.get_state_changes_by_validation(Validation::Invalid)
    }

    /// Get the set of all state changes missing validation dependencies
    fn get_state_changes_missing_validation_dependencies(&self) -> HashSet<S> {
        self.get_state_changes_by_validation(Validation::MissingDependencies)
    }
}


// Layer 4.1: A working DHT. Are we done yet?
trait ValidatedSignedStateChangeDht<H: Hash, S: ValidatedSignedStateChange> {
    fn get(&self, h: H) -> S;
    fn put(&self, state_change: S) -> H;
}

// We could stop here. This provides the base layer for a fully functioning DHT comprised of validated, signed, crdt state changes.
//
// However, it does not provide 3 properties we want in our DHT:
//
// 1. Ability to store state changes at a *different* hash than its own.
// 2. Ability to store state changes at *multiple* hashes.
// 3. Ability to run *different* validation on a state change, for each hash it is stored at.
//
// So no, we are not done yet.


// Layer 4.2: Addressed Validated Signed CRDT State Changes 
//
// An Address is different from a Hash:
// A CRDT State Change only has one Hash, but it can be stored at multiple Addresses.
//
// Every CRDT State Change has a set of Addresses where it can be found.
// The set of Addresses must be deterministically generated from the State Change itself.
//
// From this, we can now now storing multiple state changes at a single Address.

struct Address<H: Hash>(H);

trait Address {
    fn get_addresses(&self) -> Vec<Address>;
}

trait AddressedValidatedSignedStateChange<H>: ValidatedSignedStateChange<H> + Address {}

trait AddressedValidatedSignedStateChangeDht<H: Hash, A: Address, S: AddressedValidatedSignedStateChange> {
    fn get(&self, h: H) -> S;
    fn put(&self, state_change: S) -> H;
    fn get_at_address(&self, address: Address) -> Option<HashSet<S>>;
    fn get_hashes_at_address(&self, address: Address) -> Option<HashSet<H>>;
}


// Layer 4.3: Address-Validated Signed CRDT State Changes 
//
// We unify the previous two layers of Addressed and Validated
//
// Instead of validating a Signed CRDT State Change,
// we now validate a Signed CRDT State Change *at* an Address.
//
// We now can have different validation logic depending on the address,
// which allows us to split up the overall validation logic,
// into smaller units of logic that run on different addresses,
// because we expect *other* related state changes to be stored at that address.
//
// And those other related state changes are are used in our validation logic.

trait AddressValidated<H: Hash>: Address {
    fn validate_at_address(&self, address: Address<H>) -> Validation<H>;
}

trait AddressedValidatedSignedStateChange<H>: SignedStateChange<H> + Address + AddressValidated {}


// Layer 5: Address-Context
//
// This is not strictly necessary,
// but for ease of developer experience, we add an additional concept of Address-Context
//
// This is a human-understandable "hint" of what kind of validation should be performed at that Address

trait Context {
    fn get_contexts(&self) -> HashSet<String>;
}

trait AddressContext: From<Context> + From<Address> {}

trait AddressContextValidated<H: Hash, C: Context>: AddressValidated {
    fn validate_for_context(&self, context: C) -> Validation<H>;
}

trait AddressedContextValidatedSignedStateChange<H>: AddressedValidatedSignedStateChange + AddressContextValidated {}



// The final product: A DHT of Address-Context-Validated, Signed, CRDT State Changes

struct AddressedContextValidatedSignedStateChangeDht<H: Hash> {
    // The full set of state changes
    state_changes: HashMap<dyn AddressedContextValidatedSignedStateChange>,

    // A map of Address -> Set of hashes stored there
    address_hashes: BTreeMap<Address<H>, HashSet<H>>,
}

impl AddressedContextValidatedSignedStateChangeDht<H: Hash> {
    fn get(&self, h: H) -> Option<dyn AddressedContextValidatedSignedStateChange> {
        self.state_changes.get(h)
    }

    fn put(&self, state_change: dyn AddressedContextValidatedSignedStateChange) -> Option<HashSet<dyn AddressedContextValidatedSignedStateChange>> {
        // Add state change to state_changes set
        self.state_changes.insert(state_change);

        // Derive the hash of the state change
        let hash = hash(state_change);

        // Get all the addresses for the state change
        let addresses = state_change.get_addresses();

        // Add the hash to all the addresses
        for a in addresses {
            let mut hashes_at_address = self.address_hashes.get(a).unwrap_or_default();
            hashes_at_address.insert(hash);
        }
    }

    fn get_at_address(&self, address: Address<H>) -> Option<HashSet<dyn ValidatedSignedStateChange>> {
        let hashes = self.get_hashes_at_address(address);

        match hashes {
            Some(hashes) => {
                Some(hashes.into_iter().flat_map(|h| self.state_changes.get(&h)).collect())
            }
            _ => None
        }
    }

    fn get_hashes_at_address(&self, address: Address<H>) -> Option<HashSet<dyn ValidatedSignedStateChange>> {
        self.address_hashes.get(&address)
    }
}