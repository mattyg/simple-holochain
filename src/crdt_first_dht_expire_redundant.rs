

// Expiration of State Changes
// 
// If a state change is expired, it can be safely removed from the DHT.
// By default, a state change will never expire.
//
// We must retain the *tombstone* state change, which includes the hashes of the expired state changes.
//
// This allows us to pass those expired hashes down to the network layer,
// so that we never attempt to fetch them during gossip rounds.
//
// We may want an state change to expire only after it has been deleted AND some additional time period has passed.
// This means that a node will store and gossip the deleted state changes for some additional time.
//
// This leeway time means that a node that comes online and receives gossip during that time, who did *not* have the deleted state changes, 
// can receive them, and then validate the Delete against them.
//
// For nodes who do *not* come online and receive gossip during that time, they will be stuck with Validation::MissingDependencies forever.
// Likely they will eventually want to give up on trying to get the state change during gossip. Or continue trying with an ever increasing exponential backoff.
trait Expire {
    /// Which dependencies of this state change will it cause to expire?
    /// 
    /// Note that these may *not* actually be allowed to be expired yet,
    /// as that is specified by the function `is_dependency_expired`.
    fn get_dependencies_to_expire(&self) -> BTreeSet<H> {
        BTreeSet::with_capacity(0)
    }

    // Is this particular dependency state change expired yet?
    fn is_dependency_expired(&self, h: H) -> bool {
        false
    }

    /// Optionally, the `get_expired_dependency_state_change_hashes` logic can choose to expire a state change
    /// based on the time it was received.
    /// 
    /// This can be used to ensure greater availability of the expired data as it syncs across the network,
    /// while still ensuring that every node will expire the data.
    fn received_at(&self) -> u64;
}

trait ExpiredAddressedContextValidatedSignedStateChange<H: Hash, A: Address<H>>: AddressedContextValidatedSignedStateChange<H> + Expire { }


trait ExpiredContextAddressedValidatedSignedStateChangeHashMap<H: Hash, A: Address<H>, S: AddressedValidatedSignedStateChange> {
    fn get(&self, h: H) -> Option<S>;
    fn put(&self, state_change: S) -> Option<H>;
    fn get_at_address(&self, address: A) -> Option<HashSet<S>>;
    fn get_address_hashes(&self, address: A) -> Option<BTreeSet<H>>;
}


struct ExpiredAddressedContextValidatedSignedStateChangeHashMap<H: Hash, A: Address<H>> {
    // The full set of state changes
    state_changes: HashMap<dyn RedundantExpiredAddressedContextValidatedSignedStateChange>,

    // A map of Address -> Set of hashes stored there
    //
    // All hashes in this map MUST exist in state_changes
    address_hashes: BTreeMap<A, BTreeSet<H>>,

    // The set of hashes that have been expired.
    //
    // All hashes in this set MUST NOT exist in state_changes
    //
    // We store these to pass down to the network layer,
    // so we never request them via gossip.
    expired_hashes: BTreeSet<H>,
}

/// TODO
/// 
/// Still need to add a "garbage_collect()" and "remove_state_change()" and "get_expired_hashes" function on the Crdt type
/// which checks the expiration of everything and then removes it from the store.
/// 



// Deduplicatation of redundant State Changes
//
// Multiple State Changes can be treated as *redundant*,
// even if they are not equivalent.
//
// Two State Changes may be redundant if one contains all the information in the other,
// plus some additional information. I.e. it "supersedes" the other.
//
// We must preserve the hash of the redundant data, so that any references to one are treated as references to the other.
// We must pass the redundant hash down to the network layer, to ensure we never request it via gossip.

trait Redundant {
    /// If state changes are not redundant, returns None.
    /// 
    /// Otherwise returns the state change that should be treated as "canonical". I.e the one to preserve.
    /// i.e. Some(self) or Some(other)
    /// 
    /// By default, two state changes are not treated as redundant, unless they are equivalent.
    fn get_canonical(&self, other: Self) -> Option<Self> {
        if self == other {
            return Some(self);
        }

        None
    }
}

trait RedundantExpiredAddressedContextValidatedSignedStateChange<H: Hash>: AddressedContextValidatedSignedStateChange<H> + Redundant {}


struct RedundantExpiredAddressedContextValidatedSignedStateChangeHashMap<H: Hash, A: Address<H>> {
    // The full set of state changes
    state_changes: HashMap<dyn RedundantExpiredAddressedContextValidatedSignedStateChange>,

    // A map of Address -> Set of hashes stored there
    //
    // All hashes in this map MUST exist in state_changes
    address_hashes: BTreeMap<A, BTreeSet<H>>,

    // The set of hashes that have been expired.
    //
    // All hashes in this set MUST NOT exist in state_changes
    //
    // We store these to pass down to the network layer,
    // so we never request them via gossip.
    expired_hashes: BTreeSet<H>,

    // The map of all hashes to treat as redundant.
    //
    // A hashes used as *value* are the "canonical" hash, and MUST exist in state_changes.
    //
    // We store these to easily transform a query for a redundant hash,
    // into a query for its canonical hash.
    redundant_hashes: BTreeMap<H, H>,
}



impl AddressValidatedAddressedSignedStateChangeHashMap<H: Hash> {
    fn get(&self, h: H) -> Option<dyn AddressedValidatedSignedStateChange> {
        self.state_changes.get(h)
    }

    fn put(&self, state_change: dyn AddressedContextValidatedSignedStateChange) -> Option<H> {
        match state_change.validate() {
            Validation::Valid => {
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
                Some(hash)
            },
            _ => None
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
