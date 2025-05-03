
// However, it does not provide 3 properties we want in our DHT:
//
// 1. Ability to store state changes at a *different* hash than its own.
// 2. Ability to store state changes at *multiple* hashes.
// 3. Ability to run *different* validation on a state change, for each hash it is stored at.




/// Example implementation of a CRUD Object Crdt
enum CrudCrdtSignedStateChange<H: Hash, E: H + Serialize> {
    Create(E),
    Update(H, E),
    Delete(H),
}

impl SignedStateChange<H: Hash> for CrudCrdtSignedStateChange<H, E: H + Serialize> {
    fn get_dependency_hashes(&self) -> BTreeSet<H> {
        match self {
            Self::Create => BTreeSet::with_capacity(0),
            Self::Update(create_hash, ..) => HashSet::from(create_hash),
            Self::Delete(prev_hash) => HashSet::from(prev_hash),
        }
    }
}

trait CrudCrdt<H: Hash, E: H + Serialize>: SignedCrdt<H, CrudCrdtStateChange, E> {
    fn create(&self, data: E) {
        self.add_state_change(CrudCrdtStateChange::Create(data))
    }

    fn update(&self, prev_state_change_hash: H, data: E) -> CrudCrdtStateChange {
        self.add_state_change(CrudCrdtStateChange::Update(prev_state_change_hash, data))
    }

    fn delete(&self, prev_state_change_hash: H) -> CrudCrdtStateChange {
        self.add_state_change(CrudCrdtStateChange::Delete(prev_state_change_hash))
    }

    fn get_merged(&self) -> E {
        let state_changes = self.get_state_changes();

        // Remove deleted items

        // Apply upd        
    }
}

#[derive(Serialize, Hash)]
struct MovieCrudCrdt {
    director: String,
    title: String,
    release_date: u64,
}

impl CrudCrdt<H: Hash, MovieCrudCrdt> for MovieCrudCrdt {}



// Layer 4.3: Address-Context
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

