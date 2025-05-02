use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use rmp_serde::Serializer;
use blake3::{Hash, hash};


// Layer 1: Basic source chain constructs

#[derive(Serialize, Deserialize)]
pub struct ActionMetadata {
    author: Hash,
    prev_action_hash: Hash,
}

#[derive(Serialize, Deserialize)]
pub struct Action<T: Serialize> {
    metadata: ActionMetadata,
    content: T
}

impl<T: Serialize> Action<T> {
    fn hash(&self) -> Hash {
        let mut buf = Vec::new();
        self.serialize(&mut Serializer::new(&mut buf)).unwrap();
        hash(&buf)
    }
}

#[derive(Serialize, Deserialize)]
pub struct Record<T: Serialize, E: Serialize> {
    signature: Hash,
    action: Action<T>,
    entry: E
}

#[derive(Serialize, Deserialize)]
pub struct Empty;


// Layer 2: Higher-level abstractions: CRUD Objects, Links, and SourceChain

#[derive(Serialize, Deserialize)]
pub struct Link<T: Serialize> {
    // The index of this link type in the LinkTypes enum
    type_enum_unit: u8,

    base: Hash,
    target: Hash,
    tag: T
}

#[derive(Serialize, Deserialize)]
pub struct LinkDeleteData {
    base: Hash,
    create_link_hash: Hash
}

// We currently call this an "entry", but that is misleading.
// In the source chain an "entry" means a blob of arbitrary bytes <= 4MB
//
// This is a higher-level abstraction built upon actions and entries, that provides CRUD (whereas entries only provide "create").
// I'm renaming this to CrudObject for clarity
#[derive(Serialize, Deserialize)]
pub struct CrudObject<T: Serialize>(T);

pub struct CrudObjectData<T: Serialize> {
    // The index of this link type in the CrudObjectTypes enum
    type_enum_unit: u8,

    data: T
}


// This is a higher-level abstraction, that provides open & close (whereas the source chain only provides "append")
#[derive(Serialize, Deserialize)]
pub struct SourceChain;

#[derive(Serialize, Deserialize)]
pub struct SourceChainOpenData {
    author: Hash,
    dna: Hash,
    proof: Vec<u8>,
}


// Layer 3: Available state changes to Links, CrudObjects, and SourceChains
// These sets of state changes must merge to a deterministic end state. Each is a CRDT object.

pub enum LinkStateChange<T: Serialize> {
    Create(Record<Link<T>, Empty>),
    Delete(Record<LinkDeleteData, Empty>)
}

pub enum CrudObjectStateChange<T: Serialize> {
    Create(Record<Empty, CrudObject<T>>),
    Update(Record<Hash, CrudObject<T>>),
    Delete(Record<Hash, Empty>)
}

pub enum SourceChainStateChange {
    Open(Record<SourceChainOpenData, Empty>),
    Close(Record<Empty, Empty>)
}


// Layer 4: State Changes can be located at multiple Addresses, each with a different LocationContext

pub struct Address([u8; 4]);

// Last 4 bytes of a hash is its location
impl From<Hash> for Address {
    fn from(val: Hash) -> Self {
        let val_bytes = val.as_bytes();
        let last_4_bytes: [u8; 4] = val_bytes[val_bytes.len()-4..val_bytes.len()].try_into().unwrap();
        Self(last_4_bytes)
    }
}

// The context of a location is a hint of what data can we expect to be stored there
pub enum LocationContext {
    // All Records by this author are stored here
    Author,

    // A single Record (action + entry) is stored here
    Record,

    // All LinkCreate and LinkDelete with the same base hash are stored here
    LinkStateChangeReference,

    // All CrudObjectCreate and associated CrudObjectUpdate and CrudObjectDelete are stored here
    CrudObjectStateChangeReference,
}

pub struct Location {
    address: Address,
    context: LocationContext
}

trait Locate {
    fn locations(&self) -> Vec<Location>;
}

pub enum Validation {
    Valid,
    Invalid,
    MissingDependency(Hash)
}

trait SysValidate {
    fn validate(&self, location_context: LocationContext) -> Validation;
}

trait AppValidate {
    // App Validation is valid by default
    fn validate(&self, location_context: LocationContext) -> Validation {
        Validation::Valid
    }
}

trait LocateValidate: Locate + SysValidate + AppValidate {}


// Layer 5: The Dht is a map of location -> list of LocateValidate pub structs

pub struct Dht(HashMap<Location, Vec<Box<dyn LocateValidate>>>);

impl<T: Serialize> Locate for LinkStateChange<T> {
    fn locations(&self) -> Vec<Location> {
        let action_hash = match self {
            LinkStateChange::Create(r) => r.action.hash(),
            LinkStateChange::Delete(r) => r.action.hash(),
        };

        let author = match self {
            LinkStateChange::Create(r) => r.action.metadata.author,
            LinkStateChange::Delete(r) => r.action.metadata.author,
        };

        let base = match self {
            LinkStateChange::Create(r) => r.action.content.base,
            LinkStateChange::Delete(r) => r.action.content.base,
        };

        vec![
            // Author hash
            Location {
                address: author.into(),
                context: LocationContext::Author
            },
            
            // Location of this action
            Location {
                address: action_hash.into(),
                context: LocationContext::Record
            },

            // Base hash of create link
            Location {
                address: base.into(),
                context: LocationContext::Record
            }
        ]
    }
}

impl<T: Serialize> SysValidate for LinkStateChange<T> {
    fn validate(&self, location_type: LocationContext) -> Validation {
        match self {
            LinkStateChange::Create(record) => {
                // validate action signature

                // validate link tag <= 1kb
            }
            LinkStateChange::Delete(record) => {
                // validate action signature
            }
        };

        match location_type {
            LocationContext::Author => {
                // validate chain pub structure back to genesis
            }
            LocationContext::LinkStateChangeReference => {
                // validate referenced link has the same base as new link
                // validate referenced link is a LinkCreate and new link is a LinkDelete
            }
            LocationContext::CrudObjectStateChangeReference => {
                // validate referenced crud object state change chain back to CrudObjectCreate
                // validate previous referenced crud object state change is not a CrudObjectDelete 
            },
            _ => {}
        }

        return Validation::Valid;
    }
}


// Dht can be queried via an api

trait DhtApi {
    fn get_action<T: Serialize, E: Serialize>(&self, hash: Hash) -> Option<Record<T, E>>;
    fn get_entry<T: Serialize, E: Serialize>(&self, hash: Hash) -> Option<Record<T, E>>;
    fn get_links<T: Serialize>(&self, base: Hash) -> Vec<Record<Link<T>, Empty>>;
    
    fn create_link<T: Serialize>(&self, link: Link<T>) -> Record<Link<T>, Empty>;
    fn delete_link(&self, hash: Hash) -> Record<LinkDeleteData, Empty>;
    
    fn create_crud_object<T: Serialize>(&self, entry: T) -> Record<Empty, CrudObject<T>>;
    fn update_crud_object<T: Serialize>(&self, hash: Hash, entry: T) -> Record<Hash, CrudObject<T>>;
    fn delete_crud_object<T: Serialize>(&self, hash: Hash) -> Record<Hash, Empty>;

    fn open_chain_object(&self, agent: Hash, dna: Hash, proof: Vec<u8>) -> Record<SourceChainOpenData, Empty>;
    fn close_chain_object(&self, agent: Hash, dna: Hash, proof: Vec<u8>) -> Record<Empty, Empty>;
}

impl DhtApi for Dht {
    fn get_action<T: Serialize, E: Serialize>(&self, hash: Hash) -> Option<Record<T, E>> {
        todo!()
    }

    fn get_entry<T: Serialize, E: Serialize>(&self, hash: Hash) -> Option<Record<T, E>> {
        todo!()
    }

    fn get_links<T: Serialize>(&self, base: Hash) -> Vec<Record<Link<T>, Empty>> {
        todo!()
    }

    fn create_link<T: Serialize>(&self, link: Link<T>) -> Record<Link<T>, Empty> {
        todo!()
    }

    fn delete_link(&self, hash: Hash) -> Record<LinkDeleteData, Empty> {
        todo!()
    }

    fn create_crud_object<T: Serialize>(&self, entry: T) -> Record<Empty, CrudObject<T>> {
        todo!()
    }

    fn update_crud_object<T: Serialize>(&self, hash: Hash, entry: T) -> Record<Hash, CrudObject<T>> {
        todo!()
    }

    fn delete_crud_object<T: Serialize>(&self, hash: Hash) -> Record<Hash, Empty> {
        todo!()
    }

    fn open_chain_object(&self, agent: Hash, dna: Hash, proof: Vec<u8>) -> Record<SourceChainOpenData, Empty> {
        todo!()
    }

    fn close_chain_object(&self, agent: Hash, dna: Hash, proof: Vec<u8>) -> Record<Empty, Empty> {
        todo!()
    }
}