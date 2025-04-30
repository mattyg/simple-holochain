// WIP  -what might app validation look like?
// This is not complete or sensible yet

use crate::dht::*;
use blake3::Hash;

enum LinkType {
    PostToComments
}

enum EntryType {
    Post(Post),
    Comment(Comment),
}

struct Post {
    title: String,
    text: String,
}

struct Comment {
    post_hash: Hash,
    text: String,
}

impl AppValidate for LinkStateChange {
    fn validate(&self, location_context: LocationContext) -> Validation {
        Validation::Valid
    }
}

// How the app validation callback could look
fn validate_link_state_change(state_change: LinkStateChange, context: LocationContext) {
    match state_change {
        LinkStateChange::Create(record) => {
            match record.action {
                Create => {
                    match context {
                        LocationContext::Author => {

                        },
                        _ => {

                        }
                    }
                }
                Delete => {

                }
            }
        },
        LinkStateChange::Delete(record) => {
            match record.action {
                Create => {
                        
                }
                Delete => {
    
                }
            }
        }
    }
}