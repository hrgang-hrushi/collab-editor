use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AstNodeId {
    pub client_id: u64,
    pub clock: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AstOperation {
    InsertNode {
        id: AstNodeId,
        parent_id: Option<AstNodeId>,
        kind: String,
        text: String,
    },
    DeleteNode {
        id: AstNodeId,
    },
    UpdateText {
        id: AstNodeId,
        text: String,
    },
}

pub struct AstCrdt {
    pub client_id: u64,
    pub clock: u64,
    pub nodes: HashMap<AstNodeId, String>,
}

impl AstCrdt {
    pub fn new(client_id: u64) -> Self {
        Self {
            client_id,
            clock: 0,
            nodes: HashMap::new(),
        }
    }

    pub fn insert_node(&mut self, kind: &str, text: &str) -> (AstNodeId, AstOperation) {
        self.clock += 1;
        let id = AstNodeId {
            client_id: self.client_id,
            clock: self.clock,
        };
        self.nodes.insert(id.clone(), text.to_string());
        let op = AstOperation::InsertNode {
            id: id.clone(),
            parent_id: None,
            kind: kind.to_string(),
            text: text.to_string(),
        };
        (id, op)
    }

    pub fn apply_remote_op(&mut self, op: AstOperation) {
        match op {
            AstOperation::InsertNode { id, text, .. } => {
                self.clock = self.clock.max(id.clock) + 1;
                self.nodes.insert(id, text);
            }
            AstOperation::DeleteNode { id } => {
                self.nodes.remove(&id);
            }
            AstOperation::UpdateText { id, text } => {
                if let Some(existing) = self.nodes.get_mut(&id) {
                    *existing = text;
                }
            }
        }
    }
}
