use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Unique identifier for an AST Node in the document
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AstNodeId {
    pub client_id: u64,
    pub counter: u64,
}

/// Structural AST Node representation
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AstNode {
    pub id: AstNodeId,
    pub parent_id: Option<AstNodeId>,
    pub kind: String,        // e.g. "function_item", "binary_expression", "identifier", "block"
    pub text: Option<String>,// Leaf text content
    pub range: AstRange,
    pub children: Vec<AstNodeId>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct AstRange {
    pub start_byte: usize,
    pub end_byte: usize,
    pub start_point: (usize, usize), // line, column
    pub end_point: (usize, usize),
}

/// Semantic AST CRDT Operation
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AstMutation {
    NodeInserted {
        node: AstNode,
        parent_id: Option<AstNodeId>,
        index: usize,
    },
    NodeDeleted {
        id: AstNodeId,
    },
    NodeReplaced {
        id: AstNodeId,
        new_text: String,
        new_kind: String,
    },
    NodeMoved {
        id: AstNodeId,
        new_parent_id: Option<AstNodeId>,
        new_index: usize,
    },
}

/// Binary AST Delta payload ready for peer-to-peer WebSockets/WebRTC synchronization
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AstSyncDelta {
    pub client_id: u64,
    pub lamport_ts: u64,
    pub vector_clock: HashMap<u64, u64>,
    pub mutations: Vec<AstMutation>,
}

/// AST CRDT State Machine
pub struct AstCrdtEngine {
    pub client_id: u64,
    pub lamport_ts: u64,
    pub vector_clock: HashMap<u64, u64>,
    pub nodes: HashMap<AstNodeId, AstNode>,
    pub root_children: Vec<AstNodeId>,
}

impl AstCrdtEngine {
    pub fn new(client_id: u64) -> Self {
        let mut vector_clock = HashMap::new();
        vector_clock.insert(client_id, 0);

        Self {
            client_id,
            lamport_ts: 0,
            vector_clock,
            nodes: HashMap::new(),
            root_children: Vec::new(),
        }
    }

    pub fn next_id(&mut self) -> AstNodeId {
        self.lamport_ts += 1;
        let counter = self.vector_clock.entry(self.client_id).or_insert(0);
        *counter += 1;
        AstNodeId {
            client_id: self.client_id,
            counter: *counter,
        }
    }

    /// Creates and applies a node insertion mutation locally
    pub fn insert_node(
        &mut self,
        kind: String,
        text: Option<String>,
        range: AstRange,
        parent_id: Option<AstNodeId>,
        index: usize,
    ) -> AstSyncDelta {
        let node_id = self.next_id();
        let node = AstNode {
            id: node_id.clone(),
            parent_id: parent_id.clone(),
            kind,
            text,
            range,
            children: Vec::new(),
        };

        let mutation = AstMutation::NodeInserted {
            node: node.clone(),
            parent_id: parent_id.clone(),
            index,
        };

        self.apply_mutation(mutation.clone());

        AstSyncDelta {
            client_id: self.client_id,
            lamport_ts: self.lamport_ts,
            vector_clock: self.vector_clock.clone(),
            mutations: vec![mutation],
        }
    }

    /// Replaces node content semantically
    pub fn replace_node(
        &mut self,
        id: AstNodeId,
        new_text: String,
        new_kind: String,
    ) -> AstSyncDelta {
        self.lamport_ts += 1;
        let mutation = AstMutation::NodeReplaced {
            id,
            new_text,
            new_kind,
        };

        self.apply_mutation(mutation.clone());

        AstSyncDelta {
            client_id: self.client_id,
            lamport_ts: self.lamport_ts,
            vector_clock: self.vector_clock.clone(),
            mutations: vec![mutation],
        }
    }

    /// Applies an AST mutation deterministically
    pub fn apply_mutation(&mut self, mutation: AstMutation) {
        match mutation {
            AstMutation::NodeInserted { node, parent_id, index } => {
                let id = node.id.clone();
                self.nodes.insert(id.clone(), node);

                if let Some(pid) = parent_id {
                    if let Some(parent) = self.nodes.get_mut(&pid) {
                        let idx = index.min(parent.children.len());
                        parent.children.insert(idx, id);
                    }
                } else {
                    let idx = index.min(self.root_children.len());
                    self.root_children.insert(idx, id);
                }
            }
            AstMutation::NodeDeleted { id } => {
                if let Some(node) = self.nodes.remove(&id) {
                    if let Some(pid) = node.parent_id {
                        if let Some(parent) = self.nodes.get_mut(&pid) {
                            parent.children.retain(|c| *c != id);
                        }
                    } else {
                        self.root_children.retain(|c| *c != id);
                    }
                }
            }
            AstMutation::NodeReplaced { id, new_text, new_kind } => {
                if let Some(node) = self.nodes.get_mut(&id) {
                    node.text = Some(new_text);
                    node.kind = new_kind;
                }
            }
            AstMutation::NodeMoved { id, new_parent_id, new_index } => {
                // Remove from old parent
                if let Some(node) = self.nodes.get(&id) {
                    let old_pid = node.parent_id.clone();
                    if let Some(pid) = old_pid {
                        if let Some(parent) = self.nodes.get_mut(&pid) {
                            parent.children.retain(|c| *c != id);
                        }
                    } else {
                        self.root_children.retain(|c| *c != id);
                    }
                }

                // Insert into new parent
                if let Some(pid) = &new_parent_id {
                    if let Some(parent) = self.nodes.get_mut(pid) {
                        let idx = new_index.min(parent.children.len());
                        parent.children.insert(idx, id.clone());
                    }
                } else {
                    let idx = new_index.min(self.root_children.len());
                    self.root_children.insert(idx, id.clone());
                }

                if let Some(node) = self.nodes.get_mut(&id) {
                    node.parent_id = new_parent_id;
                }
            }
        }
    }

    /// Ingests remote sync delta from peer
    pub fn merge_remote_delta(&mut self, delta: AstSyncDelta) {
        self.lamport_ts = self.lamport_ts.max(delta.lamport_ts) + 1;
        let peer_counter = delta.vector_clock.get(&delta.client_id).copied().unwrap_or(0);
        let curr = self.vector_clock.entry(delta.client_id).or_insert(0);
        *curr = (*curr).max(peer_counter);

        for mutation in delta.mutations {
            self.apply_mutation(mutation);
        }
    }

    /// Serializes delta into a binary or JSON string payload
    pub fn serialize_delta(&self, delta: &AstSyncDelta) -> Result<String, String> {
        serde_json::to_string(delta).map_err(|e| e.to_string())
    }

    /// Deserializes delta from payload
    pub fn deserialize_delta(payload: &str) -> Result<AstSyncDelta, String> {
        serde_json::from_str(payload).map_err(|e| e.to_string())
    }
}
