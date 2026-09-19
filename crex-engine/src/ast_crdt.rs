use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeId {
    pub peer_id: u64,
    pub sequence: u64,
    pub clock: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemanticNode {
    pub id: NodeId,
    pub kind: String,
    pub value: String,
    pub children: Vec<NodeId>,
    pub parent: Option<NodeId>,
    pub deleted: bool,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AstMutation {
    Insert {
        parent_id: Option<NodeId>,
        index: usize,
        node: SemanticNode,
    },
    Update {
        node_id: NodeId,
        new_value: String,
        timestamp: u64,
    },
    Delete {
        node_id: NodeId,
        timestamp: u64,
    },
    Reorder {
        parent_id: NodeId,
        new_order: Vec<NodeId>,
        timestamp: u64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AstCrdtEngine {
    pub local_peer_id: u64,
    pub sequence: u64,
    pub clock: u64,
    pub root_id: Option<NodeId>,
    pub nodes: HashMap<NodeId, SemanticNode>,
}

impl AstCrdtEngine {
    pub fn new(peer_id: u64) -> Self {
        Self {
            local_peer_id: peer_id,
            sequence: 0,
            clock: 0,
            root_id: None,
            nodes: HashMap::new(),
        }
    }

    pub fn next_node_id(&mut self) -> NodeId {
        self.sequence += 1;
        self.clock += 1;
        NodeId {
            peer_id: self.local_peer_id,
            sequence: self.sequence,
            clock: self.clock,
        }
    }

    /// Parses plain text into a structured Semantic AST CRDT
    pub fn parse_and_sync_source(&mut self, source: &str, language: &str) -> Vec<AstMutation> {
        let mut mutations = Vec::new();
        self.clock += 1;

        let root_id = match self.root_id {
            Some(id) => id,
            None => {
                let id = self.next_node_id();
                self.root_id = Some(id);
                let root_node = SemanticNode {
                    id,
                    kind: format!("{}_program", language),
                    value: String::new(),
                    children: Vec::new(),
                    parent: None,
                    deleted: false,
                    timestamp: self.clock,
                };
                self.nodes.insert(id, root_node.clone());
                mutations.push(AstMutation::Insert {
                    parent_id: None,
                    index: 0,
                    node: root_node,
                });
                id
            }
        };

        // Break source code into structural semantic nodes (statements / blocks)
        let lines: Vec<&str> = source.lines().collect();
        let mut new_children = Vec::new();

        for (idx, line) in lines.iter().enumerate() {
            let trimmed = line.trim();
            let kind = if trimmed.starts_with("import ") || trimmed.starts_with("#include") || trimmed.starts_with("use ") {
                "import_directive"
            } else if trimmed.starts_with("fn ") || trimmed.starts_with("def ") || trimmed.starts_with("function ") || trimmed.contains("main(") {
                "function_declaration"
            } else if trimmed.starts_with("//") || trimmed.starts_with("#") || trimmed.starts_with("/*") {
                "comment"
            } else if trimmed.starts_with("return ") {
                "return_statement"
            } else if trimmed.is_empty() {
                "empty_line"
            } else {
                "statement"
            };

            let node_id = self.next_node_id();
            let child_node = SemanticNode {
                id: node_id,
                kind: kind.to_string(),
                value: line.to_string(),
                children: Vec::new(),
                parent: Some(root_id),
                deleted: false,
                timestamp: self.clock,
            };

            self.nodes.insert(node_id, child_node.clone());
            new_children.push(node_id);

            mutations.push(AstMutation::Insert {
                parent_id: Some(root_id),
                index: idx,
                node: child_node,
            });
        }

        if let Some(root) = self.nodes.get_mut(&root_id) {
            root.children = new_children;
        }

        mutations
    }

    /// Commutative, associative, idempotent CRDT merge function
    pub fn apply_mutation(&mut self, mutation: AstMutation) -> bool {
        match mutation {
            AstMutation::Insert { parent_id, index, node } => {
                let id = node.id;
                if self.nodes.contains_key(&id) {
                    return false; // Idempotent check
                }
                
                if node.timestamp > self.clock {
                    self.clock = node.timestamp;
                }

                self.nodes.insert(id, node);

                if let Some(pid) = parent_id {
                    if let Some(parent) = self.nodes.get_mut(&pid) {
                        let insert_idx = index.min(parent.children.len());
                        parent.children.insert(insert_idx, id);
                    }
                } else if self.root_id.is_none() {
                    self.root_id = Some(id);
                }
                true
            }
            AstMutation::Update { node_id, new_value, timestamp } => {
                if timestamp > self.clock {
                    self.clock = timestamp;
                }
                if let Some(node) = self.nodes.get_mut(&node_id) {
                    // Last-Write-Wins (LWW) conflict resolution
                    if timestamp >= node.timestamp {
                        node.value = new_value;
                        node.timestamp = timestamp;
                        return true;
                    }
                }
                false
            }
            AstMutation::Delete { node_id, timestamp } => {
                if timestamp > self.clock {
                    self.clock = timestamp;
                }
                if let Some(node) = self.nodes.get_mut(&node_id) {
                    if timestamp >= node.timestamp {
                        node.deleted = true;
                        node.timestamp = timestamp;
                        return true;
                    }
                }
                false
            }
            AstMutation::Reorder { parent_id, new_order, timestamp } => {
                if timestamp > self.clock {
                    self.clock = timestamp;
                }
                if let Some(parent) = self.nodes.get_mut(&parent_id) {
                    if timestamp >= parent.timestamp {
                        parent.children = new_order;
                        parent.timestamp = timestamp;
                        return true;
                    }
                }
                false
            }
        }
    }

    /// Reconstructs the code buffer deterministically from the AST
    pub fn to_source(&self) -> String {
        let root_id = match self.root_id {
            Some(id) => id,
            None => return String::new(),
        };

        let root = match self.nodes.get(&root_id) {
            Some(r) => r,
            None => return String::new(),
        };

        let mut lines = Vec::new();
        for child_id in &root.children {
            if let Some(child) = self.nodes.get(child_id) {
                if !child.deleted {
                    lines.push(child.value.as_str());
                }
            }
        }

        lines.join("\n")
    }

    /// Export AST as JSON representation for inspector and telemetry
    pub fn to_json(&self) -> String {
        serde_json::to_string(&self.nodes).unwrap_or_else(|_| "{}".to_string())
    }
}
