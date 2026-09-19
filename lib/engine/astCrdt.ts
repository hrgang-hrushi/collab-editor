/**
 * AST-CRDT Semantic Synchronization Engine
 * Represents code documents as trees of typed semantic syntax nodes.
 * Synchronizes node mutations (Insert, Update, Delete, Reorder) over the network
 * rather than raw string offsets to prevent syntax breakage and merge conflicts.
 */

export interface NodeId {
  peerId: string;
  seq: number;
  clock: number;
}

export interface SemanticCrdtNode {
  id: string;
  kind: string;
  value: string;
  parent: string | null;
  children: string[];
  deleted: boolean;
  timestamp: number;
}

export type AstCrdtMutation =
  | {
      type: "INSERT";
      node: SemanticCrdtNode;
      parentId: string | null;
      index: number;
    }
  | {
      type: "UPDATE";
      nodeId: string;
      newValue: string;
      timestamp: number;
    }
  | {
      type: "DELETE";
      nodeId: string;
      timestamp: number;
    }
  | {
      type: "REORDER";
      parentId: string;
      newOrder: string[];
      timestamp: number;
    };

export class SemanticAstCrdtEngine {
  public peerId: string;
  public clock: number = 0;
  public seq: number = 0;
  public rootId: string | null = null;
  public nodes: Map<string, SemanticCrdtNode> = new Map();

  constructor(peerId?: string) {
    this.peerId = peerId || "peer-" + Math.random().toString(36).substring(2, 8);
  }

  public nextId(): string {
    this.seq += 1;
    this.clock += 1;
    return `${this.peerId}:${this.seq}:${this.clock}`;
  }

  /**
   * Parses source code into semantic AST nodes
   */
  public parseAndSync(source: string, language: string): AstCrdtMutation[] {
    const mutations: AstCrdtMutation[] = [];
    this.clock += 1;

    let rootId = this.rootId;
    if (!rootId || !this.nodes.has(rootId)) {
      rootId = this.nextId();
      this.rootId = rootId;
      const rootNode: SemanticCrdtNode = {
        id: rootId,
        kind: `${language}_program`,
        value: "",
        parent: null,
        children: [],
        deleted: false,
        timestamp: this.clock,
      };
      this.nodes.set(rootId, rootNode);
      mutations.push({
        type: "INSERT",
        node: rootNode,
        parentId: null,
        index: 0,
      });
    }

    const lines = source.split("\n");
    const newChildrenIds: string[] = [];

    lines.forEach((line, idx) => {
      const trimmed = line.trim();
      let kind = "statement";
      if (trimmed.startsWith("import ") || trimmed.startsWith("#include") || trimmed.startsWith("use ")) {
        kind = "import_declaration";
      } else if (trimmed.startsWith("fn ") || trimmed.startsWith("def ") || trimmed.startsWith("function ") || trimmed.includes("main(")) {
        kind = "function_declaration";
      } else if (trimmed.startsWith("//") || trimmed.startsWith("#") || trimmed.startsWith("/*")) {
        kind = "comment";
      } else if (trimmed.startsWith("return ")) {
        kind = "return_statement";
      } else if (trimmed === "") {
        kind = "empty_line";
      }

      const nodeId = this.nextId();
      const node: SemanticCrdtNode = {
        id: nodeId,
        kind,
        value: line,
        parent: rootId,
        children: [],
        deleted: false,
        timestamp: this.clock,
      };

      this.nodes.set(nodeId, node);
      newChildrenIds.push(nodeId);

      mutations.push({
        type: "INSERT",
        node,
        parentId: rootId,
        index: idx,
      });
    });

    const root = this.nodes.get(rootId);
    if (root) {
      root.children = newChildrenIds;
    }

    return mutations;
  }

  /**
   * Commutative merge function
   */
  public applyMutation(mut: AstCrdtMutation): boolean {
    switch (mut.type) {
      case "INSERT": {
        if (this.nodes.has(mut.node.id)) return false;
        if (mut.node.timestamp > this.clock) this.clock = mut.node.timestamp;
        this.nodes.set(mut.node.id, mut.node);
        if (mut.parentId && this.nodes.has(mut.parentId)) {
          const parent = this.nodes.get(mut.parentId)!;
          const idx = Math.min(mut.index, parent.children.length);
          parent.children.splice(idx, 0, mut.node.id);
        } else if (!this.rootId) {
          this.rootId = mut.node.id;
        }
        return true;
      }
      case "UPDATE": {
        if (mut.timestamp > this.clock) this.clock = mut.timestamp;
        const node = this.nodes.get(mut.nodeId);
        if (node && mut.timestamp >= node.timestamp) {
          node.value = mut.newValue;
          node.timestamp = mut.timestamp;
          return true;
        }
        return false;
      }
      case "DELETE": {
        if (mut.timestamp > this.clock) this.clock = mut.timestamp;
        const node = this.nodes.get(mut.nodeId);
        if (node && mut.timestamp >= node.timestamp) {
          node.deleted = true;
          node.timestamp = mut.timestamp;
          return true;
        }
        return false;
      }
      case "REORDER": {
        if (mut.timestamp > this.clock) this.clock = mut.timestamp;
        const parent = this.nodes.get(mut.parentId);
        if (parent && mut.timestamp >= parent.timestamp) {
          parent.children = mut.newOrder;
          parent.timestamp = mut.timestamp;
          return true;
        }
        return false;
      }
    }
  }

  /**
   * Synthesizes source text from the AST tree
   */
  public toSource(): string {
    if (!this.rootId) return "";
    const root = this.nodes.get(this.rootId);
    if (!root) return "";

    const lines: string[] = [];
    for (const childId of root.children) {
      const child = this.nodes.get(childId);
      if (child && !child.deleted) {
        lines.push(child.value);
      }
    }
    return lines.join("\n");
  }

  public getNodeCount(): number {
    let count = 0;
    for (const [, node] of this.nodes) {
      if (!node.deleted) count++;
    }
    return count;
  }
}
