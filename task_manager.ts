/**
 * Crux Task Manager (TypeScript / Bun / Node)
 * Run: bun run task_manager.ts
 */

export interface Task {
  id: number;
  title: string;
  category: string;
  priority: "P0" | "P1" | "P2";
  status: "TODO" | "IN_PROGRESS" | "DONE";
  createdAt: string;
}

export class TaskManager {
  private tasks: Task[] = [];
  private nextId = 1;

  constructor() {
    this.addTask("Initialize CRDT state sync", "Core", "P0");
    this.addTask("Implement zero-copy PTY stream", "Infra", "P0");
    this.addTask("Build Hardware Brutalist terminal interface", "UI", "P1");
    if (this.tasks[0]) this.tasks[0].status = "DONE";
    if (this.tasks[1]) this.tasks[1].status = "IN_PROGRESS";
  }

  addTask(title: string, category: string = "General", priority: Task["priority"] = "P1"): Task {
    const t: Task = {
      id: this.nextId++,
      title,
      category,
      priority,
      status: "TODO",
      createdAt: new Date().toISOString().slice(0, 16).replace("T", " "),
    };
    this.tasks.push(t);
    return t;
  }

  printTasks(): void {
    console.log("\n+-----+--------------------------------------+------------+---------------+-------------+");
    console.log("| ID  | TITLE                                | CATEGORY   | PRIORITY      | STATUS      |");
    console.log("+-----+--------------------------------------+------------+---------------+-------------+");
    for (const t of this.tasks) {
      const title = t.title.length > 36 ? t.title.slice(0, 33) + "..." : t.title.padEnd(36);
      console.log(`| ${String(t.id).padEnd(3)} | ${title} | ${t.category.padEnd(10)} | ${t.priority.padEnd(13)} | ${t.status.padEnd(11)} |`);
    }
    console.log("+-----+--------------------------------------+------------+---------------+-------------+\n");
  }
}

const manager = new TaskManager();
manager.printTasks();
console.log("[OK] TypeScript task manager engine running.");
