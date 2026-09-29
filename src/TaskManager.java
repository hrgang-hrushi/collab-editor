import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

/**
 * TaskManager - A clean, self-contained CLI Task Management engine.
 * Compile & Run:
 *   javac TaskManager.java && java TaskManager
 */
public class TaskManager {

    public enum Priority {
        P0("P0 // CRITICAL"),
        P1("P1 // HIGH"),
        P2("P2 // NORMAL");

        private final String label;
        Priority(String label) { this.label = label; }
        public String getLabel() { return label; }
    }

    public enum Status {
        TODO("TODO"),
        IN_PROGRESS("IN_PROGRESS"),
        DONE("DONE");

        private final String label;
        Status(String label) { this.label = label; }
        public String getLabel() { return label; }
    }

    public static class Task {
        private final int id;
        private String title;
        private String category;
        private Priority priority;
        private Status status;
        private final String createdAt;

        public Task(int id, String title, String category, Priority priority) {
            this.id = id;
            this.title = title;
            this.category = category;
            this.priority = priority;
            this.status = Status.TODO;
            this.createdAt = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm"));
        }

        public int getId() { return id; }
        public String getTitle() { return title; }
        public String getCategory() { return category; }
        public Priority getPriority() { return priority; }
        public Status getStatus() { return status; }
        public String getCreatedAt() { return createdAt; }

        public void setStatus(Status status) { this.status = status; }
        public void setPriority(Priority priority) { this.priority = priority; }
        public void setTitle(String title) { this.title = title; }
    }

    private final List<Task> tasks = new ArrayList<>();
    private int nextId = 1;

    public TaskManager() {
        addTask("Initialize CRDT state sync", "Core", Priority.P0);
        addTask("Implement zero-copy PTY stream", "Infra", Priority.P0);
        addTask("Build Hardware Brutalist terminal interface", "UI", Priority.P1);
        getTask(1).ifPresent(t -> t.setStatus(Status.DONE));
        getTask(2).ifPresent(t -> t.setStatus(Status.IN_PROGRESS));
    }

    public Task addTask(String title, String category, Priority priority) {
        Task task = new Task(nextId++, title, category, priority);
        tasks.add(task);
        return task;
    }

    public Optional<Task> getTask(int id) {
        return tasks.stream().filter(t -> t.getId() == id).findFirst();
    }

    public boolean deleteTask(int id) {
        return tasks.removeIf(t -> t.getId() == id);
    }

    public List<Task> getAllTasks() {
        return Collections.unmodifiableList(tasks);
    }

    public void printTaskList(List<Task> list) {
        System.out.println("\n+-----+--------------------------------------+------------+---------------+-------------+------------------+");
        System.out.printf("| %-3s | %-36s | %-10s | %-13s | %-11s | %-16s |\n",
                "ID", "TITLE", "CATEGORY", "PRIORITY", "STATUS", "CREATED AT");
        System.out.println("+-----+--------------------------------------+------------+---------------+-------------+------------------+");

        if (list.isEmpty()) {
            System.out.printf("| %-101s |\n", "No tasks found in current view.");
        } else {
            for (Task t : list) {
                String title = t.getTitle().length() > 36 ? t.getTitle().substring(0, 33) + "..." : t.getTitle();
                System.out.printf("| %-3d | %-36s | %-10s | %-13s | %-11s | %-16s |\n",
                        t.getId(), title, t.getCategory(), t.getPriority().name(), t.getStatus().name(), t.getCreatedAt());
            }
        }
        System.out.println("+-----+--------------------------------------+------------+---------------+-------------+------------------+\n");
    }

    public void printStats() {
        long total = tasks.size();
        long done = tasks.stream().filter(t -> t.getStatus() == Status.DONE).count();
        long inProgress = tasks.stream().filter(t -> t.getStatus() == Status.IN_PROGRESS).count();
        long todo = total - done - inProgress;
        System.out.printf("\n[SYSTEM METRICS] TOTAL: %d | TODO: %d | IN_PROGRESS: %d | COMPLETED: %d\n\n", total, todo, inProgress, done);
    }

    public static void main(String[] args) {
        TaskManager manager = new TaskManager();
        Scanner scanner = new Scanner(System.in);

        System.out.println("=================================================");
        System.out.println("            CRUX TASK MANAGER v1.0.0             ");
        System.out.println("=================================================");

        boolean running = true;
        while (running) {
            System.out.println("[MENU]");
            System.out.println("  1. List All Tasks");
            System.out.println("  2. Add New Task");
            System.out.println("  3. Update Task Status (1=TODO, 2=IN_PROGRESS, 3=DONE)");
            System.out.println("  4. Filter by Status");
            System.out.println("  5. Filter by Priority");
            System.out.println("  6. Delete Task");
            System.out.println("  7. System Telemetry / Stats");
            System.out.println("  0. Exit");
            System.out.print("\nSelect option [0-7]: ");

            String input = scanner.hasNextLine() ? scanner.nextLine().trim() : "0";
            switch (input) {
                case "1":
                    manager.printTaskList(manager.getAllTasks());
                    break;
                case "2":
                    System.out.print("Enter task title: ");
                    String title = scanner.nextLine().trim();
                    if (!title.isEmpty()) {
                        System.out.print("Category (Core/Infra/UI/General): ");
                        String cat = scanner.nextLine().trim();
                        System.out.print("Priority (0=P0/CRITICAL, 1=P1/HIGH, 2=P2/NORMAL): ");
                        String pr = scanner.nextLine().trim();
                        Priority p = pr.equals("0") ? Priority.P0 : pr.equals("2") ? Priority.P2 : Priority.P1;
                        Task created = manager.addTask(title, cat.isEmpty() ? "General" : cat, p);
                        System.out.printf("[OK] Task #%d created successfully.\n\n", created.getId());
                    }
                    break;
                case "3":
                    System.out.print("Enter task ID: ");
                    try {
                        int id = Integer.parseInt(scanner.nextLine().trim());
                        manager.getTask(id).ifPresentOrElse(t -> {
                            System.out.print("Select status (1=TODO, 2=IN_PROGRESS, 3=DONE): ");
                            String st = scanner.nextLine().trim();
                            if (st.equals("1")) t.setStatus(Status.TODO);
                            else if (st.equals("2")) t.setStatus(Status.IN_PROGRESS);
                            else if (st.equals("3")) t.setStatus(Status.DONE);
                            System.out.printf("[OK] Task #%d updated to %s.\n\n", id, t.getStatus());
                        }, () -> System.out.printf("[ERR] Task #%d not found.\n\n", id));
                    } catch (Exception e) {
                        System.out.println("[ERR] Invalid task ID.\n");
                    }
                    break;
                case "4":
                    System.out.print("Filter by (1=TODO, 2=IN_PROGRESS, 3=DONE): ");
                    String fs = scanner.nextLine().trim();
                    Status target = fs.equals("2") ? Status.IN_PROGRESS : fs.equals("3") ? Status.DONE : Status.TODO;
                    manager.printTaskList(manager.getAllTasks().stream().filter(t -> t.getStatus() == target).toList());
                    break;
                case "5":
                    System.out.print("Filter by (0=P0, 1=P1, 2=P2): ");
                    String fp = scanner.nextLine().trim();
                    Priority tp = fp.equals("0") ? Priority.P0 : fp.equals("2") ? Priority.P2 : Priority.P1;
                    manager.printTaskList(manager.getAllTasks().stream().filter(t -> t.getPriority() == tp).toList());
                    break;
                case "6":
                    System.out.print("Enter task ID to delete: ");
                    try {
                        int delId = Integer.parseInt(scanner.nextLine().trim());
                        if (manager.deleteTask(delId)) System.out.printf("[OK] Task #%d deleted.\n\n", delId);
                        else System.out.printf("[ERR] Task #%d not found.\n\n", delId);
                    } catch (Exception e) {
                        System.out.println("[ERR] Invalid task ID.\n");
                    }
                    break;
                case "7":
                    manager.printStats();
                    break;
                case "0":
                    running = false;
                    System.out.println("[SHUTDOWN] Exiting Task Manager. Goodbye!");
                    break;
                default:
                    System.out.println("[WARN] Unrecognized option. Enter 0-7.\n");
                    break;
            }
        }
        scanner.close();
    }
}
