# Crux — Collaborative Code Editor with a Spatial Canvas

Crux is a collaborative IDE for exploring related files, editing code together, and keeping a terminal beside the work. Try the browser workspace now; desktop access is available through the waitlist.

[Website](https://codecrux.us/) · [Try the browser IDE](https://codecrux.us/ide) · [IDE guide](https://codecrux.us/docs) · [Join the desktop waitlist](https://codecrux.us/#waitlist)

## What Crux does

- **Spatial code canvas:** Open related files together to follow a change across the project.
- **Shared editing:** Work in the same files with teammate cursor presence. The Share dialog provides full-edit and view-only links.
- **Integrated terminal:** Run commands and inspect output alongside the editor.
- **Browser and desktop workflows:** The browser IDE is available to try; the desktop app is being offered through the waitlist.

Read the [collaborative code editor overview](https://codecrux.us/code-editor) or follow the [pair programming guide](https://codecrux.us/pair-programming) for a practical walkthrough.

## Compare code editors

If you are evaluating code editor competitors, compare the workflow you need rather than relying on a single speed claim. The [comparison guide](https://codecrux.us/compare) covers Crux, Cursor, VS Code Live Share, and Zed, with links to each product's documentation.

- [Crux vs Cursor](https://codecrux.us/vs-cursor)
- [Crux vs VS Code Live Share](https://codecrux.us/vs-vscode)
- [Crux vs Zed](https://codecrux.us/vs-zed)

## Run the web project locally

    git clone https://github.com/hrgang-hrushi/collab-editor.git
    cd collab-editor
    npm install
    npm run dev

Open http://localhost:3000 after the development server starts. The web app uses Next.js; the desktop source is under src-tauri and uses Tauri.

## Project status

Crux is under active development. The browser IDE can be tried today, and desktop access is being rolled out through the waitlist. No independently reproducible latency, memory, or competitor benchmark results are published here.

This repository does not currently include a license file. Contact the maintainers before reusing its code outside the repository.
