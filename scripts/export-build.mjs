import fs from "fs";
import path from "path";
import { execSync } from "child_process";

const apiDir = path.resolve("app/api");
const backupDir = path.resolve(".api_export_tmp");

let moved = false;
try {
  if (fs.existsSync(apiDir)) {
    fs.renameSync(apiDir, backupDir);
    moved = true;
  }
  console.log("Running next build for static export...");
  execSync("npx next build", {
    stdio: "inherit",
    env: { ...process.env, NEXT_DIST_DIR: ".next-prod" },
  });
} finally {
  if (moved && fs.existsSync(backupDir)) {
    fs.renameSync(backupDir, apiDir);
    console.log("Restored app/api route handlers.");
  }
}
