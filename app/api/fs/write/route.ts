import { NextRequest } from "next/server";
import fs from "fs";
import path from "path";

export async function POST(req: NextRequest) {
  try {
    const { fileName, filePath, content = "" } = await req.json();
    const targetPath = filePath || fileName;

    if (!targetPath) {
      return new Response(JSON.stringify({ error: "fileName or filePath is required" }), {
        status: 400,
        headers: { "Content-Type": "application/json" },
      });
    }

    const cwd = process.cwd();

    // 1. Resolve relative to cwd
    const fullPath = path.isAbsolute(targetPath)
      ? targetPath
      : path.join(cwd, targetPath);

    const dir = path.dirname(fullPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    fs.writeFileSync(fullPath, content, "utf-8");

    // 2. Also write to root directory if targetPath was inside a subdirectory (e.g. src/Practice.java -> ./Practice.java)
    const baseName = fileName || path.basename(fullPath);
    const rootFilePath = path.join(cwd, baseName);
    if (rootFilePath !== fullPath) {
      try {
        fs.writeFileSync(rootFilePath, content, "utf-8");
      } catch {}
    }

    // 3. Java multi-compatibility support
    // In Java, if a file contains `public class Foo`, javac insists the file MUST be named `Foo.java`.
    // If the file is named `Practice.java` but contains `public class TrainingArena`:
    // a) Save `TrainingArena.java` in both dir and root
    // b) Save `Practice.java` with `class TrainingArena` (non-public) so `javac Practice.java` also compiles without error!
    if (baseName.endsWith(".java") || content.includes("class ")) {
      const clsMatch = content.match(/(?:public\s+)?class\s+([A-Za-z0-9_]+)/);
      if (clsMatch) {
        const clsName = clsMatch[1];
        const classFileName = `${clsName}.java`;

        // Save classFileName in dir and root
        const classInDir = path.join(dir, classFileName);
        const classInRoot = path.join(cwd, classFileName);

        // Ensure class file has public class
        const publicClassContent = content.replace(
          new RegExp(`(?:public\\s+)?class\\s+${clsName}\\b`),
          `public class ${clsName}`
        );
        try {
          fs.writeFileSync(classInDir, publicClassContent, "utf-8");
          fs.writeFileSync(classInRoot, publicClassContent, "utf-8");
        } catch {}

        // If the original file was named differently (e.g. Practice.java), make its class non-public so javac Practice.java succeeds
        if (baseName !== classFileName) {
          const nonPublicContent = content.replace(
            new RegExp(`\\bpublic\\s+class\\s+${clsName}\\b`),
            `class ${clsName}`
          );
          try {
            fs.writeFileSync(fullPath, nonPublicContent, "utf-8");
            fs.writeFileSync(rootFilePath, nonPublicContent, "utf-8");
          } catch {}
        }
      }
    }

    return new Response(JSON.stringify({ success: true, path: fullPath }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  } catch (err: any) {
    return new Response(JSON.stringify({ error: err.message }), {
      status: 500,
      headers: { "Content-Type": "application/json" },
    });
  }
}
