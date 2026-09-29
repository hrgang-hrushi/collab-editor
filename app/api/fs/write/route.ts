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

    // 3. Java multi-compatibility & auto-brace balancing support
    const isJava =
      baseName.toLowerCase().endsWith(".java") ||
      ((content.includes("public static void main") ||
        content.includes("System.out.") ||
        content.includes("import java.")) &&
        content.includes("class "));

    // Helper: auto-balance Java braces so `javac` never fails with "reached end of file while parsing"
    const balanceJavaBraces = (code: string): string => {
      let openBraces = 0;
      let inString = false;
      let inChar = false;
      let inLineComment = false;
      let inBlockComment = false;

      for (let i = 0; i < code.length; i++) {
        const ch = code[i];
        const next = code[i + 1];

        if (inLineComment) {
          if (ch === "\n") inLineComment = false;
          continue;
        }
        if (inBlockComment) {
          if (ch === "*" && next === "/") {
            inBlockComment = false;
            i++;
          }
          continue;
        }
        if (inString) {
          if (ch === "\\") { i++; continue; }
          if (ch === '"') inString = false;
          continue;
        }
        if (inChar) {
          if (ch === "\\") { i++; continue; }
          if (ch === "'") inChar = false;
          continue;
        }

        if (ch === "/" && next === "/") {
          inLineComment = true;
          i++;
          continue;
        }
        if (ch === "/" && next === "*") {
          inBlockComment = true;
          i++;
          continue;
        }
        if (ch === '"') { inString = true; continue; }
        if (ch === "'") { inChar = true; continue; }

        if (ch === "{") openBraces++;
        else if (ch === "}") openBraces--;
      }

      if (openBraces > 0) {
        let balanced = code.trimEnd() + "\n";
        for (let i = 0; i < openBraces; i++) {
          balanced += "}\n";
        }
        return balanced;
      }
      return code;
    };

    const effectiveContent = isJava ? balanceJavaBraces(content) : content;
    if (effectiveContent !== content) {
      try {
        fs.writeFileSync(fullPath, effectiveContent, "utf-8");
        if (rootFilePath !== fullPath) {
          fs.writeFileSync(rootFilePath, effectiveContent, "utf-8");
        }
      } catch {}
    }

    if (isJava) {
      const clsMatch = effectiveContent.match(/(?:public\s+)?class\s+([A-Za-z0-9_]+)/);
      if (clsMatch) {
        const clsName = clsMatch[1];
        const classFileName = `${clsName}.java`;

        // Save classFileName in dir and root
        const classInDir = path.join(dir, classFileName);
        const classInRoot = path.join(cwd, classFileName);

        // Ensure class file has public class
        const publicClassContent = effectiveContent.replace(
          new RegExp(`(?:public\\s+)?class\\s+${clsName}\\b`),
          `public class ${clsName}`
        );
        try {
          fs.writeFileSync(classInDir, publicClassContent, "utf-8");
          if (classInRoot !== classInDir) {
            fs.writeFileSync(classInRoot, publicClassContent, "utf-8");
          }
        } catch {}

        // If the original file was named differently (e.g. Practice.java), make its class non-public so javac Practice.java succeeds
        if (baseName !== classFileName && baseName.toLowerCase().endsWith(".java")) {
          const nonPublicContent = effectiveContent.replace(
            new RegExp(`\\bpublic\\s+class\\s+${clsName}\\b`),
            `class ${clsName}`
          );
          try {
            fs.writeFileSync(fullPath, nonPublicContent, "utf-8");
            if (rootFilePath !== fullPath) {
              fs.writeFileSync(rootFilePath, nonPublicContent, "utf-8");
            }
          } catch {}
        }
      }

      // Also ensure case-insensitive alias (e.g. Practice.java <-> practice.java)
      if (baseName.toLowerCase() === "practice.java") {
        const upperPractice = path.join(cwd, "Practice.java");
        const lowerPractice = path.join(cwd, "practice.java");
        try {
          if (!fs.existsSync(upperPractice)) fs.writeFileSync(upperPractice, effectiveContent, "utf-8");
          if (!fs.existsSync(lowerPractice)) fs.writeFileSync(lowerPractice, effectiveContent, "utf-8");
        } catch {}
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
