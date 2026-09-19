import { NextRequest, NextResponse } from "next/server";
import fs from "fs";
import path from "path";
import os from "os";
import { execSync } from "child_process";
import vm from "vm";
import ts from "typescript";

export async function POST(req: NextRequest) {
  const startTime = Date.now();
  const stdout: string[] = [];
  const stderr: string[] = [];
  let exitCode = 0;

  try {
    const body = await req.json();
    const { code, language = "typescript", files = [] } = body;

    if (typeof code !== "string") {
      return NextResponse.json(
        { error: "Missing or invalid code property" },
        { status: 400 }
      );
    }

    const lang = (language || "typescript").toLowerCase();

    // Multi-Language Host Execution Daemon
    if (lang === "python" || lang === "py") {
      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "crux-py-"));
      const scriptPath = path.join(tmpDir, "temp.py");
      try {
        fs.writeFileSync(scriptPath, code);
        const output = execSync("python3 temp.py", {
          cwd: tmpDir,
          timeout: 10000,
          encoding: "utf-8",
        });
        stdout.push(output);
      } catch (err: any) {
        if (err.stdout) stdout.push(err.stdout.toString());
        if (err.stderr) stderr.push(err.stderr.toString());
        exitCode = err.status || 1;
      } finally {
        fs.rmSync(tmpDir, { recursive: true, force: true });
      }
    } else if (lang === "c") {
      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "crux-c-"));
      const srcPath = path.join(tmpDir, "temp.c");
      const binPath = path.join(tmpDir, "temp");
      try {
        fs.writeFileSync(srcPath, code);
        execSync(`gcc temp.c -o temp`, { cwd: tmpDir, timeout: 10000 });
        const output = execSync(`./temp`, { cwd: tmpDir, timeout: 10000, encoding: "utf-8" });
        stdout.push(output);
      } catch (err: any) {
        if (err.stdout) stdout.push(err.stdout.toString());
        if (err.stderr) stderr.push(err.stderr.toString());
        exitCode = err.status || 1;
      } finally {
        fs.rmSync(tmpDir, { recursive: true, force: true });
      }
    } else if (lang === "rust" || lang === "rs") {
      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "crux-rs-"));
      const srcPath = path.join(tmpDir, "temp.rs");
      const binPath = path.join(tmpDir, "temp");
      try {
        fs.writeFileSync(srcPath, code);
        execSync(`rustc temp.rs -o temp`, { cwd: tmpDir, timeout: 10000 });
        const output = execSync(`./temp`, { cwd: tmpDir, timeout: 10000, encoding: "utf-8" });
        stdout.push(output);
      } catch (err: any) {
        if (err.stdout) stdout.push(err.stdout.toString());
        if (err.stderr) stderr.push(err.stderr.toString());
        exitCode = err.status || 1;
      } finally {
        fs.rmSync(tmpDir, { recursive: true, force: true });
      }
    } else if (lang === "swift") {
      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "crux-swift-"));
      const srcPath = path.join(tmpDir, "temp.swift");
      const binPath = path.join(tmpDir, "temp");
      try {
        fs.writeFileSync(srcPath, code);
        execSync(`swiftc temp.swift -o temp`, { cwd: tmpDir, timeout: 10000 });
        const output = execSync(`./temp`, { cwd: tmpDir, timeout: 10000, encoding: "utf-8" });
        stdout.push(output);
      } catch (err: any) {
        if (err.stdout) stdout.push(err.stdout.toString());
        if (err.stderr) stderr.push(err.stderr.toString());
        exitCode = err.status || 1;
      } finally {
        fs.rmSync(tmpDir, { recursive: true, force: true });
      }
    } else if (lang === "java") {
      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "crux-java-"));
      const srcPath = path.join(tmpDir, "Temp.java");
      try {
        fs.writeFileSync(srcPath, code);
        execSync(`javac Temp.java`, { cwd: tmpDir, timeout: 10000 });
        const output = execSync(`java Temp`, { cwd: tmpDir, timeout: 10000, encoding: "utf-8" });
        stdout.push(output);
      } catch (err: any) {
        if (err.stdout) stdout.push(err.stdout.toString());
        if (err.stderr) stderr.push(err.stderr.toString());
        exitCode = err.status || 1;
      } finally {
        fs.rmSync(tmpDir, { recursive: true, force: true });
      }
    } else {
      // TypeScript / JavaScript VM execution
      const transpileResult = ts.transpileModule(code, {
        compilerOptions: {
          module: ts.ModuleKind.CommonJS,
          target: ts.ScriptTarget.ES2022,
          jsx: ts.JsxEmit.React,
          allowJs: true,
          removeComments: false,
        },
      });

      const rootMod = { exports: {} };
      const sandbox: Record<string, any> = {
        module: rootMod,
        exports: rootMod.exports,
        console: {
          log: (...args: any[]) => stdout.push(args.map(String).join(" ")),
          info: (...args: any[]) => stdout.push("[INFO] " + args.map(String).join(" ")),
          warn: (...args: any[]) => stdout.push("[WARN] " + args.map(String).join(" ")),
          error: (...args: any[]) => stderr.push("[ERR] " + args.map(String).join(" ")),
        },
      };

      const ctx = vm.createContext(sandbox);
      const script = new vm.Script(transpileResult.outputText, { filename: "main.ts" });
      script.runInContext(ctx, { timeout: 5000 });
    }

    return NextResponse.json({
      stdout,
      stderr,
      exitCode,
      executionTimeMs: Date.now() - startTime,
    });
  } catch (err: any) {
    return NextResponse.json({
      stdout,
      stderr: [err.message || String(err)],
      exitCode: 1,
      executionTimeMs: Date.now() - startTime,
    });
  }
}
