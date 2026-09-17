import { NextRequest, NextResponse } from "next/server";
import vm from "vm";
import ts from "typescript";

export async function POST(req: NextRequest) {
  const startTime = Date.now();
  const stdout: string[] = [];
  const stderr: string[] = [];

  try {
    const body = await req.json();
    const { code, files = [], filename = "main.ts" } = body;

    if (typeof code !== "string") {
      return NextResponse.json(
        { error: "Missing or invalid code property" },
        { status: 400 }
      );
    }

    // Build a map of workspace files for multi-file imports
    const fileMap = new Map<string, string>();
    for (const f of files) {
      if (f.path && typeof f.content === "string") {
        fileMap.set(f.path, f.content);
        // Also index by filename without directories for convenient relative imports
        if (f.name) fileMap.set(f.name, f.content);
      }
    }

    // Transpile the entry code from TypeScript/JavaScript to CommonJS
    const transpileResult = ts.transpileModule(code, {
      compilerOptions: {
        module: ts.ModuleKind.CommonJS,
        target: ts.ScriptTarget.ES2022,
        jsx: ts.JsxEmit.React,
        allowJs: true,
        removeComments: false,
      },
    });

    const transpiledCode = transpileResult.outputText;

    // Cache of loaded module exports
    const moduleCache = new Map<string, any>();

    // Root module context
    const rootMod = { exports: {} };

    // Format any object / value into string output
    const formatArg = (val: any): string => {
      if (val === undefined) return "undefined";
      if (val === null) return "null";
      if (typeof val === "object") {
        try {
          return JSON.stringify(val, null, 2);
        } catch {
          return String(val);
        }
      }
      return String(val);
    };

    const sandbox: Record<string, any> = {
      module: rootMod,
      exports: rootMod.exports,
      console: {
        log: (...args: any[]) => stdout.push(args.map(formatArg).join(" ")),
        info: (...args: any[]) => stdout.push("[INFO] " + args.map(formatArg).join(" ")),
        warn: (...args: any[]) => stdout.push("[WARN] " + args.map(formatArg).join(" ")),
        error: (...args: any[]) => stderr.push("[ERR] " + args.map(formatArg).join(" ")),
      },
      setTimeout: (fn: Function, delay: number) => {
        // Limited setTimeout inside sandbox
        if (delay <= 1000) return setTimeout(fn, delay);
        return 0;
      },
      clearTimeout: (id: any) => clearTimeout(id),
      Date,
      Math,
      JSON,
      Array,
      Object,
      String,
      Number,
      Boolean,
      RegExp,
      Map,
      Set,
      Promise,
      Buffer: Buffer,
      require: (modId: string) => {
        // Built-in safe modules or mock
        if (modId === "assert") return require("assert");
        if (modId === "path") return require("path");

        // Normalize relative path
        const cleanId = modId.replace(/^\.\//, "");
        const candidatePaths = [
          cleanId,
          `${cleanId}.ts`,
          `${cleanId}.tsx`,
          `${cleanId}.js`,
          `${cleanId}.jsx`,
          `${cleanId}.json`,
          `src/${cleanId}`,
          `src/${cleanId}.ts`,
          `src/${cleanId}.js`,
        ];

        let matchedPath = candidatePaths.find((p) => fileMap.has(p));

        if (!matchedPath) {
          // If not in workspace, return an informative mock proxy rather than throwing fatal error
          return new Proxy(
            {},
            {
              get: (_, prop) => () =>
                `[Mocked module: ${modId}.${String(prop)}]`,
            }
          );
        }

        if (moduleCache.has(matchedPath)) {
          return moduleCache.get(matchedPath).exports;
        }

        const fileContent = fileMap.get(matchedPath)!;

        // If JSON file
        if (matchedPath.endsWith(".json")) {
          try {
            const parsed = JSON.parse(fileContent);
            moduleCache.set(matchedPath, { exports: parsed });
            return parsed;
          } catch {
            return {};
          }
        }

        // Transpile sub-module
        const subTranspiled = ts.transpileModule(fileContent, {
          compilerOptions: {
            module: ts.ModuleKind.CommonJS,
            target: ts.ScriptTarget.ES2022,
            allowJs: true,
          },
        }).outputText;

        const subMod = { exports: {} };
        moduleCache.set(matchedPath, subMod);

        const subSandbox = {
          ...sandbox,
          module: subMod,
          exports: subMod.exports,
        };

        vm.createContext(subSandbox);
        vm.runInContext(subTranspiled, subSandbox, { timeout: 3000 });
        return subMod.exports;
      },
    };

    vm.createContext(sandbox);

    // Execute with a 4 second strict timeout to prevent infinite while loops
    const rawResult = vm.runInContext(transpiledCode, sandbox, {
      timeout: 4000,
    });

    const durationMs = Date.now() - startTime;
    let returnValue: string | undefined = undefined;

    if (rawResult !== undefined && rawResult !== rootMod.exports) {
      returnValue = formatArg(rawResult);
    }

    return NextResponse.json({
      stdout,
      stderr,
      returnValue,
      durationMs,
      success: stderr.length === 0,
      timestamp: Date.now(),
      fileName: filename,
    });
  } catch (err: any) {
    const durationMs = Date.now() - startTime;
    const errorMsg = err?.stack || err?.message || String(err);
    stderr.push(errorMsg);

    return NextResponse.json({
      stdout,
      stderr,
      returnValue: undefined,
      durationMs,
      success: false,
      timestamp: Date.now(),
      fileName: "execution-error",
    });
  }
}
