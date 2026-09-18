import { NextRequest, NextResponse } from "next/server";
import vm from "vm";
import ts from "typescript";

export async function POST(req: NextRequest) {
  const startTime = Date.now();
  const stdout: string[] = [];
  const stderr: string[] = [];
  let executionFileName = "main.ts";

  try {
    const body = await req.json();
    const { code, files = [], filename = "main.ts" } = body;
    executionFileName = filename;

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
      crypto: {
        subtle: {
          verify: async () => true,
          sign: async () => new Uint8Array([1, 2, 3, 4]).buffer,
          digest: async () => new Uint8Array([5, 6, 7, 8]).buffer,
        },
        randomUUID: () => "crx-uuid-" + Math.random().toString(36).slice(2, 9),
      },
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
          // If not in workspace, return an informative constructable mock proxy
          const createMockConstructor = (name: string) => {
            function MockClass(this: any, ...args: any[]) {
              this._name = name;
              this._args = args;
              return new Proxy(this, {
                get: (target, prop) => {
                  if (prop in target) return target[prop];
                  if (prop === "then") return undefined;
                  return async (...callArgs: any[]) => {
                    if (prop === "acquireLock") {
                      return {
                        ticketId: `CRX-TK-${Math.floor(1000 + Math.random() * 9000)}`,
                        acquiredAt: Date.now(),
                        resource: callArgs[0] || "stream-mesh-primary",
                        origin: "localhost:7447",
                      };
                    }
                    if (prop === "append") {
                      return Math.floor(100 + Math.random() * 900);
                    }
                    if (prop === "verify" || prop === "flushSync" || prop === "broadcast" || prop === "sync" || prop === "connect" || prop === "disconnect") {
                      return true;
                    }
                    return {
                      success: true,
                      method: String(prop),
                      timestamp: Date.now(),
                    };
                  };
                },
              });
            }
            return MockClass;
          };

          return new Proxy(
            {},
            {
              get: (_, prop) => {
                if (prop === "__esModule") return true;
                return createMockConstructor(`${modId}.${String(prop)}`);
              },
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
    let rawResult = vm.runInContext(transpiledCode, sandbox, {
      timeout: 4000,
    });

    // If the executed code returned a promise, await it
    if (rawResult && typeof (rawResult as any).then === "function") {
      try {
        rawResult = await Promise.race([
          rawResult,
          new Promise((_, reject) =>
            setTimeout(() => reject(new Error("Async execution timed out (3000ms)")), 3000)
          ),
        ]);
      } catch (pErr: any) {
        stderr.push(`[Async Error] ${pErr?.message || String(pErr)}`);
      }
    }

    // Give microtasks and resolved promises 60ms to flush their console logs
    await new Promise((resolve) => setTimeout(resolve, 60));

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
    let cleanError = err?.message || String(err);

    if (err?.stack) {
      const lines = (err.stack as string)
        .split("\n")
        .filter(
          (line) =>
            !line.includes("node_modules") &&
            !line.includes("webpack-internal") &&
            !line.includes("node:vm") &&
            !line.includes("next/dist") &&
            !line.includes("node:internal")
        );
      if (lines.length > 0) {
        cleanError = lines.join("\n").trim();
      }
    }

    // Replace evalmachine reference with the user's actual filename
    const targetFileName = executionFileName;
    cleanError = cleanError.replace(/evalmachine\.<anonymous>/g, targetFileName);
    stderr.push(cleanError);

    return NextResponse.json({
      stdout,
      stderr,
      returnValue: undefined,
      durationMs,
      success: false,
      timestamp: Date.now(),
      fileName: targetFileName,
    });
  }
}
