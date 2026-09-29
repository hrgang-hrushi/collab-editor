import { build } from "esbuild";
import { readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const result = await build({
  entryPoints: [path.join(root, "scripts/orb-gallery.tsx")],
  bundle: true,
  minify: true,
  format: "iife",
  platform: "browser",
  write: false,
});
const template = await readFile(path.join(root, "scripts/orb-gallery.template.html"), "utf8");
const bundle = result.outputFiles[0].text.replaceAll("</script", "<\\/script");
const marker = "/* ORB_GALLERY_BUNDLE */";
if (!template.includes(marker)) throw new Error("Orb gallery script marker missing");
await writeFile(path.join(root, "public/orb-comparison.html"), template.replace(marker, bundle));
console.log("Wrote public/orb-comparison.html");
