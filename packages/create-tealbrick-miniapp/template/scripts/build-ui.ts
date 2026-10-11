// UI build without a bundler. `tsc -p tsconfig.build.json` has emitted src/ui as ES modules to dist/ui; this script
// copies the browser dependencies next to it and writes dist/ui/index.html with an import map:
// - ES module packages (@opt2-tealbrick/ui, @opt2-tealbrick/miniapp-sdk/client, ...) are copied file by file, only
//   the files reachable from dist/ui/main.js;
// - React ships CommonJS only, so each React entry it needs is wrapped once into an ES module (production build).
import { copyFileSync, existsSync, mkdirSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { builtinModules, createRequire } from "node:module";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));
const out = join(root, "dist", "ui");
const VENDOR = "vendor";
const STYLES = ["@opt2-tealbrick/ui/tokens.css", "@opt2-tealbrick/ui/components.css"];

/** CommonJS entries (production builds), by bare specifier: package, file inside it, package to resolve it from. */
const CJS: Record<string, { pkg: string; file: string; from?: string }> = {
  react: { pkg: "react", file: "cjs/react.production.js" },
  "react/jsx-runtime": { pkg: "react", file: "cjs/react-jsx-runtime.production.js" },
  "react-dom": { pkg: "react-dom", file: "cjs/react-dom.production.js" },
  "react-dom/client": { pkg: "react-dom", file: "cjs/react-dom-client.production.js" },
  scheduler: { pkg: "scheduler", file: "cjs/scheduler.production.js", from: "react-dom" },
};

const fail = (msg: string): never => {
  throw new Error(`build-ui: ${msg}`);
};
const posix = (p: string) => p.split(sep).join("/");
const requireFrom = (file: string) => createRequire(file);
const pkgDir = (name: string, fromFile: string) => dirname(realpathSync(requireFrom(fromFile).resolve(`${name}/package.json`)));

/** Static and dynamic import specifiers of an emitted ES module. */
function specifiers(code: string): string[] {
  const found = new Set<string>();
  for (const m of code.matchAll(/\b(?:import|export)\s*(?:[^;"'`]*?\bfrom\s*)?["']([^"']+)["']/g)) found.add(m[1] as string);
  for (const m of code.matchAll(/\bimport\(\s*["']([^"']+)["']\s*\)/g)) found.add(m[1] as string);
  return [...found];
}

/** Nearest package.json above `file` that has a name. */
function owningPackage(file: string): { name: string; dir: string } {
  for (let dir = dirname(file); dir !== dirname(dir); dir = dirname(dir)) {
    const pj = join(dir, "package.json");
    if (!existsSync(pj)) continue;
    const name = (JSON.parse(readFileSync(pj, "utf8")) as { name?: string }).name;
    if (name) return { name, dir };
  }
  return fail(`no package.json above ${file}`);
}

const importMap: Record<string, string> = {};
const mapTo = (spec: string, url: string) => {
  if (importMap[spec] && importMap[spec] !== url) fail(`${spec} resolves to two files (${importMap[spec]}, ${url}); dedupe the dependency`);
  importMap[spec] = url;
};
/** Output path of a dependency file, keeping its layout inside its package (relative imports stay valid). */
function destOf(file: string): string {
  if (file.startsWith(out + sep)) return file;
  const pkg = owningPackage(file);
  return join(out, VENDOR, pkg.name, relative(pkg.dir, file));
}
function vendorPath(file: string): string {
  const dest = destOf(file);
  if (dest !== file) {
    mkdirSync(dirname(dest), { recursive: true });
    copyFileSync(file, dest);
  }
  return dest;
}
const urlOf = (dest: string) => `./${posix(relative(out, dest))}`;

// 1. ES modules reachable from the entry
const entry = join(out, "main.js");
if (!existsSync(entry)) fail("dist/ui/main.js is missing; run tsc -p tsconfig.build.json first");
const cjsNeeded = new Set<string>();
const seen = new Set<string>();
const queue = [entry];
while (queue.length > 0) {
  const file = queue.pop() as string;
  if (seen.has(file)) continue;
  seen.add(file);
  vendorPath(file);
  for (const spec of specifiers(readFileSync(file, "utf8"))) {
    if (spec.startsWith("./") || spec.startsWith("../")) {
      const target = resolve(dirname(file), spec);
      if (!existsSync(target)) fail(`${file} imports missing ${spec}`);
      queue.push(target);
    } else if (spec in CJS) cjsNeeded.add(spec);
    else if (spec.startsWith("node:") || builtinModules.includes(spec)) fail(`${file} imports the Node built-in ${spec}; it cannot run in a browser`);
    else {
      const target = realpathSync(requireFrom(file).resolve(spec));
      mapTo(spec, urlOf(destOf(target)));
      queue.push(target);
    }
  }
}

// 2. CommonJS entries wrapped into ES modules (their own requires become imports through the same map)
const pending = [...cjsNeeded];
const wrapped = new Set<string>();
while (pending.length > 0) {
  const spec = pending.pop() as string;
  if (wrapped.has(spec)) continue;
  wrapped.add(spec);
  const def = CJS[spec] ?? fail(`unknown CommonJS entry ${spec}`);
  const base = def.from ? pkgDir(def.from, join(root, "package.json")) : root;
  const file = join(pkgDir(def.pkg, join(base, "package.json")), def.file);
  const source = readFileSync(file, "utf8");
  const deps = [...new Set([...source.matchAll(/\brequire\("([^"]+)"\)/g)].map((m) => m[1] as string))];
  for (const d of deps) {
    if (!(d in CJS)) fail(`${spec} requires ${d}, which is not in the CommonJS table`);
    pending.push(d);
  }
  const names = Object.keys(requireFrom(file)(file) as object).filter((n) => n !== "default" && /^[A-Za-z_$][\w$]*$/.test(n));
  const dest = join(out, VENDOR, "cjs", `${spec}.js`);
  mkdirSync(dirname(dest), { recursive: true });
  writeFileSync(
    dest,
    [
      `// ${spec}: ${posix(relative(root, file))} wrapped as an ES module by scripts/build-ui.ts`,
      ...deps.map((d, i) => `import __dep${i} from ${JSON.stringify(d)};`),
      `const __deps = { ${deps.map((d, i) => `${JSON.stringify(d)}: __dep${i}`).join(", ")} };`,
      "const module = { exports: {} };",
      "(function (module, exports, require, process) {",
      source,
      '})(module, module.exports, (id) => __deps[id], { env: { NODE_ENV: "production" } });',
      "export default module.exports;",
      names.length ? `export const { ${names.join(", ")} } = module.exports;` : "",
      "",
    ].join("\n"),
  );
  mapTo(spec, urlOf(dest));
}

// 3. stylesheets + index.html
const links = STYLES.map((s) => {
  const file = realpathSync(requireFrom(join(root, "package.json")).resolve(s));
  return `<link rel="stylesheet" href="${urlOf(vendorPath(file))}" />`;
});
const html = readFileSync(join(root, "src", "ui", "index.html"), "utf8");
const marker = /<!-- tb:head[^>]*-->/;
if (!marker.test(html)) fail("src/ui/index.html has no <!-- tb:head --> marker");
const sorted = Object.fromEntries(Object.entries(importMap).sort(([a], [b]) => a.localeCompare(b)));
const head = [...links, `<script type="importmap">${JSON.stringify({ imports: sorted })}</script>`].join("\n    ");
writeFileSync(join(out, "index.html"), html.replace(marker, head));
console.log(`build-ui: ${seen.size} modules, ${wrapped.size} CommonJS wrappers, ${links.length} stylesheets -> dist/ui`);
