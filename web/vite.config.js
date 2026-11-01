import { defineConfig } from "vite";
import { readFile, readdir } from "node:fs/promises";
import { join } from "node:path";

function lineEndings() {
  let publicDirectory = "";
  return {
    name: "kone-text-line-endings",
    configResolved(config) {
      publicDirectory = config.build.copyPublicDir ? config.publicDir : "";
    },
    transformIndexHtml: {
      order: "pre",
      // Existing Windows checkouts may still contain CRLF after pulling the
      // LF attributes. Normalize before Vite injects its LF asset tags.
      handler: (html) => html.replace(/\r\n?/g, "\n"),
    },
    async generateBundle() {
      // Vite copies public assets verbatim. Emit canonical SVG text over those
      // copies; leave source files and binary icons untouched.
      if (!publicDirectory) return;
      const visit = async (directory, prefix = "") => {
        for (const entry of await readdir(directory, { withFileTypes: true })) {
          const path = join(directory, entry.name), name = prefix + entry.name;
          if (entry.isDirectory()) await visit(path, `${name}/`);
          else if (entry.isFile() && entry.name.endsWith(".svg")) this.emitFile({
            type: "asset", fileName: name,
            source: (await readFile(path, "utf8")).replace(/\r\n?/g, "\n"),
          });
        }
      };
      await visit(publicDirectory);
    },
  };
}

export default defineConfig({
  plugins: [lineEndings()],
  build: {
    // All UI code is one offline module; native module support is sufficient.
    modulePreload: false,
    target: ["chrome110", "safari16.4", "firefox115"],
  },
});
