import { defineConfig } from "vite";

export default defineConfig({
  build: {
    // All UI code is one offline module; native module support is sufficient.
    modulePreload: false,
    target: ["chrome110", "safari16.4", "firefox115"],
  },
});
