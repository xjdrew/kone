const commands = {
  init: {
    usage: "just init",
    description: "Check local tools and prepare native Go and locked Web dependencies.",
    default: "Prepare dependencies only; do not build or start KONE.",
    values: [],
    examples: ["just init"],
  },
  dev: {
    usage: "just dev [mode]",
    description: "Start local desktop management or the Web development server.",
    default: "desktop (capture remains paused until explicitly enabled).",
    values: ["desktop", "web"],
    examples: ["just dev", "just dev web"],
  },
  quality: {
    usage: "just quality [mode]",
    description: "Run local checks; privileged network acceptance belongs to CI.",
    default: "quick (format check, vet, cached Go tests and Web unit tests).",
    values: ["quick", "full", "fmt", "vet", "benchmark"],
    examples: ["just quality", "just quality full", "just quality vet"],
  },
  build: {
    usage: "just build [stack]",
    description: "Build the current OS and architecture with embedded Web assets.",
    default: "system; desktop GUI and console CLI on Windows/macOS, CLI on Linux.",
    values: ["system", "mixed"],
    examples: ["just build", "just build mixed"],
  },
  "build-all": {
    usage: "just build-all",
    description: "Cross-build all seven supported OS/architecture targets.",
    default: "All targets; ARMv7 uses system, other targets include mixed support.",
    values: [],
    examples: ["just build-all"],
  },
  package: {
    usage: "just package [stack]",
    description: "Build and package the current OS and architecture without running or installing it.",
    default: "system; unsigned local artifacts in release-assets/.",
    values: ["system", "mixed"],
    examples: ["just package", "just package mixed"],
  },
  "package-all": {
    usage: "just package-all",
    description: "Build all seven portable packages plus the current host's native installer when available.",
    default: "All targets; create unsigned artifacts without running or installing them.",
    values: [],
    examples: ["just package-all"],
  },
};

export function taskHelp(command) {
  const definition = commands[command];
  if (!definition) throw new Error(`Unknown task: ${command}`);
  return [
    `Usage: ${definition.usage}`,
    definition.description,
    `Default: ${definition.default}`,
    `Options: ${definition.values.length ? definition.values.join(" | ") : "no positional arguments"}; -h, --help`,
    "Examples:",
    ...definition.examples.map(example => `  ${example}`),
    "Advanced tasks: just --list ci; inspect a task with just --show ci::<task>.",
  ].join("\n");
}

// Call before initialization/build/launch. Defaults stay in the task functions;
// this checks the complete CLI argv so surplus arguments are never discarded.
export function showHelp(command, args, write = console.log) {
  const definition = commands[command];
  if (!definition) throw new Error(`Unknown task: ${command}`);
  if (args.length === 1 && ["-h", "--help"].includes(args[0])) {
    write(taskHelp(command));
    return true;
  }
  if (args.length > (definition.values.length ? 1 : 0) || (args.length === 1 && !definition.values.includes(args[0])))
    throw new Error(`Invalid arguments for just ${command}.\nUsage: ${definition.usage}\nRun just ${command} --help for options and examples.`);
  return false;
}
