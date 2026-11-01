import { execFileSync } from "node:child_process";
import { join } from "node:path";

// Use Windows PowerShell 5.1 shipped with Windows, independent of shell PATH.
export function runWindowsScript(script, args, options = {}) {
  const executable = join(
    process.env.SystemRoot || "C:\\Windows",
    "System32",
    "WindowsPowerShell",
    "v1.0",
    "powershell.exe",
  );
  return execFileSync(
    executable,
    [
      "-NoLogo",
      "-NoProfile",
      "-NonInteractive",
      // Applies to this child session only; does not change machine policy.
      "-ExecutionPolicy",
      "Bypass",
      "-File",
      script,
      ...args,
    ],
    { stdio: "inherit", ...options },
  );
}
