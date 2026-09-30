#!/usr/bin/env node
import * as fs from "node:fs";
import * as path from "node:path";
import { buildFileReport } from "./scanFile";
import { buildScanReport, renderHumanReadable } from "./report";
import { FileReport } from "./types";

const KNOWN_EXTENSIONS = new Set([".pt", ".pth", ".ckpt", ".bin", ".safetensors", ".gguf"]);

function printUsage(): void {
  console.log(`ModelSBOM - supply-chain security scanner for AI model files

Usage:
  modelsbom scan <path-to-model-file-or-directory> [--json]

Supported formats:
  .pt .pth .ckpt .bin   PyTorch pickle (scanned for dangerous opcodes)
  .safetensors          safetensors (structural/integrity check)
  .gguf                 GGUF (structural/metadata report)

Exit codes:
  0  no high-severity findings
  1  at least one high-severity pickle finding (likely arbitrary code execution)
  2  at least one structurally invalid/corrupted file (no high-severity pickle finding)
`);
}

function collectFiles(targetPath: string): string[] {
  const stat = fs.statSync(targetPath);
  if (stat.isFile()) return [targetPath];

  const results: string[] = [];
  const stack = [targetPath];
  while (stack.length > 0) {
    const dir = stack.pop()!;
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        stack.push(full);
      } else if (entry.isFile() && KNOWN_EXTENSIONS.has(path.extname(entry.name).toLowerCase())) {
        results.push(full);
      }
    }
  }
  return results.sort();
}

function main(): number {
  const argv = process.argv.slice(2);
  if (argv.length === 0 || argv[0] === "--help" || argv[0] === "-h") {
    printUsage();
    return argv.length === 0 ? 1 : 0;
  }

  const command = argv[0];
  if (command !== "scan") {
    console.error(`Unknown command "${command}".\n`);
    printUsage();
    return 1;
  }

  const rest = argv.slice(1);
  const jsonOutput = rest.includes("--json");
  const positional = rest.filter((a) => !a.startsWith("--"));
  const targetPath = positional[0];

  if (!targetPath) {
    console.error("Error: missing <path-to-model-file-or-directory> argument.\n");
    printUsage();
    return 1;
  }

  const resolvedPath = path.resolve(targetPath);
  if (!fs.existsSync(resolvedPath)) {
    console.error(`Error: path does not exist: ${resolvedPath}`);
    return 1;
  }

  const files = collectFiles(resolvedPath);
  if (files.length === 0) {
    console.error(
      `No supported model files found under ${resolvedPath} (looked for ${[...KNOWN_EXTENSIONS].join(", ")}).`
    );
    return 1;
  }

  const fileReports: FileReport[] = files.map((f) => {
    try {
      const buf = fs.readFileSync(f);
      return buildFileReport(f, buf);
    } catch (err) {
      return {
        path: f,
        sizeBytes: 0,
        result: {
          format: "unknown",
          verdict: "UNSUPPORTED",
          findings: [
            {
              severity: "medium",
              code: "FILE_READ_OR_SCAN_ERROR",
              message: `Failed to read or scan "${f}": ${
                err instanceof Error ? err.message : String(err)
              }`,
            },
          ],
        },
      };
    }
  });

  const report = buildScanReport(fileReports);

  if (jsonOutput) {
    console.log(JSON.stringify(report, null, 2));
  } else {
    console.log(renderHumanReadable(report));
  }

  const hasHighSeverityPickleFinding = fileReports.some(
    (f) => f.result.format === "pytorch-pickle" && f.result.findings.some((finding) => finding.severity === "high")
  );
  if (hasHighSeverityPickleFinding) return 1;

  const hasInvalid = fileReports.some((f) => f.result.verdict === "INVALID");
  if (hasInvalid) return 2;

  return 0;
}

process.exit(main());
