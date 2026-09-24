import {
  FileReport,
  GgufScanResult,
  PytorchScanResult,
  SafetensorsScanResult,
  ScanReport,
  Verdict,
} from "./types";

const TOOL_VERSION = "0.1.0";

export function buildScanReport(files: FileReport[]): ScanReport {
  const summary = {
    filesScanned: files.length,
    dangerous: 0,
    suspicious: 0,
    invalid: 0,
    clean: 0,
  };
  for (const f of files) {
    const v: Verdict = f.result.verdict;
    if (v === "DANGEROUS") summary.dangerous++;
    else if (v === "SUSPICIOUS") summary.suspicious++;
    else if (v === "INVALID") summary.invalid++;
    else if (v === "CLEAN" || v === "VALID") summary.clean++;
  }
  return {
    tool: "modelsbom",
    version: TOOL_VERSION,
    generatedAt: new Date().toISOString(),
    files,
    summary,
  };
}

function verdictBadge(v: Verdict): string {
  switch (v) {
    case "DANGEROUS":
      return "[DANGEROUS]";
    case "SUSPICIOUS":
      return "[SUSPICIOUS]";
    case "INVALID":
      return "[INVALID]";
    case "UNSUPPORTED":
      return "[SKIPPED]";
    case "VALID":
      return "[VALID]";
    case "CLEAN":
    default:
      return "[CLEAN]";
  }
}

function renderPytorchSection(r: PytorchScanResult, lines: string[]): void {
  lines.push(`  format: pytorch-pickle (${r.pickleEntryName})`);
  lines.push(`  opcodes scanned: ${r.opcodeCount}`);
  if (r.globalReferences.length > 0) {
    lines.push(`  global references (${r.globalReferences.length}):`);
    for (const g of r.globalReferences) {
      const tag = g.allowlisted ? "allowlisted" : "NOT ALLOWLISTED";
      lines.push(`    - ${g.module}.${g.name}  [offset ${g.offset}]  (${tag})`);
    }
  } else {
    lines.push("  global references: none");
  }
  renderFindings(r.findings, lines);
}

function renderSafetensorsSection(r: SafetensorsScanResult, lines: string[]): void {
  lines.push("  format: safetensors (structural/integrity check only - no code execution surface)");
  lines.push(`  header length: ${r.headerLength} bytes`);
  lines.push(`  tensors: ${r.tensorCount}`);
  for (const t of r.tensors) {
    lines.push(
      `    - ${t.name}: dtype=${t.dtype} shape=${JSON.stringify(t.shape)} offsets=[${t.dataOffsets[0]}, ${t.dataOffsets[1]})`
    );
  }
  if (r.metadata) {
    lines.push(`  metadata: ${JSON.stringify(r.metadata)}`);
  }
  renderFindings(r.findings, lines);
}

function renderGgufSection(r: GgufScanResult, lines: string[]): void {
  lines.push("  format: gguf (structural/metadata report only - no code execution surface)");
  lines.push(`  version: ${r.version}`);
  lines.push(`  tensor count: ${r.tensorCount}`);
  lines.push(`  metadata kv count: ${r.metadataCount}`);
  const interestingKeys = Object.keys(r.metadata).slice(0, 20);
  if (interestingKeys.length > 0) {
    lines.push("  metadata:");
    for (const k of interestingKeys) {
      const v = r.metadata[k];
      const rendered = Array.isArray(v) ? `[${v.length} item(s)]` : JSON.stringify(v);
      lines.push(`    - ${k} = ${rendered}`);
    }
  }
  renderFindings(r.findings, lines);
}

function renderFindings(findings: { severity: string; code: string; message: string }[], lines: string[]): void {
  const notable = findings.filter((f) => f.severity !== "info");
  if (notable.length === 0) {
    lines.push("  findings: none");
    return;
  }
  lines.push(`  findings (${notable.length}):`);
  for (const f of notable) {
    lines.push(`    [${f.severity.toUpperCase()}] ${f.code}: ${f.message}`);
  }
}

export function renderHumanReadable(report: ScanReport): string {
  const lines: string[] = [];
  lines.push(`ModelSBOM v${report.version} - scan report (${report.generatedAt})`);
  lines.push("=".repeat(72));

  for (const file of report.files) {
    lines.push("");
    lines.push(`${verdictBadge(file.result.verdict)} ${file.path} (${file.sizeBytes} bytes)`);
    switch (file.result.format) {
      case "pytorch-pickle":
        renderPytorchSection(file.result, lines);
        break;
      case "safetensors":
        renderSafetensorsSection(file.result, lines);
        break;
      case "gguf":
        renderGgufSection(file.result, lines);
        break;
      default:
        renderFindings(file.result.findings, lines);
        break;
    }
  }

  lines.push("");
  lines.push("-".repeat(72));
  lines.push(
    `Summary: ${report.summary.filesScanned} file(s) scanned - ` +
      `${report.summary.dangerous} dangerous, ${report.summary.suspicious} suspicious, ` +
      `${report.summary.invalid} invalid, ${report.summary.clean} clean.`
  );
  return lines.join("\n");
}
