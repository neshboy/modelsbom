/**
 * PyTorch model file handling.
 *
 * Modern `torch.save()` output (the default since PyTorch 1.6) is a ZIP
 * archive (see zip.ts) containing `<archive-name>/data.pkl` - the pickled
 * object graph - plus raw tensor storage blobs. Older files (and some
 * `.bin` files, e.g. from Hugging Face `transformers` before safetensors)
 * are a bare pickle stream with no ZIP wrapper ("legacy format").
 *
 * Either way, the actual code-execution risk lives entirely in the pickle
 * bytes, so both paths funnel into the same opcode scanner.
 */
import { isZip, listZipEntries, extractZipEntry } from "../zip";
import { scanPickleBytes } from "../pickle/scanner";
import { Finding, PytorchScanResult, Verdict } from "../types";

function verdictFromFindings(findings: Finding[]): Verdict {
  if (findings.some((f) => f.severity === "high")) return "DANGEROUS";
  if (findings.some((f) => f.severity === "medium")) return "SUSPICIOUS";
  return "CLEAN";
}

export function scanPytorchFile(buf: Buffer): PytorchScanResult {
  const findings: Finding[] = [];

  if (isZip(buf)) {
    let entries;
    try {
      entries = listZipEntries(buf);
    } catch (err) {
      return {
        format: "pytorch-pickle",
        verdict: "INVALID",
        pickleEntryName: "",
        globalReferences: [],
        findings: [
          {
            severity: "medium",
            code: "PYTORCH_ZIP_PARSE_ERROR",
            message: `Failed to parse ZIP structure: ${
              err instanceof Error ? err.message : String(err)
            }`,
          },
        ],
        opcodeCount: 0,
      };
    }
    const pklEntry = entries.find((e) => e.name.endsWith("data.pkl"));
    if (!pklEntry) {
      return {
        format: "pytorch-pickle",
        verdict: "INVALID",
        pickleEntryName: "",
        globalReferences: [],
        findings: [
          {
            severity: "medium",
            code: "PYTORCH_NO_DATA_PKL",
            message:
              "File is a ZIP archive but no data.pkl entry was found - this doesn't look like a torch.save() archive.",
          },
        ],
        opcodeCount: 0,
      };
    }
    let pickleBytes: Buffer;
    try {
      pickleBytes = extractZipEntry(buf, pklEntry);
    } catch (err) {
      return {
        format: "pytorch-pickle",
        verdict: "INVALID",
        pickleEntryName: pklEntry.name,
        globalReferences: [],
        findings: [
          {
            severity: "medium",
            code: "PYTORCH_ZIP_EXTRACT_ERROR",
            message: `Failed to extract ${pklEntry.name} from ZIP archive: ${
              err instanceof Error ? err.message : String(err)
            }`,
          },
        ],
        opcodeCount: 0,
      };
    }
    const outcome = scanPickleBytes(pickleBytes);
    findings.push(...outcome.findings);
    return {
      format: "pytorch-pickle",
      verdict: verdictFromFindings(findings),
      pickleEntryName: pklEntry.name,
      globalReferences: outcome.globalReferences,
      findings,
      opcodeCount: outcome.opcodeCount,
    };
  }

  // Legacy (pre-zip) format: the whole file (or close to it) is a raw
  // pickle stream. We scan it directly.
  const outcome = scanPickleBytes(buf);
  findings.push(...outcome.findings);
  return {
    format: "pytorch-pickle",
    verdict: verdictFromFindings(findings),
    pickleEntryName: "(legacy raw pickle, no ZIP container)",
    globalReferences: outcome.globalReferences,
    findings,
    opcodeCount: outcome.opcodeCount,
  };
}
