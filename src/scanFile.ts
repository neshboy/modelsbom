import * as path from "node:path";
import { isZip } from "./zip";
import { scanPytorchFile } from "./formats/pytorch";
import { scanSafetensorsFile } from "./formats/safetensors";
import { scanGgufFile } from "./formats/gguf";
import { FileFormat, FileReport, ScanResult } from "./types";

const PICKLE_EXTENSIONS = new Set([".pt", ".pth", ".ckpt", ".bin"]);

function detectFormat(filePath: string, buf: Buffer): FileFormat {
  const ext = path.extname(filePath).toLowerCase();
  if (ext === ".safetensors") return "safetensors";
  if (ext === ".gguf") return "gguf";
  if (PICKLE_EXTENSIONS.has(ext)) return "pytorch-pickle";

  // Fall back to magic-byte sniffing for extensionless / unusual files.
  if (buf.length >= 4 && buf.toString("ascii", 0, 4) === "GGUF") return "gguf";
  if (isZip(buf)) return "pytorch-pickle"; // torch.save() ZIP container
  if (buf.length >= 1 && buf[0] === 0x80) return "pytorch-pickle"; // PROTO opcode: raw pickle
  return "unknown";
}

export function scanBuffer(filePath: string, buf: Buffer): ScanResult {
  const format = detectFormat(filePath, buf);
  switch (format) {
    case "pytorch-pickle":
      return scanPytorchFile(buf);
    case "safetensors":
      return scanSafetensorsFile(buf);
    case "gguf":
      return scanGgufFile(buf);
    default:
      return {
        format: "unknown",
        verdict: "UNSUPPORTED",
        findings: [
          {
            severity: "info",
            code: "UNSUPPORTED_FORMAT",
            message: `Could not identify "${filePath}" as a PyTorch pickle, safetensors, or GGUF file - skipped.`,
          },
        ],
      };
  }
}

export function buildFileReport(filePath: string, buf: Buffer): FileReport {
  return {
    path: filePath,
    sizeBytes: buf.length,
    result: scanBuffer(filePath, buf),
  };
}
