export type Severity = "high" | "medium" | "low" | "info";

export interface Finding {
  severity: Severity;
  code: string; // machine-readable finding id, e.g. "PICKLE_UNSAFE_REDUCE"
  message: string; // human readable summary
  detail?: string; // extra detail (e.g. exact opcode sequence)
  offset?: number; // byte offset in the relevant stream, if applicable
}

export type FileFormat = "pytorch-pickle" | "safetensors" | "gguf" | "unknown";

export type Verdict =
  | "CLEAN"
  | "SUSPICIOUS"
  | "DANGEROUS"
  | "VALID"
  | "INVALID"
  | "UNSUPPORTED";

export interface PickleGlobalRef {
  module: string;
  name: string;
  offset: number;
  allowlisted: boolean;
}

export interface PytorchScanResult {
  format: "pytorch-pickle";
  verdict: Verdict;
  pickleEntryName: string;
  globalReferences: PickleGlobalRef[];
  findings: Finding[];
  opcodeCount: number;
}

export interface SafetensorsScanResult {
  format: "safetensors";
  verdict: Verdict;
  headerLength: number;
  tensorCount: number;
  tensors: Array<{
    name: string;
    dtype: string;
    shape: number[];
    dataOffsets: [number, number];
  }>;
  metadata?: Record<string, string>;
  findings: Finding[];
}

export interface GgufScanResult {
  format: "gguf";
  verdict: Verdict;
  version: number;
  tensorCount: number | string;
  metadataCount: number | string;
  metadata: Record<string, unknown>;
  findings: Finding[];
}

export interface UnsupportedScanResult {
  format: "unknown";
  verdict: "UNSUPPORTED";
  findings: Finding[];
}

export type ScanResult =
  | PytorchScanResult
  | SafetensorsScanResult
  | GgufScanResult
  | UnsupportedScanResult;

export interface FileReport {
  path: string;
  sizeBytes: number;
  result: ScanResult;
}

export interface ScanReport {
  tool: "modelsbom";
  version: string;
  generatedAt: string;
  files: FileReport[];
  summary: {
    filesScanned: number;
    dangerous: number;
    suspicious: number;
    invalid: number;
    clean: number;
  };
}
