/**
 * safetensors structural validation.
 *
 * safetensors is a deliberately boring, safe-by-design format: no code
 * execution surface, no opcodes, just data. Layout:
 *
 *   [0..8)    little-endian uint64 header length N
 *   [8..8+N)  UTF-8 JSON header: { "<tensor name>": { dtype, shape,
 *             data_offsets: [start, end] }, ..., "__metadata__"?: {...} }
 *   [8+N..)   raw tensor bytes, referenced by each tensor's data_offsets
 *             (relative to the start of this data section)
 *
 * Because there's no code execution surface here, ModelSBOM's job for
 * this format is honestly just an integrity/consistency check: do the
 * declared tensor byte ranges make sense, do they fit inside the file,
 * do they overlap, does dtype/shape agree with the declared byte range.
 */
import { Finding, SafetensorsScanResult, Verdict } from "../types";

const DTYPE_BYTE_SIZES: Record<string, number> = {
  BOOL: 1,
  U8: 1,
  I8: 1,
  F8_E4M3: 1,
  F8_E5M2: 1,
  I16: 2,
  U16: 2,
  F16: 2,
  BF16: 2,
  I32: 4,
  U32: 4,
  F32: 4,
  I64: 8,
  U64: 8,
  F64: 8,
};

interface RawTensorEntry {
  dtype: string;
  shape: number[];
  data_offsets: [number, number];
}

function verdictFromFindings(findings: Finding[]): Verdict {
  return findings.some((f) => f.severity === "high" || f.severity === "medium")
    ? "INVALID"
    : "VALID";
}

export function scanSafetensorsFile(buf: Buffer): SafetensorsScanResult {
  const findings: Finding[] = [];
  const empty = (verdict: Verdict): SafetensorsScanResult => ({
    format: "safetensors",
    verdict,
    headerLength: 0,
    tensorCount: 0,
    tensors: [],
    findings,
  });

  if (buf.length < 8) {
    findings.push({
      severity: "high",
      code: "SAFETENSORS_TRUNCATED_HEADER_LENGTH",
      message: "File is smaller than the 8-byte header-length prefix - not a valid safetensors file.",
    });
    return empty("INVALID");
  }

  const headerLengthBig = buf.readBigUInt64LE(0);
  if (headerLengthBig > BigInt(Number.MAX_SAFE_INTEGER)) {
    findings.push({
      severity: "high",
      code: "SAFETENSORS_ABSURD_HEADER_LENGTH",
      message: "Declared header length is absurdly large.",
    });
    return empty("INVALID");
  }
  const headerLength = Number(headerLengthBig);

  if (headerLength <= 0 || 8 + headerLength > buf.length) {
    findings.push({
      severity: "high",
      code: "SAFETENSORS_HEADER_OUT_OF_BOUNDS",
      message: `Declared header length (${headerLength} bytes) does not fit within the file (${buf.length} bytes total).`,
    });
    return empty("INVALID");
  }

  const headerBytes = buf.subarray(8, 8 + headerLength);
  let header: Record<string, unknown>;
  try {
    header = JSON.parse(headerBytes.toString("utf8"));
  } catch (err) {
    findings.push({
      severity: "high",
      code: "SAFETENSORS_HEADER_NOT_JSON",
      message: `Header is not valid JSON: ${err instanceof Error ? err.message : String(err)}`,
    });
    return empty("INVALID");
  }

  const dataSectionLength = buf.length - 8 - headerLength;
  const tensors: SafetensorsScanResult["tensors"] = [];
  let metadata: Record<string, string> | undefined;

  const ranges: Array<{ name: string; start: number; end: number }> = [];

  for (const [name, rawValue] of Object.entries(header)) {
    if (name === "__metadata__") {
      if (rawValue && typeof rawValue === "object") {
        metadata = rawValue as Record<string, string>;
      }
      continue;
    }
    const entry = rawValue as Partial<RawTensorEntry>;

    if (
      typeof entry !== "object" ||
      entry === null ||
      typeof entry.dtype !== "string" ||
      !Array.isArray(entry.shape) ||
      !Array.isArray(entry.data_offsets) ||
      entry.data_offsets.length !== 2
    ) {
      findings.push({
        severity: "medium",
        code: "SAFETENSORS_MALFORMED_TENSOR_ENTRY",
        message: `Tensor "${name}" has a malformed header entry (missing dtype/shape/data_offsets).`,
      });
      continue;
    }

    const [start, end] = entry.data_offsets as [number, number];
    const shape = entry.shape as number[];
    const dtype = entry.dtype;

    tensors.push({ name, dtype, shape, dataOffsets: [start, end] });

    if (!Number.isFinite(start) || !Number.isFinite(end) || start < 0 || end < start) {
      findings.push({
        severity: "high",
        code: "SAFETENSORS_INVALID_OFFSET_RANGE",
        message: `Tensor "${name}" has an invalid byte range [${start}, ${end}).`,
      });
      continue;
    }

    if (end > dataSectionLength) {
      findings.push({
        severity: "high",
        code: "SAFETENSORS_OFFSET_OVERFLOWS_FILE",
        message: `Tensor "${name}" declares byte range [${start}, ${end}) but the data section is only ${dataSectionLength} bytes - this tensor's data would read past the end of the file.`,
      });
      continue;
    }

    const elementSize = DTYPE_BYTE_SIZES[dtype];
    if (elementSize === undefined) {
      findings.push({
        severity: "low",
        code: "SAFETENSORS_UNKNOWN_DTYPE",
        message: `Tensor "${name}" declares unrecognized dtype "${dtype}" - cannot verify its byte range matches its shape.`,
      });
    } else {
      const elementCount = shape.reduce((a, b) => a * b, 1);
      const expectedBytes = elementCount * elementSize;
      const actualBytes = end - start;
      if (expectedBytes !== actualBytes) {
        findings.push({
          severity: "medium",
          code: "SAFETENSORS_SHAPE_SIZE_MISMATCH",
          message: `Tensor "${name}" has shape ${JSON.stringify(
            shape
          )} and dtype ${dtype}, which implies ${expectedBytes} byte(s), but its declared byte range [${start}, ${end}) is ${actualBytes} byte(s).`,
        });
      }
    }

    ranges.push({ name, start, end });
  }

  ranges.sort((a, b) => a.start - b.start);
  for (let i = 1; i < ranges.length; i++) {
    if (ranges[i].start < ranges[i - 1].end) {
      findings.push({
        severity: "high",
        code: "SAFETENSORS_OVERLAPPING_TENSORS",
        message: `Tensor "${ranges[i].name}" [${ranges[i].start}, ${ranges[i].end}) overlaps tensor "${ranges[i - 1].name}" [${ranges[i - 1].start}, ${ranges[i - 1].end}).`,
      });
    }
  }

  if (findings.length === 0) {
    findings.push({
      severity: "info",
      code: "SAFETENSORS_STRUCTURALLY_VALID",
      message:
        "Header parsed successfully and all tensor byte ranges are internally consistent. " +
        "Note: safetensors has no code-execution surface by design, so this is an integrity " +
        "check, not a malware scan.",
    });
  }

  return {
    format: "safetensors",
    verdict: verdictFromFindings(findings),
    headerLength,
    tensorCount: tensors.length,
    tensors,
    metadata,
    findings,
  };
}
