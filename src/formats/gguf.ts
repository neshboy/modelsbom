/**
 * GGUF structural parsing.
 *
 * GGUF (used by llama.cpp / Ollama / LM Studio for quantized model
 * weights) is a documented binary container:
 *
 *   uint32   magic ("GGUF" as bytes 0x47 0x47 0x55 0x46, i.e. 0x46554747 LE)
 *   uint32   version
 *   uint64   tensor_count
 *   uint64   metadata_kv_count
 *   metadata_kv_count * { key: gguf_string, value_type: uint32, value }
 *   tensor_count * { name: gguf_string, n_dims: uint32, dims: uint64[n_dims],
 *                     ggml_type: uint32, offset: uint64 }
 *
 * Like safetensors, this is pure data with no code-execution surface -
 * ModelSBOM's job here is to parse it correctly and report what's inside
 * (architecture, tensor count, quantization, etc), and to flag structural
 * corruption (truncated files, out-of-bounds lengths) rather than to hunt
 * for exploits that this format has no mechanism to carry.
 */
import { Finding, GgufScanResult, Verdict } from "../types";

const GGUF_MAGIC = 0x46554747; // "GGUF" little-endian

enum GgufValueType {
  UINT8 = 0,
  INT8 = 1,
  UINT16 = 2,
  INT16 = 3,
  UINT32 = 4,
  INT32 = 5,
  FLOAT32 = 6,
  BOOL = 7,
  STRING = 8,
  ARRAY = 9,
  UINT64 = 10,
  INT64 = 11,
  FLOAT64 = 12,
}

class OutOfBoundsError extends Error {}

class Cursor {
  pos = 0;
  constructor(private buf: Buffer) {}

  private need(n: number) {
    if (this.pos + n > this.buf.length) {
      throw new OutOfBoundsError(
        `Unexpected end of file at offset ${this.pos}: need ${n} more byte(s), only ${
          this.buf.length - this.pos
        } available`
      );
    }
  }

  u8(): number {
    this.need(1);
    const v = this.buf.readUInt8(this.pos);
    this.pos += 1;
    return v;
  }
  i8(): number {
    this.need(1);
    const v = this.buf.readInt8(this.pos);
    this.pos += 1;
    return v;
  }
  u16(): number {
    this.need(2);
    const v = this.buf.readUInt16LE(this.pos);
    this.pos += 2;
    return v;
  }
  i16(): number {
    this.need(2);
    const v = this.buf.readInt16LE(this.pos);
    this.pos += 2;
    return v;
  }
  u32(): number {
    this.need(4);
    const v = this.buf.readUInt32LE(this.pos);
    this.pos += 4;
    return v;
  }
  i32(): number {
    this.need(4);
    const v = this.buf.readInt32LE(this.pos);
    this.pos += 4;
    return v;
  }
  f32(): number {
    this.need(4);
    const v = this.buf.readFloatLE(this.pos);
    this.pos += 4;
    return v;
  }
  u64(): bigint {
    this.need(8);
    const v = this.buf.readBigUInt64LE(this.pos);
    this.pos += 8;
    return v;
  }
  i64(): bigint {
    this.need(8);
    const v = this.buf.readBigInt64LE(this.pos);
    this.pos += 8;
    return v;
  }
  f64(): number {
    this.need(8);
    const v = this.buf.readDoubleLE(this.pos);
    this.pos += 8;
    return v;
  }
  bool(): boolean {
    return this.u8() !== 0;
  }
  bytes(n: number): Buffer {
    this.need(n);
    const v = this.buf.subarray(this.pos, this.pos + n);
    this.pos += n;
    return v;
  }
  ggufString(): string {
    const lenBig = this.u64();
    if (lenBig > BigInt(Number.MAX_SAFE_INTEGER)) {
      throw new OutOfBoundsError("String length field is absurdly large");
    }
    const len = Number(lenBig);
    return this.bytes(len).toString("utf8");
  }
}

function toSafeNumber(big: bigint): number | string {
  return big <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(big) : big.toString();
}

function readValue(c: Cursor, type: number): unknown {
  switch (type) {
    case GgufValueType.UINT8:
      return c.u8();
    case GgufValueType.INT8:
      return c.i8();
    case GgufValueType.UINT16:
      return c.u16();
    case GgufValueType.INT16:
      return c.i16();
    case GgufValueType.UINT32:
      return c.u32();
    case GgufValueType.INT32:
      return c.i32();
    case GgufValueType.FLOAT32:
      return c.f32();
    case GgufValueType.BOOL:
      return c.bool();
    case GgufValueType.STRING:
      return c.ggufString();
    case GgufValueType.UINT64:
      return toSafeNumber(c.u64());
    case GgufValueType.INT64:
      return toSafeNumber(c.i64());
    case GgufValueType.FLOAT64:
      return c.f64();
    case GgufValueType.ARRAY: {
      const elemType = c.u32();
      const lenBig = c.u64();
      if (lenBig > BigInt(1_000_000)) {
        // Sanity cap: refuse to allocate absurd arrays for a truncated/
        // malicious length field. Real GGUF arrays (e.g. tokenizer
        // vocabularies) are large but not this large per-element-count
        // relative to typical metadata array sizes; treat as corruption.
        throw new OutOfBoundsError(`Implausible array length (${lenBig}) in metadata value`);
      }
      const len = Number(lenBig);
      const values: unknown[] = [];
      for (let i = 0; i < len; i++) {
        values.push(readValue(c, elemType));
      }
      return values;
    }
    default:
      throw new OutOfBoundsError(`Unknown GGUF metadata value type ${type}`);
  }
}

function verdictFromFindings(findings: Finding[]): Verdict {
  return findings.some((f) => f.severity === "high" || f.severity === "medium")
    ? "INVALID"
    : "VALID";
}

export function scanGgufFile(buf: Buffer): GgufScanResult {
  const findings: Finding[] = [];
  const invalid = (code: string, message: string): GgufScanResult => {
    findings.push({ severity: "high", code, message });
    return {
      format: "gguf",
      verdict: "INVALID",
      version: 0,
      tensorCount: 0,
      metadataCount: 0,
      metadata: {},
      findings,
    };
  };

  if (buf.length < 8) {
    return invalid("GGUF_TRUNCATED", "File is smaller than the GGUF magic+version header.");
  }

  const magic = buf.readUInt32LE(0);
  if (magic !== GGUF_MAGIC) {
    return invalid(
      "GGUF_BAD_MAGIC",
      `Magic bytes do not match "GGUF" (expected 0x${GGUF_MAGIC.toString(16)}, got 0x${magic
        .toString(16)
        .padStart(8, "0")}).`
    );
  }

  const cursor = new Cursor(buf);
  cursor.pos = 4;

  try {
    const version = cursor.u32();
    const tensorCountBig = cursor.u64();
    const metadataCountBig = cursor.u64();

    if (tensorCountBig > BigInt(1_000_000) || metadataCountBig > BigInt(1_000_000)) {
      return invalid(
        "GGUF_IMPLAUSIBLE_COUNTS",
        `Declared tensor_count (${tensorCountBig}) or metadata_kv_count (${metadataCountBig}) is implausibly large - file is likely truncated or corrupted.`
      );
    }

    const tensorCount = Number(tensorCountBig);
    const metadataCount = Number(metadataCountBig);
    const metadata: Record<string, unknown> = {};

    for (let i = 0; i < metadataCount; i++) {
      const key = cursor.ggufString();
      const valueType = cursor.u32();
      const value = readValue(cursor, valueType);
      metadata[key] = value;
    }

    interface TensorInfo {
      name: string;
      dims: number[];
      ggmlType: number;
      offset: number | string;
    }
    const tensors: TensorInfo[] = [];
    for (let i = 0; i < tensorCount; i++) {
      const name = cursor.ggufString();
      const nDims = cursor.u32();
      if (nDims > 64) {
        throw new OutOfBoundsError(`Implausible tensor dimension count (${nDims}) for "${name}"`);
      }
      const dims: number[] = [];
      for (let d = 0; d < nDims; d++) {
        dims.push(Number(cursor.u64()));
      }
      const ggmlType = cursor.u32();
      const offset = toSafeNumber(cursor.u64());
      tensors.push({ name, dims, ggmlType, offset });
    }

    if (findings.length === 0) {
      findings.push({
        severity: "info",
        code: "GGUF_STRUCTURALLY_VALID",
        message: `Header, ${metadataCount} metadata key/value pair(s), and ${tensorCount} tensor descriptor(s) parsed successfully. GGUF has no code-execution surface by design - this is a structural/metadata report, not a malware scan.`,
      });
    }

    return {
      format: "gguf",
      verdict: verdictFromFindings(findings),
      version,
      tensorCount,
      metadataCount,
      metadata,
      findings,
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return invalid("GGUF_PARSE_ERROR", `Failed to parse GGUF structure: ${message}`);
  }
}
