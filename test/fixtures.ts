/**
 * Real, hand-built test fixtures - no fake/stubbed files. Every byte here
 * is constructed according to the actual documented format spec (pickle
 * opcode set, ZIP local/central directory records, safetensors header
 * layout, GGUF header layout) so the tests exercise the real parsers.
 */
import { buildZip } from "../src/zip";

// ---------------------------------------------------------------------------
// Pickle opcode fixtures
// ---------------------------------------------------------------------------

/** Encode a GLOBAL opcode: 'c' + "<module>\n<name>\n" */
function globalOp(moduleName: string, name: string): Buffer {
  return Buffer.concat([
    Buffer.from("c", "latin1"),
    Buffer.from(`${moduleName}\n${name}\n`, "latin1"),
  ]);
}

/** SHORT_BINUNICODE opcode: 0x8c + 1-byte length + utf8 bytes */
function shortBinUnicode(value: string): Buffer {
  const data = Buffer.from(value, "utf8");
  return Buffer.concat([Buffer.from([0x8c, data.length]), data]);
}

const PROTO2 = Buffer.from([0x80, 0x02]);
const TUPLE1 = Buffer.from([0x85]);
const EMPTY_TUPLE = Buffer.from(")", "latin1");
const REDUCE = Buffer.from("R", "latin1");
const STOP = Buffer.from(".", "latin1");

/**
 * The textbook malicious pickle payload (the same one fickling/ModelScan
 * use as their canonical example): GLOBAL "os" "system", push a 1-tuple
 * containing a shell command string, REDUCE -> calls os.system("...").
 * If this were ever unpickled (e.g. via torch.load()) it would run the
 * shell command.
 */
export function buildDangerousPickle(): Buffer {
  return Buffer.concat([
    PROTO2,
    globalOp("os", "system"),
    shortBinUnicode("echo pwned > /tmp/pwned"),
    TUPLE1,
    REDUCE,
    STOP,
  ]);
}

/**
 * A clean pickle in the same shape (GLOBAL + REDUCE) but referencing only
 * collections.OrderedDict(), which is exactly how PyTorch state_dict()
 * checkpoints are normally structured. This must NOT be flagged as
 * dangerous.
 */
export function buildCleanPickle(): Buffer {
  return Buffer.concat([
    PROTO2,
    globalOp("collections", "OrderedDict"),
    EMPTY_TUPLE,
    REDUCE,
    STOP,
  ]);
}

/** Wrap raw pickle bytes in a minimal torch.save()-style ZIP archive. */
export function buildPytorchZip(pickleBytes: Buffer, opts?: { compress?: boolean }): Buffer {
  return buildZip([
    { name: "archive/data.pkl", data: pickleBytes, compress: opts?.compress },
    { name: "archive/data/0", data: Buffer.from([1, 2, 3, 4]), compress: opts?.compress },
    { name: "archive/version", data: Buffer.from("3\n"), compress: opts?.compress },
  ]);
}

// ---------------------------------------------------------------------------
// safetensors fixtures
// ---------------------------------------------------------------------------

export function buildValidSafetensors(): Buffer {
  // One small F32 tensor, shape [2, 2] -> 4 elements * 4 bytes = 16 bytes.
  const tensorData = Buffer.alloc(16);
  for (let i = 0; i < 4; i++) tensorData.writeFloatLE(i + 0.5, i * 4);

  const header = {
    weight: {
      dtype: "F32",
      shape: [2, 2],
      data_offsets: [0, 16],
    },
    __metadata__: { format: "modelsbom-test" },
  };
  const headerBytes = Buffer.from(JSON.stringify(header), "utf8");
  const headerLenBuf = Buffer.alloc(8);
  headerLenBuf.writeBigUInt64LE(BigInt(headerBytes.length), 0);

  return Buffer.concat([headerLenBuf, headerBytes, tensorData]);
}

/** Same as buildValidSafetensors but with a deliberately inconsistent offset. */
export function buildCorruptSafetensors(): Buffer {
  const tensorData = Buffer.alloc(16);
  for (let i = 0; i < 4; i++) tensorData.writeFloatLE(i + 0.5, i * 4);

  const header = {
    weight: {
      dtype: "F32",
      shape: [2, 2],
      // Declares 32 bytes (end=32) but only 16 bytes of tensor data
      // actually follow the header - this must be caught as an overflow.
      data_offsets: [0, 32],
    },
  };
  const headerBytes = Buffer.from(JSON.stringify(header), "utf8");
  const headerLenBuf = Buffer.alloc(8);
  headerLenBuf.writeBigUInt64LE(BigInt(headerBytes.length), 0);

  return Buffer.concat([headerLenBuf, headerBytes, tensorData]);
}

/** Two tensors whose declared byte ranges overlap - internally inconsistent. */
export function buildOverlappingSafetensors(): Buffer {
  const tensorData = Buffer.alloc(16);
  const header = {
    a: { dtype: "U8", shape: [8], data_offsets: [0, 8] },
    b: { dtype: "U8", shape: [8], data_offsets: [4, 12] }, // overlaps "a"
  };
  const headerBytes = Buffer.from(JSON.stringify(header), "utf8");
  const headerLenBuf = Buffer.alloc(8);
  headerLenBuf.writeBigUInt64LE(BigInt(headerBytes.length), 0);
  return Buffer.concat([headerLenBuf, headerBytes, tensorData]);
}

// ---------------------------------------------------------------------------
// GGUF fixtures
// ---------------------------------------------------------------------------

function ggufString(value: string): Buffer {
  const data = Buffer.from(value, "utf8");
  const lenBuf = Buffer.alloc(8);
  lenBuf.writeBigUInt64LE(BigInt(data.length), 0);
  return Buffer.concat([lenBuf, data]);
}

/**
 * A minimal but valid GGUF file: magic, version 3, zero tensors, one
 * string metadata key ("general.architecture" = "llama").
 */
export function buildValidGguf(): Buffer {
  const magic = Buffer.from([0x47, 0x47, 0x55, 0x46]); // "GGUF"
  const version = Buffer.alloc(4);
  version.writeUInt32LE(3, 0);
  const tensorCount = Buffer.alloc(8);
  tensorCount.writeBigUInt64LE(0n, 0);
  const kvCount = Buffer.alloc(8);
  kvCount.writeBigUInt64LE(1n, 0);

  const key = ggufString("general.architecture");
  const valueType = Buffer.alloc(4);
  valueType.writeUInt32LE(8, 0); // STRING
  const value = ggufString("llama");

  return Buffer.concat([magic, version, tensorCount, kvCount, key, valueType, value]);
}

/** A GGUF file truncated mid-way through the metadata string value. */
export function buildTruncatedGguf(): Buffer {
  const valid = buildValidGguf();
  // Cut it off partway through the metadata value's string bytes so the
  // declared string length cannot be satisfied by the remaining bytes.
  return valid.subarray(0, valid.length - 3);
}
