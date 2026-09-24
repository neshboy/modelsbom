import { describe, it, expect } from "vitest";
import { scanSafetensorsFile } from "../src/formats/safetensors";
import {
  buildValidSafetensors,
  buildCorruptSafetensors,
  buildOverlappingSafetensors,
} from "./fixtures";

describe("safetensors structural validator", () => {
  it("accepts a real, minimal, valid safetensors file", () => {
    const result = scanSafetensorsFile(buildValidSafetensors());

    expect(result.verdict).toBe("VALID");
    expect(result.tensorCount).toBe(1);
    expect(result.tensors[0]).toMatchObject({
      name: "weight",
      dtype: "F32",
      shape: [2, 2],
      dataOffsets: [0, 16],
    });
    expect(result.metadata).toEqual({ format: "modelsbom-test" });
    expect(result.findings.every((f) => f.severity === "info")).toBe(true);
  });

  it("catches a corrupted file with an offset that overflows the data section", () => {
    const result = scanSafetensorsFile(buildCorruptSafetensors());

    expect(result.verdict).toBe("INVALID");
    expect(
      result.findings.some((f) => f.code === "SAFETENSORS_OFFSET_OVERFLOWS_FILE")
    ).toBe(true);
  });

  it("catches two tensors whose declared byte ranges overlap", () => {
    const result = scanSafetensorsFile(buildOverlappingSafetensors());

    expect(result.verdict).toBe("INVALID");
    expect(result.findings.some((f) => f.code === "SAFETENSORS_OVERLAPPING_TENSORS")).toBe(true);
  });

  it("rejects a file smaller than the 8-byte header-length prefix", () => {
    const result = scanSafetensorsFile(Buffer.from([1, 2, 3]));
    expect(result.verdict).toBe("INVALID");
    expect(result.findings[0].code).toBe("SAFETENSORS_TRUNCATED_HEADER_LENGTH");
  });

  it("rejects a header length that doesn't fit in the file", () => {
    const headerLenBuf = Buffer.alloc(8);
    headerLenBuf.writeBigUInt64LE(9999n, 0);
    const result = scanSafetensorsFile(Buffer.concat([headerLenBuf, Buffer.from("{}")]));
    expect(result.verdict).toBe("INVALID");
    expect(result.findings[0].code).toBe("SAFETENSORS_HEADER_OUT_OF_BOUNDS");
  });

  it("flags a shape/dtype vs byte-range mismatch", () => {
    const header = { w: { dtype: "F32", shape: [4], data_offsets: [0, 8] } }; // should be 16 bytes, declares 8
    const headerBytes = Buffer.from(JSON.stringify(header), "utf8");
    const headerLenBuf = Buffer.alloc(8);
    headerLenBuf.writeBigUInt64LE(BigInt(headerBytes.length), 0);
    const buf = Buffer.concat([headerLenBuf, headerBytes, Buffer.alloc(8)]);

    const result = scanSafetensorsFile(buf);
    expect(result.verdict).toBe("INVALID");
    expect(result.findings.some((f) => f.code === "SAFETENSORS_SHAPE_SIZE_MISMATCH")).toBe(true);
  });
});
