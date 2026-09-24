import { describe, it, expect } from "vitest";
import { scanGgufFile } from "../src/formats/gguf";
import { buildValidGguf, buildTruncatedGguf } from "./fixtures";

describe("GGUF structural parser", () => {
  it("parses a real, minimal, valid GGUF header and reports its metadata", () => {
    const result = scanGgufFile(buildValidGguf());

    expect(result.verdict).toBe("VALID");
    expect(result.version).toBe(3);
    expect(result.tensorCount).toBe(0);
    expect(result.metadataCount).toBe(1);
    expect(result.metadata["general.architecture"]).toBe("llama");
    expect(result.findings.every((f) => f.severity === "info")).toBe(true);
  });

  it("catches a truncated/corrupted GGUF file instead of crashing", () => {
    const result = scanGgufFile(buildTruncatedGguf());

    expect(result.verdict).toBe("INVALID");
    expect(result.findings.some((f) => f.severity === "high")).toBe(true);
  });

  it("rejects a file with the wrong magic bytes", () => {
    const notGguf = Buffer.from("NOTGGUFDATA........");
    const result = scanGgufFile(notGguf);
    expect(result.verdict).toBe("INVALID");
    expect(result.findings[0].code).toBe("GGUF_BAD_MAGIC");
  });

  it("rejects a file too small to contain the magic+version header", () => {
    const result = scanGgufFile(Buffer.from([0x47, 0x47]));
    expect(result.verdict).toBe("INVALID");
    expect(result.findings[0].code).toBe("GGUF_TRUNCATED");
  });
});
