import { describe, it, expect } from "vitest";
import { buildFileReport } from "../src/scanFile";
import { buildScanReport, renderHumanReadable } from "../src/report";
import {
  buildDangerousPickle,
  buildCleanPickle,
  buildPytorchZip,
  buildValidSafetensors,
  buildCorruptSafetensors,
  buildValidGguf,
  buildTruncatedGguf,
} from "./fixtures";

describe("end-to-end format detection + reporting", () => {
  it("detects .pt extension and flags a dangerous checkpoint end-to-end", () => {
    const report = buildFileReport("model.pt", buildPytorchZip(buildDangerousPickle()));
    expect(report.result.format).toBe("pytorch-pickle");
    expect(report.result.verdict).toBe("DANGEROUS");
  });

  it("detects .pth extension and clears a clean checkpoint end-to-end", () => {
    const report = buildFileReport("model.pth", buildPytorchZip(buildCleanPickle()));
    expect(report.result.verdict).toBe("CLEAN");
  });

  it("detects .safetensors by extension", () => {
    const report = buildFileReport("model.safetensors", buildValidSafetensors());
    expect(report.result.format).toBe("safetensors");
    expect(report.result.verdict).toBe("VALID");
  });

  it("detects .gguf by extension", () => {
    const report = buildFileReport("model.gguf", buildValidGguf());
    expect(report.result.format).toBe("gguf");
    expect(report.result.verdict).toBe("VALID");
  });

  it("falls back to magic-byte sniffing for a .bin file that is actually a ZIP torch checkpoint", () => {
    const report = buildFileReport("weird_extension_model.bin", buildPytorchZip(buildDangerousPickle()));
    expect(report.result.format).toBe("pytorch-pickle");
    expect(report.result.verdict).toBe("DANGEROUS");
  });

  it("builds a full multi-file report with an accurate summary and renders human-readable text", () => {
    const files = [
      buildFileReport("dangerous.pt", buildPytorchZip(buildDangerousPickle())),
      buildFileReport("clean.pth", buildPytorchZip(buildCleanPickle())),
      buildFileReport("good.safetensors", buildValidSafetensors()),
      buildFileReport("bad.safetensors", buildCorruptSafetensors()),
      buildFileReport("good.gguf", buildValidGguf()),
      buildFileReport("bad.gguf", buildTruncatedGguf()),
    ];
    const report = buildScanReport(files);

    expect(report.summary).toEqual({
      filesScanned: 6,
      dangerous: 1,
      suspicious: 0,
      invalid: 2,
      clean: 3,
    });

    const text = renderHumanReadable(report);
    expect(text).toContain("[DANGEROUS] dangerous.pt");
    expect(text).toContain("[CLEAN] clean.pth");
    expect(text).toContain("[VALID] good.safetensors");
    expect(text).toContain("[INVALID] bad.safetensors");
    expect(text).toContain("[VALID] good.gguf");
    expect(text).toContain("[INVALID] bad.gguf");
    expect(text).toContain("os.system");
  });
});
