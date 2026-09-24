import { describe, it, expect } from "vitest";
import { scanPytorchFile } from "../src/formats/pytorch";
import { buildZip } from "../src/zip";
import {
  buildDangerousPickle,
  buildCleanPickle,
  buildPytorchZip,
} from "./fixtures";

describe("PyTorch (.pt-style ZIP) scanner", () => {
  it("marks a ZIP archive whose data.pkl contains os.system+REDUCE as DANGEROUS", () => {
    const zip = buildPytorchZip(buildDangerousPickle());
    const result = scanPytorchFile(zip);

    expect(result.format).toBe("pytorch-pickle");
    expect(result.pickleEntryName).toBe("archive/data.pkl");
    expect(result.verdict).toBe("DANGEROUS");
    expect(result.findings.some((f) => f.severity === "high")).toBe(true);
  });

  it("marks a ZIP archive whose data.pkl only builds OrderedDict as CLEAN", () => {
    const zip = buildPytorchZip(buildCleanPickle());
    const result = scanPytorchFile(zip);

    expect(result.verdict).toBe("CLEAN");
    expect(result.findings.filter((f) => f.severity === "high" || f.severity === "medium")).toHaveLength(0);
  });

  it("also detects danger when the ZIP entry is DEFLATE-compressed", () => {
    const zip = buildPytorchZip(buildDangerousPickle(), { compress: true });
    const result = scanPytorchFile(zip);
    expect(result.verdict).toBe("DANGEROUS");
  });

  it("scans legacy (non-ZIP) raw pickle streams the same way", () => {
    const dangerous = scanPytorchFile(buildDangerousPickle());
    expect(dangerous.pickleEntryName).toContain("legacy");
    expect(dangerous.verdict).toBe("DANGEROUS");

    const clean = scanPytorchFile(buildCleanPickle());
    expect(clean.verdict).toBe("CLEAN");
  });

  it("reports INVALID when a ZIP has no data.pkl entry", () => {
    const zip = buildZip([{ name: "archive/version", data: Buffer.from("3\n") }]);
    const result = scanPytorchFile(zip);
    expect(result.verdict).toBe("INVALID");
  });
});
