import { describe, it, expect } from "vitest";
import { buildZip, listZipEntries, extractZipEntry, isZip, readZipEntryByName } from "../src/zip";

describe("zip reader/writer", () => {
  it("round-trips a stored (uncompressed) entry, matching torch.save()'s default", () => {
    const payload = Buffer.from("hello modelsbom, stored entry", "utf8");
    const zip = buildZip([{ name: "archive/data.pkl", data: payload }]);

    expect(isZip(zip)).toBe(true);
    const entries = listZipEntries(zip);
    expect(entries).toHaveLength(1);
    expect(entries[0].name).toBe("archive/data.pkl");
    expect(entries[0].compressionMethod).toBe(0);

    const extracted = extractZipEntry(zip, entries[0]);
    expect(extracted.equals(payload)).toBe(true);
  });

  it("round-trips a deflate-compressed entry", () => {
    const payload = Buffer.from("x".repeat(5000), "utf8");
    const zip = buildZip([{ name: "archive/data.pkl", data: payload, compress: true }]);

    const entries = listZipEntries(zip);
    expect(entries[0].compressionMethod).toBe(8);
    expect(entries[0].compressedSize).toBeLessThan(payload.length);

    const extracted = extractZipEntry(zip, entries[0]);
    expect(extracted.equals(payload)).toBe(true);
  });

  it("handles multiple entries and finds one by name", () => {
    const zip = buildZip([
      { name: "archive/version", data: Buffer.from("3\n") },
      { name: "archive/data.pkl", data: Buffer.from("pickle-bytes-here") },
      { name: "archive/data/0", data: Buffer.from([9, 9, 9]) },
    ]);
    const entries = listZipEntries(zip);
    expect(entries.map((e) => e.name)).toEqual([
      "archive/version",
      "archive/data.pkl",
      "archive/data/0",
    ]);

    const pkl = readZipEntryByName(zip, "data.pkl");
    expect(pkl?.toString("utf8")).toBe("pickle-bytes-here");
  });

  it("rejects non-ZIP data", () => {
    const notAZip = Buffer.from("this is definitely not a zip file at all");
    expect(isZip(notAZip)).toBe(false);
    expect(() => listZipEntries(notAZip)).toThrow();
  });
});
