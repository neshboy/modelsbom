import { describe, it, expect } from "vitest";
import { scanPickleBytes } from "../src/pickle/scanner";
import { buildDangerousPickle, buildCleanPickle } from "./fixtures";

describe("pickle opcode scanner", () => {
  it("flags the hand-built dangerous pickle (GLOBAL os.system + REDUCE) as high severity", () => {
    const outcome = scanPickleBytes(buildDangerousPickle());

    // The GLOBAL reference itself must be recorded and NOT allowlisted.
    expect(outcome.globalReferences).toHaveLength(1);
    expect(outcome.globalReferences[0].module).toBe("os");
    expect(outcome.globalReferences[0].name).toBe("system");
    expect(outcome.globalReferences[0].allowlisted).toBe(false);

    // At least one HIGH severity finding must exist, and it must clearly
    // name os.system as the invoked callable.
    const highFindings = outcome.findings.filter((f) => f.severity === "high");
    expect(highFindings.length).toBeGreaterThan(0);
    expect(highFindings.some((f) => f.message.includes("os.system"))).toBe(true);

    // Specifically, the REDUCE-invocation finding must be present.
    const invoked = outcome.findings.find((f) => f.code === "PICKLE_UNSAFE_GLOBAL_INVOKED");
    expect(invoked).toBeDefined();
    expect(invoked?.detail).toContain("REDUCE");
    expect(invoked?.detail).toContain("os.system");

    // And the reference-time finding for a known-dangerous module.
    const dangerousRef = outcome.findings.find(
      (f) => f.code === "PICKLE_DANGEROUS_GLOBAL_REFERENCED"
    );
    expect(dangerousRef).toBeDefined();
  });

  it("does NOT flag a clean pickle referencing only collections.OrderedDict", () => {
    const outcome = scanPickleBytes(buildCleanPickle());

    expect(outcome.globalReferences).toHaveLength(1);
    expect(outcome.globalReferences[0].module).toBe("collections");
    expect(outcome.globalReferences[0].name).toBe("OrderedDict");
    expect(outcome.globalReferences[0].allowlisted).toBe(true);

    const highOrMedium = outcome.findings.filter(
      (f) => f.severity === "high" || f.severity === "medium"
    );
    expect(highOrMedium).toHaveLength(0);
  });

  it("does not flag torch tensor-rebuild globals used in real checkpoints", () => {
    // GLOBAL torch._utils _rebuild_tensor_v2 ; EMPTY_TUPLE ; REDUCE ; STOP
    const buf = Buffer.concat([
      Buffer.from([0x80, 0x02]),
      Buffer.from("c", "latin1"),
      Buffer.from("torch._utils\n_rebuild_tensor_v2\n", "latin1"),
      Buffer.from(")", "latin1"),
      Buffer.from("R", "latin1"),
      Buffer.from(".", "latin1"),
    ]);
    const outcome = scanPickleBytes(buf);
    expect(outcome.globalReferences[0].allowlisted).toBe(true);
    expect(outcome.findings.filter((f) => f.severity === "high")).toHaveLength(0);
  });

  it("flags STACK_GLOBAL + REDUCE (protocol 4 style) referencing subprocess.call", () => {
    // PROTO 4; SHORT_BINUNICODE "subprocess"; SHORT_BINUNICODE "call";
    // STACK_GLOBAL; EMPTY_TUPLE; REDUCE; STOP
    function shortBinUnicode(value: string): Buffer {
      const data = Buffer.from(value, "utf8");
      return Buffer.concat([Buffer.from([0x8c, data.length]), data]);
    }
    const buf = Buffer.concat([
      Buffer.from([0x80, 0x04]),
      shortBinUnicode("subprocess"),
      shortBinUnicode("call"),
      Buffer.from([0x93]), // STACK_GLOBAL
      Buffer.from(")", "latin1"), // EMPTY_TUPLE
      Buffer.from("R", "latin1"), // REDUCE
      Buffer.from(".", "latin1"), // STOP
    ]);
    const outcome = scanPickleBytes(buf);
    expect(outcome.globalReferences[0]).toMatchObject({ module: "subprocess", name: "call" });
    const invoked = outcome.findings.find((f) => f.code === "PICKLE_UNSAFE_GLOBAL_INVOKED");
    expect(invoked).toBeDefined();
  });

  it("reports a parse error (medium severity) for a truncated/malformed stream instead of crashing", () => {
    // GLOBAL opcode with no terminating newline at all -> unterminated text arg.
    const buf = Buffer.concat([Buffer.from([0x80, 0x02]), Buffer.from("c", "latin1"), Buffer.from("os")]);
    const outcome = scanPickleBytes(buf);
    expect(outcome.findings.some((f) => f.code === "PICKLE_PARSE_ERROR")).toBe(true);
  });
});
