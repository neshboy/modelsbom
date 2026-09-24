/**
 * The actual danger-detection logic. Built on top of the real opcode
 * disassembler (disassembler.ts): we replay the pickle VM's stack effects
 * just enough to know, for every REDUCE / NEWOBJ / NEWOBJ_EX / OBJ / INST /
 * BUILD opcode (the opcodes that call something), *what* is being called -
 * because that's the load-bearing fact for whether a pickle can execute
 * arbitrary code on `torch.load()`/`pickle.load()`.
 *
 * This is the same technique real tools (fickling, ModelScan) use: GLOBAL
 * (or STACK_GLOBAL) pushes a reference to some `module.name` callable, and
 * REDUCE/NEWOBJ/etc. then calls it with attacker-controlled arguments. If
 * that callable isn't on a small allowlist of known-safe torch/numpy/stdlib
 * rebuild helpers, the pickle can do anything Python can do the moment it's
 * loaded.
 */
import { disassemble, DisassembledOp, PickleParseError } from "./disassembler";
import { isAllowlisted, isKnownDangerous } from "./allowlist";
import { Finding, PickleGlobalRef } from "../types";

type StackValue =
  | { kind: "mark" }
  | { kind: "string"; value: string }
  | { kind: "global"; module: string; name: string; offset: number }
  | { kind: "other" };

export interface PickleScanOutcome {
  findings: Finding[];
  globalReferences: PickleGlobalRef[];
  opcodeCount: number;
}

function decodeBufferArg(arg: DisassembledOp["arg"]): string | undefined {
  if (Buffer.isBuffer(arg)) return arg.toString("utf8");
  return undefined;
}

export function scanPickleBytes(buf: Buffer): PickleScanOutcome {
  const findings: Finding[] = [];
  const globalReferences: PickleGlobalRef[] = [];

  let ops: DisassembledOp[];
  try {
    ops = disassemble(buf);
  } catch (err) {
    const message = err instanceof PickleParseError ? err.message : String(err);
    findings.push({
      severity: "medium",
      code: "PICKLE_PARSE_ERROR",
      message: `Could not fully disassemble the pickle opcode stream: ${message}`,
      detail:
        "Static analysis could not verify this pickle is safe because it could not be " +
        "fully parsed. Treat this file with caution - malformed pickle streams are also " +
        "how some scanner-evasion payloads behave.",
    });
    return { findings, globalReferences, opcodeCount: 0 };
  }

  const stack: StackValue[] = [];
  const memo = new Map<number, StackValue>();
  let memoCounter = 0;

  const pop = (): StackValue => stack.pop() ?? { kind: "other" };
  const push = (v: StackValue) => stack.push(v);
  const peek = (): StackValue => stack[stack.length - 1] ?? { kind: "other" };

  function popToMark(): StackValue[] {
    const items: StackValue[] = [];
    while (stack.length > 0) {
      const v = stack.pop()!;
      if (v.kind === "mark") break;
      items.unshift(v);
    }
    return items;
  }

  function recordGlobalRef(module: string, name: string, offset: number): StackValue {
    const allowlisted = isAllowlisted(module, name);
    globalReferences.push({ module, name, offset, allowlisted });

    if (!allowlisted) {
      if (isKnownDangerous(module, name)) {
        findings.push({
          severity: "high",
          code: "PICKLE_DANGEROUS_GLOBAL_REFERENCED",
          message: `Pickle stream references "${module}.${name}", a well-known code-execution primitive that has no legitimate reason to appear in a model checkpoint.`,
          detail: `GLOBAL opcode at byte offset ${offset} resolves to ${module}.${name}.`,
          offset,
        });
      } else {
        findings.push({
          severity: "medium",
          code: "PICKLE_UNKNOWN_GLOBAL_REFERENCED",
          message: `Pickle stream references "${module}.${name}", which is not on the known-safe allowlist for model checkpoints.`,
          detail: `GLOBAL opcode at byte offset ${offset} resolves to ${module}.${name}. This may be a legitimate custom class, or it may be unsafe - manual review recommended.`,
          offset,
        });
      }
    }
    return { kind: "global", module, name, offset };
  }

  function checkInvocation(value: StackValue, offset: number, viaOpcode: string): void {
    if (value.kind !== "global") return;
    const { module, name } = value;
    if (isAllowlisted(module, name)) return;
    findings.push({
      severity: "high",
      code: "PICKLE_UNSAFE_GLOBAL_INVOKED",
      message: `Pickle stream calls "${module}.${name}(...)" via ${viaOpcode}, with attacker-controlled arguments from the file itself.`,
      detail:
        `This is the textbook pickle deserialization RCE pattern: a GLOBAL/STACK_GLOBAL ` +
        `reference to ${module}.${name} followed by ${viaOpcode} means loading this file ` +
        `(e.g. via torch.load()) executes ${module}.${name}(...) with arguments taken ` +
        `directly from the pickle stream.`,
      offset,
    });
  }

  for (const op of ops) {
    const { opcode, arg, pos } = op;
    switch (opcode.name) {
      case "MARK":
        push({ kind: "mark" });
        break;
      case "STOP":
        break;
      case "POP":
        pop();
        break;
      case "POP_MARK":
        popToMark();
        break;
      case "DUP":
        push(peek());
        break;
      case "GLOBAL": {
        const text = arg as string;
        const [module, name] = text.split("\n");
        push(recordGlobalRef(module ?? "", name ?? "", pos));
        break;
      }
      case "STACK_GLOBAL": {
        const nameVal = pop();
        const moduleVal = pop();
        if (nameVal.kind === "string" && moduleVal.kind === "string") {
          push(recordGlobalRef(moduleVal.value, nameVal.value, pos));
        } else {
          push({ kind: "other" });
        }
        break;
      }
      case "INST": {
        const text = arg as string;
        const [module, name] = text.split("\n");
        popToMark(); // constructor args, we don't need their values
        const ref = recordGlobalRef(module ?? "", name ?? "", pos);
        checkInvocation(ref, pos, "INST");
        push({ kind: "other" });
        break;
      }
      case "OBJ": {
        const items = popToMark();
        const cls = items[0];
        if (cls) checkInvocation(cls, pos, "OBJ");
        push({ kind: "other" });
        break;
      }
      case "REDUCE": {
        pop(); // args tuple
        const callable = pop();
        checkInvocation(callable, pos, "REDUCE");
        push({ kind: "other" });
        break;
      }
      case "NEWOBJ": {
        pop(); // args tuple
        const cls = pop();
        checkInvocation(cls, pos, "NEWOBJ");
        push({ kind: "other" });
        break;
      }
      case "NEWOBJ_EX": {
        pop(); // kwargs
        pop(); // args tuple
        const cls = pop();
        checkInvocation(cls, pos, "NEWOBJ_EX");
        push({ kind: "other" });
        break;
      }
      case "BUILD": {
        pop(); // state
        const obj = peek();
        checkInvocation(obj, pos, "BUILD (__setstate__/__dict__.update)");
        break;
      }
      case "STRING":
      case "BINSTRING":
      case "SHORT_BINSTRING": {
        const value =
          typeof arg === "string" ? arg : decodeBufferArg(arg) ?? "";
        push({ kind: "string", value });
        break;
      }
      case "UNICODE":
      case "BINUNICODE":
      case "SHORT_BINUNICODE":
      case "BINUNICODE8": {
        const value =
          typeof arg === "string" ? arg : decodeBufferArg(arg) ?? "";
        push({ kind: "string", value });
        break;
      }
      case "APPEND":
        pop();
        break;
      case "APPENDS":
        popToMark();
        break;
      case "ADDITEMS":
        popToMark();
        break;
      case "SETITEM":
        pop();
        pop();
        break;
      case "SETITEMS":
        popToMark();
        break;
      case "DICT":
      case "LIST":
      case "TUPLE":
      case "FROZENSET":
        popToMark();
        push({ kind: "other" });
        break;
      case "TUPLE1":
        pop();
        push({ kind: "other" });
        break;
      case "TUPLE2":
        pop();
        pop();
        push({ kind: "other" });
        break;
      case "TUPLE3":
        pop();
        pop();
        pop();
        push({ kind: "other" });
        break;
      case "EMPTY_DICT":
      case "EMPTY_LIST":
      case "EMPTY_TUPLE":
      case "EMPTY_SET":
      case "NONE":
      case "NEWTRUE":
      case "NEWFALSE":
      case "INT":
      case "BININT":
      case "BININT1":
      case "BININT2":
      case "LONG":
      case "LONG1":
      case "LONG4":
      case "FLOAT":
      case "BINFLOAT":
      case "BINBYTES":
      case "SHORT_BINBYTES":
      case "BINBYTES8":
      case "BYTEARRAY8":
      case "PERSID":
      case "BINPERSID":
        push({ kind: "other" });
        break;
      case "GET": {
        const idx = Number(arg as string);
        push(memo.get(idx) ?? { kind: "other" });
        break;
      }
      case "BINGET":
      case "LONG_BINGET": {
        const idx = Number(arg as number);
        push(memo.get(idx) ?? { kind: "other" });
        break;
      }
      case "PUT": {
        const idx = Number(arg as string);
        memo.set(idx, peek());
        break;
      }
      case "BINPUT":
      case "LONG_BINPUT": {
        const idx = Number(arg as number);
        memo.set(idx, peek());
        break;
      }
      case "MEMOIZE": {
        memo.set(memoCounter++, peek());
        break;
      }
      case "EXT1":
      case "EXT2":
      case "EXT4": {
        findings.push({
          severity: "low",
          code: "PICKLE_EXTENSION_OPCODE",
          message: `Pickle stream uses the extension registry opcode ${opcode.name}, which is unusual in model checkpoints.`,
          offset: pos,
        });
        push({ kind: "other" });
        break;
      }
      case "PROTO":
      case "FRAME":
        // no stack effect
        break;
      default:
        // Unhandled-but-recognized opcode: push a placeholder so the
        // abstract stack stays aligned for whatever comes next.
        push({ kind: "other" });
        break;
    }
  }

  return { findings, globalReferences, opcodeCount: ops.length };
}
