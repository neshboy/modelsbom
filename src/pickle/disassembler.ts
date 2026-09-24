/**
 * A real pickle disassembler: walks a raw pickle opcode stream one opcode
 * at a time (equivalent in spirit to Python's `pickletools.genops`), so
 * every byte in the stream is accounted for and nothing gets skipped or
 * misaligned. This is the foundation the scanner builds detections on top
 * of - it does not itself decide what's dangerous, it just accurately
 * disassembles the stream.
 */
import { OPCODE_BY_CODE, OpcodeInfo } from "./opcodes";

export interface DisassembledOp {
  pos: number; // byte offset of the opcode within the stream
  opcode: OpcodeInfo;
  /** Decoded argument, shape depends on argMode. */
  arg: string | number | bigint | Buffer | undefined;
  /** byte offset right after this opcode + its argument */
  nextPos: number;
}

export class PickleParseError extends Error {}

function readTextLine(buf: Buffer, pos: number): { value: string; next: number } {
  const nl = buf.indexOf(0x0a, pos);
  if (nl === -1) {
    throw new PickleParseError(`Unterminated text argument at offset ${pos}`);
  }
  return { value: buf.toString("latin1", pos, nl), next: nl + 1 };
}

/**
 * Disassemble a pickle byte stream into a flat list of opcodes with their
 * decoded arguments. Throws PickleParseError on structurally invalid input
 * (truncated length-prefixed fields, unknown opcodes, etc) rather than
 * reading out of bounds.
 */
export function disassemble(buf: Buffer): DisassembledOp[] {
  const ops: DisassembledOp[] = [];
  let pos = 0;

  while (pos < buf.length) {
    const code = buf[pos];
    const opcode = OPCODE_BY_CODE.get(code);
    if (!opcode) {
      throw new PickleParseError(
        `Unknown pickle opcode 0x${code.toString(16).padStart(2, "0")} at offset ${pos}`
      );
    }
    const argStart = pos + 1;
    let arg: DisassembledOp["arg"];
    let next: number;

    switch (opcode.argMode) {
      case "none":
        arg = undefined;
        next = argStart;
        break;
      case "textline": {
        const r = readTextLine(buf, argStart);
        arg = r.value;
        next = r.next;
        break;
      }
      case "textline2": {
        const r1 = readTextLine(buf, argStart);
        const r2 = readTextLine(buf, r1.next);
        arg = `${r1.value}\n${r2.value}`;
        next = r2.next;
        break;
      }
      case "uint1":
        assertAvailable(buf, argStart, 1, opcode, pos);
        arg = buf.readUInt8(argStart);
        next = argStart + 1;
        break;
      case "uint2":
        assertAvailable(buf, argStart, 2, opcode, pos);
        arg = buf.readUInt16LE(argStart);
        next = argStart + 2;
        break;
      case "int4":
        assertAvailable(buf, argStart, 4, opcode, pos);
        arg = buf.readInt32LE(argStart);
        next = argStart + 4;
        break;
      case "uint4":
        assertAvailable(buf, argStart, 4, opcode, pos);
        arg = buf.readUInt32LE(argStart);
        next = argStart + 4;
        break;
      case "uint8":
        assertAvailable(buf, argStart, 8, opcode, pos);
        arg = buf.readBigUInt64LE(argStart);
        next = argStart + 8;
        break;
      case "float8":
        assertAvailable(buf, argStart, 8, opcode, pos);
        arg = buf.readDoubleBE(argStart); // BINFLOAT is big-endian per spec
        next = argStart + 8;
        break;
      case "bytes1": {
        assertAvailable(buf, argStart, 1, opcode, pos);
        const len = buf.readUInt8(argStart);
        const dataStart = argStart + 1;
        assertAvailable(buf, dataStart, len, opcode, pos);
        arg = buf.subarray(dataStart, dataStart + len);
        next = dataStart + len;
        break;
      }
      case "bytes4": {
        assertAvailable(buf, argStart, 4, opcode, pos);
        const len = buf.readUInt32LE(argStart);
        const dataStart = argStart + 4;
        assertAvailable(buf, dataStart, len, opcode, pos);
        arg = buf.subarray(dataStart, dataStart + len);
        next = dataStart + len;
        break;
      }
      case "bytes8": {
        assertAvailable(buf, argStart, 8, opcode, pos);
        const lenBig = buf.readBigUInt64LE(argStart);
        if (lenBig > BigInt(Number.MAX_SAFE_INTEGER)) {
          throw new PickleParseError(`Absurd length argument at offset ${pos}`);
        }
        const len = Number(lenBig);
        const dataStart = argStart + 8;
        assertAvailable(buf, dataStart, len, opcode, pos);
        arg = buf.subarray(dataStart, dataStart + len);
        next = dataStart + len;
        break;
      }
      case "long1": {
        assertAvailable(buf, argStart, 1, opcode, pos);
        const len = buf.readUInt8(argStart);
        const dataStart = argStart + 1;
        assertAvailable(buf, dataStart, len, opcode, pos);
        arg = buf.subarray(dataStart, dataStart + len);
        next = dataStart + len;
        break;
      }
      default:
        throw new PickleParseError(`Unhandled arg mode for opcode ${opcode.name}`);
    }

    ops.push({ pos, opcode, arg, nextPos: next });
    pos = next;

    if (opcode.name === "STOP") {
      break;
    }
  }

  return ops;
}

function assertAvailable(
  buf: Buffer,
  start: number,
  length: number,
  opcode: OpcodeInfo,
  opPos: number
): void {
  if (start + length > buf.length) {
    throw new PickleParseError(
      `Truncated pickle stream: opcode ${opcode.name} at offset ${opPos} needs ${length} more byte(s) than are available`
    );
  }
}
