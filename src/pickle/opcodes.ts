/**
 * Real Python pickle opcode definitions, transcribed from CPython's
 * `Lib/pickle.py` (the same table `pickletools` uses to disassemble
 * pickles). Each opcode is a single byte; `argMode` describes how to read
 * the bytes that follow so the disassembler in `disassembler.ts` can walk
 * an arbitrary pickle stream without misaligning.
 */

export type ArgMode =
  | "none" // opcode takes no argument bytes
  | "textline" // argument is a newline-terminated ASCII/text string
  | "textline2" // two consecutive newline-terminated text strings (GLOBAL, INST)
  | "uint1" // 1-byte unsigned int argument
  | "uint2" // 2-byte little-endian unsigned int argument
  | "int4" // 4-byte little-endian signed int argument
  | "uint4" // 4-byte little-endian unsigned int argument
  | "uint8" // 8-byte little-endian unsigned int argument (BigInt)
  | "float8" // 8-byte big-endian IEEE754 double (BINFLOAT is big-endian!)
  | "bytes1" // 1-byte length prefix + that many raw bytes
  | "bytes4" // 4-byte length prefix + that many raw bytes
  | "bytes8" // 8-byte length prefix + that many raw bytes (BigInt length)
  | "long1"; // 1-byte length prefix + that many bytes (LONG1)

export interface OpcodeInfo {
  code: number;
  name: string;
  argMode: ArgMode;
}

function op(code: string, name: string, argMode: ArgMode): OpcodeInfo {
  return { code: code.charCodeAt(0), name, argMode };
}

function opByte(code: number, name: string, argMode: ArgMode): OpcodeInfo {
  return { code, name, argMode };
}

export const OPCODES: OpcodeInfo[] = [
  op("(", "MARK", "none"),
  op(".", "STOP", "none"),
  op("0", "POP", "none"),
  op("1", "POP_MARK", "none"),
  op("2", "DUP", "none"),
  op("F", "FLOAT", "textline"),
  op("I", "INT", "textline"),
  op("J", "BININT", "int4"),
  op("K", "BININT1", "uint1"),
  op("L", "LONG", "textline"),
  op("M", "BININT2", "uint2"),
  op("N", "NONE", "none"),
  op("P", "PERSID", "textline"),
  op("Q", "BINPERSID", "none"),
  op("R", "REDUCE", "none"),
  op("S", "STRING", "textline"),
  op("T", "BINSTRING", "bytes4"),
  op("U", "SHORT_BINSTRING", "bytes1"),
  op("V", "UNICODE", "textline"),
  op("X", "BINUNICODE", "bytes4"),
  op("a", "APPEND", "none"),
  op("b", "BUILD", "none"),
  op("c", "GLOBAL", "textline2"),
  op("d", "DICT", "none"),
  op("}", "EMPTY_DICT", "none"),
  op("e", "APPENDS", "none"),
  op("g", "GET", "textline"),
  op("h", "BINGET", "uint1"),
  op("i", "INST", "textline2"),
  op("j", "LONG_BINGET", "uint4"),
  op("l", "LIST", "none"),
  op("]", "EMPTY_LIST", "none"),
  op("o", "OBJ", "none"),
  op("p", "PUT", "textline"),
  op("q", "BINPUT", "uint1"),
  op("r", "LONG_BINPUT", "uint4"),
  op("s", "SETITEM", "none"),
  op("t", "TUPLE", "none"),
  op(")", "EMPTY_TUPLE", "none"),
  op("u", "SETITEMS", "none"),
  op("G", "BINFLOAT", "float8"),
  op("B", "BINBYTES", "bytes4"),
  op("C", "SHORT_BINBYTES", "bytes1"),

  // Protocol 2
  opByte(0x80, "PROTO", "uint1"),
  opByte(0x81, "NEWOBJ", "none"),
  opByte(0x82, "EXT1", "uint1"),
  opByte(0x83, "EXT2", "uint2"),
  opByte(0x84, "EXT4", "int4"),
  opByte(0x85, "TUPLE1", "none"),
  opByte(0x86, "TUPLE2", "none"),
  opByte(0x87, "TUPLE3", "none"),
  opByte(0x88, "NEWTRUE", "none"),
  opByte(0x89, "NEWFALSE", "none"),
  opByte(0x8a, "LONG1", "long1"),
  opByte(0x8b, "LONG4", "bytes4"),

  // Protocol 4
  opByte(0x8c, "SHORT_BINUNICODE", "bytes1"),
  opByte(0x8d, "BINUNICODE8", "bytes8"),
  opByte(0x8e, "BINBYTES8", "bytes8"),
  opByte(0x8f, "EMPTY_SET", "none"),
  opByte(0x90, "ADDITEMS", "none"),
  opByte(0x91, "FROZENSET", "none"),
  opByte(0x92, "NEWOBJ_EX", "none"),
  opByte(0x93, "STACK_GLOBAL", "none"),
  opByte(0x94, "MEMOIZE", "none"),
  opByte(0x95, "FRAME", "uint8"),

  // Protocol 5
  opByte(0x96, "BYTEARRAY8", "bytes8"),
  opByte(0x97, "NEXT_BUFFER", "none"),
  opByte(0x98, "READONLY_BUFFER", "none"),
];

export const OPCODE_BY_CODE: Map<number, OpcodeInfo> = new Map(
  OPCODES.map((o) => [o.code, o])
);
