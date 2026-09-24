/**
 * Minimal, real ZIP reader/writer.
 *
 * PyTorch's `torch.save()` format (the modern default, used for .pt/.pth/.ckpt
 * files) is literally a ZIP archive: it contains an entry named
 * `<archive>/data.pkl` (the pickled object graph) plus a set of raw tensor
 * storage blobs under `<archive>/data/*`. To inspect the pickle stream we
 * must first walk the ZIP End Of Central Directory + Central Directory
 * records and pull out the compressed/stored bytes for `data.pkl`.
 *
 * This only implements what is needed to read (and, for test fixtures,
 * write) such archives: compression methods STORED (0) and DEFLATE (8).
 * It is not a general purpose ZIP library (no zip64, no encryption, no
 * multi-disk support) - real archives that need those are out of scope for
 * an MVP model-file scanner.
 */
import * as zlib from "node:zlib";

export interface ZipEntry {
  name: string;
  compressionMethod: number;
  compressedSize: number;
  uncompressedSize: number;
  localHeaderOffset: number;
  crc32: number;
}

const EOCD_SIGNATURE = 0x06054b50;
const CENTRAL_DIR_SIGNATURE = 0x02014b50;
const LOCAL_HEADER_SIGNATURE = 0x04034b50;

/** Search backwards for the End Of Central Directory record. */
function findEndOfCentralDirectory(buf: Buffer): number {
  // EOCD is at least 22 bytes and can be followed by a variable-length
  // comment (max 65535 bytes), so scan backwards from the end.
  const maxCommentLength = 65535;
  const minOffset = Math.max(0, buf.length - 22 - maxCommentLength);
  for (let i = buf.length - 22; i >= minOffset; i--) {
    if (buf.readUInt32LE(i) === EOCD_SIGNATURE) {
      return i;
    }
  }
  throw new Error("Not a valid ZIP archive: End Of Central Directory record not found");
}

export function listZipEntries(buf: Buffer): ZipEntry[] {
  const eocdOffset = findEndOfCentralDirectory(buf);
  const totalEntries = buf.readUInt16LE(eocdOffset + 10);
  const centralDirOffset = buf.readUInt32LE(eocdOffset + 16);

  const entries: ZipEntry[] = [];
  let pos = centralDirOffset;
  for (let i = 0; i < totalEntries; i++) {
    if (buf.readUInt32LE(pos) !== CENTRAL_DIR_SIGNATURE) {
      throw new Error(
        `Not a valid ZIP archive: expected central directory signature at offset ${pos}`
      );
    }
    const compressionMethod = buf.readUInt16LE(pos + 10);
    const crc32 = buf.readUInt32LE(pos + 16);
    const compressedSize = buf.readUInt32LE(pos + 20);
    const uncompressedSize = buf.readUInt32LE(pos + 24);
    const nameLength = buf.readUInt16LE(pos + 28);
    const extraLength = buf.readUInt16LE(pos + 30);
    const commentLength = buf.readUInt16LE(pos + 32);
    const localHeaderOffset = buf.readUInt32LE(pos + 42);
    const name = buf.toString("utf8", pos + 46, pos + 46 + nameLength);

    entries.push({
      name,
      compressionMethod,
      compressedSize,
      uncompressedSize,
      localHeaderOffset,
      crc32,
    });

    pos += 46 + nameLength + extraLength + commentLength;
  }
  return entries;
}

/** Extract and decompress a single entry's data, given its Central Directory record. */
export function extractZipEntry(buf: Buffer, entry: ZipEntry): Buffer {
  const pos = entry.localHeaderOffset;
  if (buf.readUInt32LE(pos) !== LOCAL_HEADER_SIGNATURE) {
    throw new Error(
      `Not a valid ZIP archive: expected local file header signature at offset ${pos}`
    );
  }
  const nameLength = buf.readUInt16LE(pos + 26);
  const extraLength = buf.readUInt16LE(pos + 28);
  const dataStart = pos + 30 + nameLength + extraLength;
  const compressed = buf.subarray(dataStart, dataStart + entry.compressedSize);

  switch (entry.compressionMethod) {
    case 0: // stored (no compression) - this is what torch.save() uses
      return Buffer.from(compressed);
    case 8: // deflate
      return zlib.inflateRawSync(compressed);
    default:
      throw new Error(
        `Unsupported ZIP compression method ${entry.compressionMethod} for entry "${entry.name}"`
      );
  }
}

export function readZipEntryByName(buf: Buffer, name: string): Buffer | undefined {
  const entries = listZipEntries(buf);
  const entry = entries.find((e) => e.name === name || e.name.endsWith("/" + name));
  if (!entry) return undefined;
  return extractZipEntry(buf, entry);
}

export function isZip(buf: Buffer): boolean {
  return buf.length >= 4 && buf.readUInt32LE(0) === LOCAL_HEADER_SIGNATURE;
}

// ---------------------------------------------------------------------------
// Minimal ZIP writer - used only to build real test fixtures (a hand-built
// .pt-style archive containing a data.pkl entry). Supports STORED and
// DEFLATE so tests can exercise both code paths in the reader above.
// ---------------------------------------------------------------------------

export interface ZipWriteEntry {
  name: string;
  data: Buffer;
  compress?: boolean;
}

function crc32(buf: Buffer): number {
  let table = crc32Table;
  let crc = 0xffffffff;
  for (let i = 0; i < buf.length; i++) {
    crc = table[(crc ^ buf[i]) & 0xff] ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

const crc32Table = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) {
      c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    }
    table[n] = c >>> 0;
  }
  return table;
})();

export function buildZip(entries: ZipWriteEntry[]): Buffer {
  const localParts: Buffer[] = [];
  const centralParts: Buffer[] = [];
  let offset = 0;

  for (const entry of entries) {
    const nameBuf = Buffer.from(entry.name, "utf8");
    const useDeflate = entry.compress === true;
    const uncompressedData = entry.data;
    const compressedData = useDeflate
      ? zlib.deflateRawSync(uncompressedData)
      : uncompressedData;
    const method = useDeflate ? 8 : 0;
    const crc = crc32(uncompressedData);

    const localHeader = Buffer.alloc(30);
    localHeader.writeUInt32LE(LOCAL_HEADER_SIGNATURE, 0);
    localHeader.writeUInt16LE(20, 4); // version needed to extract
    localHeader.writeUInt16LE(0, 6); // flags
    localHeader.writeUInt16LE(method, 8);
    localHeader.writeUInt16LE(0, 10); // mod time
    localHeader.writeUInt16LE(0, 12); // mod date
    localHeader.writeUInt32LE(crc, 14);
    localHeader.writeUInt32LE(compressedData.length, 18);
    localHeader.writeUInt32LE(uncompressedData.length, 22);
    localHeader.writeUInt16LE(nameBuf.length, 26);
    localHeader.writeUInt16LE(0, 28); // extra length

    const localHeaderOffset = offset;
    localParts.push(localHeader, nameBuf, compressedData);
    offset += localHeader.length + nameBuf.length + compressedData.length;

    const centralHeader = Buffer.alloc(46);
    centralHeader.writeUInt32LE(CENTRAL_DIR_SIGNATURE, 0);
    centralHeader.writeUInt16LE(20, 4); // version made by
    centralHeader.writeUInt16LE(20, 6); // version needed
    centralHeader.writeUInt16LE(0, 8); // flags
    centralHeader.writeUInt16LE(method, 10);
    centralHeader.writeUInt16LE(0, 12); // mod time
    centralHeader.writeUInt16LE(0, 14); // mod date
    centralHeader.writeUInt32LE(crc, 16);
    centralHeader.writeUInt32LE(compressedData.length, 20);
    centralHeader.writeUInt32LE(uncompressedData.length, 24);
    centralHeader.writeUInt16LE(nameBuf.length, 28);
    centralHeader.writeUInt16LE(0, 30); // extra length
    centralHeader.writeUInt16LE(0, 32); // comment length
    centralHeader.writeUInt16LE(0, 34); // disk number start
    centralHeader.writeUInt16LE(0, 36); // internal attrs
    centralHeader.writeUInt32LE(0, 38); // external attrs
    centralHeader.writeUInt32LE(localHeaderOffset, 42);

    centralParts.push(centralHeader, nameBuf);
  }

  const localSection = Buffer.concat(localParts);
  const centralSection = Buffer.concat(centralParts);

  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(EOCD_SIGNATURE, 0);
  eocd.writeUInt16LE(0, 4); // disk number
  eocd.writeUInt16LE(0, 6); // disk with central dir
  eocd.writeUInt16LE(entries.length, 8); // entries on this disk
  eocd.writeUInt16LE(entries.length, 10); // total entries
  eocd.writeUInt32LE(centralSection.length, 12); // central dir size
  eocd.writeUInt32LE(localSection.length, 16); // central dir offset
  eocd.writeUInt16LE(0, 20); // comment length

  return Buffer.concat([localSection, centralSection, eocd]);
}
