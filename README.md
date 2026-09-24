# ModelSBOM

**A supply-chain security scanner for downloaded AI model files.** ModelSBOM statically
inspects a model file *before* you load it - a "Software Bill of Materials" style audit
for model weights - and tells you exactly what it found, in a real structured report.

## Why this exists

Pulling a model file from Hugging Face, a random GitHub release, or an Ollama/LM Studio
registry is, from a security perspective, downloading and running a binary from a
stranger. The risk is not hypothetical or format-agnostic:

- **PyTorch `.pt` / `.pth` / `.ckpt` files are Python `pickle` archives.** `pickle.load()`
  (which is exactly what `torch.load()` calls under the hood, by default) can be made to
  execute arbitrary code, because the pickle bytecode has opcodes (`GLOBAL`/`STACK_GLOBAL`
  to reference any importable name, `REDUCE`/`NEWOBJ`/`INST`/`OBJ` to call it) that were
  designed to reconstruct arbitrary Python objects - including calling `os.system(...)`,
  `subprocess.call(...)`, or anything else, with arguments taken straight from the file.
  This is a real, well-documented class of vulnerability, and it's exactly what tools like
  [`fickling`](https://github.com/trailofbits/fickling) and
  [`ModelScan`](https://github.com/protectai/modelscan) exist to catch.
- **GGUF and safetensors are deliberately data-only formats** (metadata + tensor bytes,
  no bytecode), but their parsers are real hand-rolled binary parsers, and hand-rolled
  binary parsers for attacker-supplied files have a track record of buffer-overflow /
  out-of-bounds read bugs. A malformed or maliciously-crafted header is worth flagging
  even though the format itself has no code-execution primitive.

ModelSBOM's job is to open the file, understand its real container format, and tell you
which of these situations you're in before you hand the file to `torch.load()` or a
model runtime.

## What it actually does (no fakery)

- **PyTorch pickle scanning is a real pickle opcode disassembler.** `.pt`/`.pth`/`.ckpt`
  files saved with modern PyTorch are genuinely ZIP archives; ModelSBOM parses the ZIP
  End-Of-Central-Directory + Central Directory records itself (`src/zip.ts`, no
  extension-sniffing, no shortcuts), extracts `data.pkl`, and walks its actual opcode
  stream byte-by-byte (`src/pickle/disassembler.ts`, modeled on Python's own
  `pickletools.genops`). It simulates just enough of the pickle VM's stack to know, for
  every `REDUCE` / `NEWOBJ` / `NEWOBJ_EX` / `OBJ` / `INST` / `BUILD` opcode, *what
  callable is being invoked* - and flags it if that callable isn't on a small allowlist
  of known-safe torch/numpy/stdlib rebuild helpers (`src/pickle/allowlist.ts`).
- **safetensors gets real structural/integrity validation**, not code-execution
  detection - because safetensors has no code-execution surface. ModelSBOM parses the
  real 8-byte little-endian header length + JSON header + raw tensor bytes, then checks
  that every tensor's declared byte range fits inside the file, matches its declared
  shape/dtype, and doesn't overlap any other tensor's range.
- **GGUF gets a real header/metadata parser**: magic bytes, version, tensor count,
  metadata key-value pairs (including nested arrays), tensor descriptors - all decoded
  according to the documented GGUF layout, reporting whatever metadata (architecture,
  quantization, etc.) is embedded in the file, and flagging truncation/corruption.

## Install / quick start

```bash
git clone <this repo>
cd modelsbom
npm install
npm run build

# scan a single file
node dist/cli.js scan ./some_checkpoint.pt

# scan a whole directory (recursively) of downloaded models
node dist/cli.js scan ./models/

# machine-readable output
node dist/cli.js scan ./models/ --json
```

Once built, `dist/cli.js` is also wired up as the `modelsbom` bin (see `package.json`),
so `npm link` (or installing from a registry, if published) gives you a plain
`modelsbom scan <path>` command.

Supported file extensions: `.pt` `.pth` `.ckpt` `.bin` (PyTorch pickle) ·
`.safetensors` · `.gguf`. Files with other/no extensions are still inspected via
magic-byte sniffing (ZIP signature, `GGUF` magic, pickle `PROTO` opcode) when scanned
directly.

**Exit codes:** `0` clean · `1` at least one **high-severity pickle finding** (likely
arbitrary code execution) · `2` at least one structurally invalid/corrupted file (no
high-severity pickle finding). This makes `modelsbom scan` usable as a CI gate.

## Example report output

Given a directory containing a malicious PyTorch checkpoint (`GLOBAL os system` +
`REDUCE` - the textbook payload), a normal checkpoint, a valid `safetensors` file, and a
`safetensors` file with a corrupted tensor offset:

```
ModelSBOM v0.1.0 - scan report (2026-09-24T08:32:08.711Z)
========================================================================

[DANGEROUS] evil_checkpoint.pt (387 bytes)
  format: pytorch-pickle (archive/data.pkl)
  opcodes scanned: 6
  global references (1):
    - os.system  [offset 2]  (NOT ALLOWLISTED)
  findings (2):
    [HIGH] PICKLE_DANGEROUS_GLOBAL_REFERENCED: Pickle stream references "os.system", a
      well-known code-execution primitive that has no legitimate reason to appear in a
      model checkpoint.
    [HIGH] PICKLE_UNSAFE_GLOBAL_INVOKED: Pickle stream calls "os.system(...)" via REDUCE,
      with attacker-controlled arguments from the file itself.

[CLEAN] normal_checkpoint.pth (376 bytes)
  format: pytorch-pickle (archive/data.pkl)
  opcodes scanned: 5
  global references (1):
    - collections.OrderedDict  [offset 2]  (allowlisted)
  findings: none

[VALID] model.safetensors (129 bytes)
  format: safetensors (structural/integrity check only - no code execution surface)
  header length: 105 bytes
  tensors: 1
    - weight: dtype=F32 shape=[2,2] offsets=[0, 16)
  metadata: {"format":"modelsbom-test"}
  findings: none

[INVALID] corrupt.safetensors (86 bytes)
  format: safetensors (structural/integrity check only - no code execution surface)
  header length: 62 bytes
  tensors: 1
    - weight: dtype=F32 shape=[2,2] offsets=[0, 32)
  findings (1):
    [HIGH] SAFETENSORS_OFFSET_OVERFLOWS_FILE: Tensor "weight" declares byte range
      [0, 32) but the data section is only 16 bytes - this tensor's data would read
      past the end of the file.

------------------------------------------------------------------------
Summary: 4 file(s) scanned - 1 dangerous, 0 suspicious, 1 invalid, 2 clean.
```

`--json` produces the same information as structured JSON (see `src/types.ts` for the
full report shape) for CI pipelines or other tooling.

## Testing

Automated tests (`npm test`, via [vitest](https://vitest.dev)) use fixtures that are
generated byte-for-byte in `test/fixtures.ts` - no fake/pre-recorded sample files:

- A hand-encoded pickle opcode stream implementing the canonical
  `GLOBAL "os" "system"` + push-args-tuple + `REDUCE` payload (the same shape real
  pickle RCE payloads use), confirmed to be flagged `DANGEROUS`/high-severity - and a
  clean pickle referencing only `collections.OrderedDict` (as real PyTorch state dicts
  do), confirmed to be **not** flagged.
- A real, minimal, valid `safetensors` file built with a correct 8-byte header length +
  JSON header + one tensor's raw bytes, plus a deliberately corrupted variant with an
  inconsistent offset (overflowing the file) and another with two overlapping tensor
  ranges - both confirmed caught.
- A real, minimal, valid `GGUF` file (correct magic/version/metadata-kv), plus a
  truncated variant - confirmed caught without crashing the parser.
- A hand-built ZIP archive (via a from-scratch ZIP writer in `src/zip.ts`) wrapping the
  pickle fixtures above, to test the actual `.pt`-style container path end-to-end,
  including a DEFLATE-compressed variant.

## Limitations (read this before trusting it blindly)

- **This is static analysis, not a sandbox.** ModelSBOM never executes, unpickles, or
  loads the file being scanned - it only disassembles bytes according to the documented
  format spec. It cannot catch anything that requires actually running the code to
  observe (e.g. a payload that decides what to do based on runtime environment checks).
- **The pickle allowlist is a heuristic, not a proof.** A sufficiently obfuscated or
  novel payload could reference a callable that looks benign but has dangerous
  side effects in some library version (false negative), and conversely a legitimate but
  unusual custom class not on the allowlist will be flagged even though it's harmless
  (false positive). Treat `SUSPICIOUS`/`MEDIUM` findings as "needs a human to look," not
  as a definitive verdict either way.
- **GGUF/safetensors checks are integrity checks, not malware scans.** These formats
  are safe by design (no bytecode, no code-execution opcodes); ModelSBOM's job there is
  to catch structural corruption/inconsistency (which could itself be a sign of parser
  exploitation attempts against the *loading* library, or just plain data corruption),
  not to detect "malicious data."
- **No zip64, no encrypted ZIPs, no multi-disk archives.** The ZIP reader intentionally
  covers exactly what `torch.save()` produces (STORED/DEFLATE, single archive) - not
  general-purpose ZIP handling.
- **MVP scope.** No package/dependency-manifest cross-referencing, no network calls, no
  signature/provenance verification (e.g. Sigstore) - this tool answers "what could this
  file *do* if I load it," nothing more.

## License

MIT - see [LICENSE](./LICENSE).
