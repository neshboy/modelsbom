/**
 * Allowlist of module/qualname pairs that legitimately show up in
 * PyTorch checkpoint pickles (tensor storage rebuilding, OrderedDict state
 * dicts, numpy array reconstruction, etc). Anything referenced by a GLOBAL
 * / STACK_GLOBAL / INST opcode that is NOT covered by this allowlist, and
 * which is then actually invoked (REDUCE / NEWOBJ / NEWOBJ_EX / OBJ /
 * INST), is exactly the pattern real PyTorch-pickle RCE payloads use
 * (e.g. GLOBAL "os" "system" + REDUCE), so it is flagged as HIGH severity.
 *
 * This mirrors the approach used by real tools in this space (fickling,
 * ModelScan): a static allowlist of "known safe" callables, everything
 * else referenced-and-invoked is treated as suspicious. See README.md
 * Limitations for the honest tradeoff this implies.
 */

export interface AllowlistRule {
  /** Exact "module.qualname" match, or a module prefix ending in "*". */
  pattern: string;
}

export const ALLOWLIST: string[] = [
  // torch internals used to rebuild tensors/parameters/storages from a
  // checkpoint - any function/class under the torch namespace.
  "torch.*",
  "torch._utils.*",
  "torch._utils._rebuild_tensor",
  "torch._utils._rebuild_tensor_v2",
  "torch._utils._rebuild_parameter",
  "torch._utils._rebuild_device_tensor_from_numpy",
  "torch.storage.*",
  "torch.serialization.*",

  // collections.OrderedDict is the standard container for state_dict()
  "collections.OrderedDict",
  "collections.defaultdict",

  // numpy array reconstruction, common when checkpoints embed numpy data
  "numpy.*",
  "numpy.core.multiarray._reconstruct",
  "numpy.core.multiarray.scalar",
  "numpy.ndarray",
  "numpy.dtype",

  // builtin containers pickle sometimes routes through explicitly
  "builtins.set",
  "builtins.frozenset",
  "builtins.bytearray",
  "builtins.dict",
  "builtins.list",
  "builtins.tuple",
  "builtins.complex",
  "__builtin__.set", // Python 2 name for builtins
  "__builtin__.frozenset",

  // used internally by pickle itself for some byte/str encodings
  "_codecs.encode",
];

/**
 * Well-known modules that have no legitimate reason to appear in a model
 * checkpoint and are the textbook building blocks of pickle RCE payloads.
 * A reference to one of these is flagged as HIGH severity even before we
 * see whether it gets invoked.
 */
export const DANGEROUS_MODULES = new Set([
  "os",
  "nt",
  "posix",
  "subprocess",
  "sys",
  "socket",
  "shutil",
  "builtins", // eval/exec/compile/__import__ live here (but see ALLOWLIST for safe builtins.*)
  "__builtin__",
  "importlib",
  "ctypes",
  "code",
  "pty",
  "platform",
  "webbrowser",
  "runpy",
]);

const DANGEROUS_BUILTIN_NAMES = new Set([
  "eval",
  "exec",
  "compile",
  "__import__",
  "getattr",
  "globals",
  "vars",
  "open",
]);

function normalize(moduleName: string, qualName: string): string {
  return `${moduleName}.${qualName}`;
}

export function isAllowlisted(moduleName: string, qualName: string): boolean {
  const full = normalize(moduleName, qualName);
  for (const pattern of ALLOWLIST) {
    if (pattern.endsWith(".*")) {
      const prefix = pattern.slice(0, -1); // keep trailing dot
      if (full.startsWith(prefix)) return true;
      if (full === pattern.slice(0, -2)) return true; // exact module match, e.g. "torch"
    } else if (pattern === full) {
      return true;
    }
  }
  return false;
}

export function isKnownDangerous(moduleName: string, qualName: string): boolean {
  if (DANGEROUS_MODULES.has(moduleName)) {
    if (moduleName === "builtins" || moduleName === "__builtin__") {
      return DANGEROUS_BUILTIN_NAMES.has(qualName);
    }
    return true;
  }
  return false;
}
