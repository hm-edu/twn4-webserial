/**
 * DESFire file template system
 *
 * Defines a JSON-serializable template that describes the binary layout of a
 * DESFire standard/backup file.  Templates are arrays of field specifications
 * that map dot-notation paths on a data source object to fixed-length,
 * padded byte regions inside the file.
 *
 * The template itself is plain data – no functions – so it round-trips
 * through JSON.stringify / JSON.parse and can be stored alongside the
 * encrypted key-store.
 */

// ── Field specification ─────────────────────────────────────────────────

export type FieldEncoding = "utf8" | "hex" | "uint8" | "uint16le" | "uint16be" | "uint32le" | "uint32be";

export interface FieldSpec {
  /** Dot-notation path into the source object (e.g. "personalData.firstName").
   *  Omit when using a constant value. */
  path?: string;
  /** Fixed byte-length of this field in the file */
  length: number;
  /** How to encode the value into bytes */
  encoding: FieldEncoding;
  /** Pad character when encoding is "utf8" (default "\0") */
  pad?: " " | "\0";
  /** Constant value – used as-is instead of resolving a path.
   *  Accepts strings (for utf8/hex) or numbers (for uint* encodings).
   *  When both `value` and `path` are set, `value` takes precedence. */
  value?: string | number;
}

// ── File template ───────────────────────────────────────────────────────

export interface FileTemplate {
  /** Human-readable name for this template */
  name: string;
  /** Ordered list of fields that make up the file content */
  fields: FieldSpec[];
}

// ── Path resolution ─────────────────────────────────────────────────────

/**
 * Resolves a dot-notation path on an arbitrary object.
 *
 * @example getByPath({ a: { b: 42 } }, "a.b") // 42
 */
export function getByPath<T>(obj: T, path: string): unknown {
  return path.split(".").reduce((acc, key) => {
    if (acc && typeof acc === "object" && key in (acc as Record<string, unknown>)) {
      return (acc as Record<string, unknown>)[key];
    }
    return undefined;
  }, obj as unknown);
}

// ── Encoding helpers ────────────────────────────────────────────────────

/**
 * Encodes a single value according to a FieldSpec into a fixed-length
 * Uint8Array, padding with the configured pad character.
 */
export function encodeField(value: unknown, spec: FieldSpec): Uint8Array {
  const out = new Uint8Array(spec.length);

  switch (spec.encoding) {
    case "utf8": {
      const padChar = spec.pad ?? "\0";
      const fill = padChar === "\0" ? 0x00 : padChar.charCodeAt(0);
      out.fill(fill);
      const bytes = new TextEncoder().encode(String(value ?? ""));
      out.set(bytes.slice(0, spec.length));
      break;
    }

    case "hex": {
      const hex = String(value ?? "").replace(/\s+/g, "");
      for (let i = 0; i < Math.min(hex.length / 2, spec.length); i++) {
        out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
      }
      break;
    }

    case "uint8": {
      const n = Number(value ?? 0);
      out[0] = n & 0xff;
      break;
    }

    case "uint16le": {
      const n = Number(value ?? 0);
      out[0] = n & 0xff;
      out[1] = (n >> 8) & 0xff;
      break;
    }

    case "uint16be": {
      const n = Number(value ?? 0);
      out[0] = (n >> 8) & 0xff;
      out[1] = n & 0xff;
      break;
    }

    case "uint32le": {
      const n = Number(value ?? 0);
      out[0] = n & 0xff;
      out[1] = (n >> 8) & 0xff;
      out[2] = (n >> 16) & 0xff;
      out[3] = (n >> 24) & 0xff;
      break;
    }

    case "uint32be": {
      const n = Number(value ?? 0);
      out[0] = (n >> 24) & 0xff;
      out[1] = (n >> 16) & 0xff;
      out[2] = (n >> 8) & 0xff;
      out[3] = n & 0xff;
      break;
    }
  }

  return out;
}

// ── Build file content ──────────────────────────────────────────────────

/**
 * Builds the binary content of a DESFire file by resolving every field path
 * on the given source object and encoding the values according to the template.
 *
 * @param source  Any object whose shape matches the template paths
 * @param template  The file template describing the binary layout
 * @returns Uint8Array with the full file content
 */
export function buildFileContent<T>(source: T, template: FileTemplate): Uint8Array {
  const chunks = template.fields.map((field) => {
    const val = field.value !== undefined
      ? field.value
      : field.path
        ? getByPath(source, field.path)
        : undefined;
    return encodeField(val, field);
  });
  const total = chunks.reduce((sum, c) => sum + c.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

/**
 * Calculates the total byte size a template will produce.
 */
export function templateSize(template: FileTemplate): number {
  return template.fields.reduce((sum, f) => sum + f.length, 0);
}

// ── Validation ──────────────────────────────────────────────────────────

/**
 * Validates a FileTemplate and returns a list of problems (empty = valid).
 */
export function validateTemplate(template: FileTemplate): string[] {
  const errors: string[] = [];

  if (!template.name || template.name.trim().length === 0) {
    errors.push("Template name must not be empty");
  }

  if (!Array.isArray(template.fields) || template.fields.length === 0) {
    errors.push("Template must contain at least one field");
  }

  const validEncodings: FieldEncoding[] = [
    "utf8", "hex", "uint8", "uint16le", "uint16be", "uint32le", "uint32be",
  ];

  for (let i = 0; i < (template.fields?.length ?? 0); i++) {
    const f = template.fields[i];
    if (f.value === undefined && (!f.path || f.path.trim().length === 0)) {
      errors.push(`Field ${i}: must have either a path or a constant value`);
    }
    if (typeof f.length !== "number" || f.length <= 0) {
      errors.push(`Field ${i}: length must be a positive number`);
    }
    if (!validEncodings.includes(f.encoding)) {
      errors.push(`Field ${i}: encoding must be one of ${validEncodings.join(", ")}`);
    }
    if (f.pad !== undefined && f.pad !== " " && f.pad !== "\0") {
      errors.push(`Field ${i}: pad must be " " or "\\0"`);
    }
  }

  return errors;
}
