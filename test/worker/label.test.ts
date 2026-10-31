// Sign-in label pre-fill contract: `prefillLabel(clientName)`, exported from
// src/index.ts.
//
// The /authorize page asks the human for a connection label. When the
// provider knows the client's name we can suggest one instead of making the
// operator invent it, but the suggestion has to satisfy the label grammar the
// POST handler enforces: 1-32 characters of [a-z0-9-], starting with a letter
// or digit (LABEL_RE /^[a-z0-9][a-z0-9-]{0,31}$/).
//
// `prefillLabel` is the pure sanitiser:
//   * lowercase the client name;
//   * replace every character outside [a-z0-9-] with "-";
//   * collapse runs of "-" into one, and trim leading/trailing "-";
//   * truncate to 32 characters (then trim any hyphen stranded at the end);
//   * return "" when the result is empty OR is a RESERVED_LABEL, so the
//     human has to type one themselves.
//
// RESERVED_LABELS is ["operator"]: "operator" names grants made before
// labels existed, so it must never be suggested. "bearer" used to be
// reserved for the static token; that path is gone, so it is an ordinary
// label now.
//
// The page renders the result in the label input's value attribute (see
// auth.test.ts); the input stays editable and POST validation is unchanged.

import { describe, expect, it } from "vitest";
import { prefillLabel } from "../../src/index";

describe("prefillLabel", () => {
  it("derives a label from a client name", () => {
    expect(prefillLabel("Example Desktop")).toBe("example-desktop");
    expect(prefillLabel("Example.ai Connector")).toBe("example-ai-connector");
  });

  it("lowercases", () => {
    expect(prefillLabel("My Phone")).toBe("my-phone");
    expect(prefillLabel("WORK")).toBe("work");
  });

  it("replaces every run of disallowed characters with one hyphen", () => {
    expect(prefillLabel("a  _  b")).toBe("a-b");
    expect(prefillLabel("!!Hello??World!!")).toBe("hello-world");
    expect(prefillLabel("a.b/c\\d")).toBe("a-b-c-d");
    expect(prefillLabel("tab\tseparated")).toBe("tab-separated");
  });

  it("trims leading and trailing hyphens", () => {
    expect(prefillLabel("---")).toBe("");
    expect(prefillLabel("  Example Desktop  ")).toBe("example-desktop");
    expect(prefillLabel("!!hello!!")).toBe("hello");
  });

  it("is empty for a missing or empty name", () => {
    expect(prefillLabel(undefined)).toBe("");
    expect(prefillLabel("")).toBe("");
    expect(prefillLabel("   ")).toBe("");
    expect(prefillLabel("!!!")).toBe("");
  });

  it("returns empty for reserved labels, so the human types one", () => {
    expect(prefillLabel("operator")).toBe("");
    expect(prefillLabel("OPERATOR")).toBe("");
    expect(prefillLabel("Operator")).toBe("");
  });

  it("no longer reserves 'bearer'", () => {
    expect(prefillLabel("bearer")).toBe("bearer");
    expect(prefillLabel("Bearer")).toBe("bearer");
  });

  it("truncates to 32 characters", () => {
    expect(prefillLabel("a".repeat(40))).toBe("a".repeat(32));
    // 36 chars of valid label; the 32nd character is a hyphen and is trimmed.
    expect(prefillLabel("Example Desktop With A Very Long Client Name")).toBe("example-desktop-with-a-very-long");
  });

  it("always yields the label grammar when non-empty", () => {
    const names = ["Example Desktop", "Example.ai Connector", "9lives", "a".repeat(40), "Example Desktop With A Very Long Client Name", "operator", "---", undefined, ""];
    for (const name of names) {
      const label = prefillLabel(name);
      if (label) expect(label, String(name)).toMatch(/^[a-z0-9][a-z0-9-]{0,31}$/);
    }
  });
});
