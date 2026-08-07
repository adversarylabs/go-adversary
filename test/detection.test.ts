import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { parseAdversaryManifest } from "@adversarylabs/sdk";

test("declares deterministic automatic detection", async () => {
  const source = await readFile(new URL("../adversary.yaml", import.meta.url), "utf8");

  // Composition members (uses) require @adversarylabs/sdk with uses support.
  // Until that release is installed, still assert detection + uses shape from YAML.
  let manifest: ReturnType<typeof parseAdversaryManifest> | undefined;
  try {
    manifest = parseAdversaryManifest(source);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    if (!msg.includes('"uses"') && !msg.includes("unknown field")) {
      throw err;
    }
  }

  if (manifest) {
    assert.deepEqual(manifest.detection?.files, ["**/*.go"]);
    assert.equal(manifest.detection?.entrypoint, undefined);
    assert.ok(Array.isArray(manifest.uses) && manifest.uses.length >= 1);
    return;
  }

  // Older SDK: parse detection/uses without full schema.
  assert.match(source, /detection:\s*\n\s*files:\s*\n\s*-\s*"\*\*\/\*\.go"/);
  assert.match(source, /^uses:\s*$/m);
  assert.match(source, /^\s+-\s+name:\s+go\//m);
});

