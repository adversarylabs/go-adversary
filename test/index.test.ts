import assert from "node:assert/strict";
import test from "node:test";
import { createAdversaryRunEnvelope } from "@adversarylabs/sdk";
import { createApp } from "../src/index.ts";

const fixture = (name: string) => new URL(`../fixtures/${name}`, import.meta.url).pathname;
const review = (name: string, raw = false) => createApp().run({ input: { source: { path: fixture(name) } }, includeRawObservations: raw });
const ruleCases = [
  { key: "shell-command", id: "go.shell-command" },
  { key: "tls-insecure", id: "go.tls-insecure" },
  { key: "world-writable", id: "go.world-writable" },
];

test("every initial rule has focused vulnerable and clean coverage", async () => {
  for (const rule of ruleCases) {
    const vulnerable = await review(`rules/${rule.key}/vulnerable`, true);
    assert.equal(vulnerable.findings.some((finding) => finding.ruleId === rule.id), true, `${rule.id} did not detect its vulnerable fixture`);
    assert.equal(vulnerable.rawObservations?.every((item) => item.location?.file !== undefined), true);
    const clean = await review(`rules/${rule.key}/clean`);
    assert.equal(clean.findings.some((finding) => finding.ruleId === rule.id), false, `${rule.id} flagged its clean fixture`);
  }
});

test("detects ModePerm directory creation without flagging masks or tests", async () => {
  const vulnerable = await review("rules/world-writable-modeperm/vulnerable", true);
  const finding = vulnerable.findings.find((item) => item.ruleId === "go.world-writable");
  assert.ok(finding);
  assert.match(finding.whyItMatters ?? "", /requests overly broad directory permissions/i);
  assert.match(finding.whyItMatters ?? "", /umask/i);
  const observedPaths = vulnerable.rawObservations
    ?.filter((item) => item.ruleId === "go.world-writable")
    .map((item) => item.location?.file);
  assert.deepEqual(observedPaths, [
    "internal/direct.go",
    "internal/fs.go",
    "internal/wrapped.go",
  ]);

  const clean = await review("rules/world-writable-modeperm/clean");
  assert.equal(
    clean.findings.some((finding) => finding.ruleId === "go.world-writable"),
    false,
  );
});

test("accepts a repository without applicable configuration", async () => {
  const output = await review("clean");
  assert.deepEqual(output.findings, []);
  assert.equal(output.assessment?.risk, "none");
  assert.equal(output.opinion?.ship, true);
});

test("output ordering and protocol envelope are deterministic", async () => {
  const first = await review(`rules/${ruleCases[0]?.key}/vulnerable`, true);
  const second = await review(`rules/${ruleCases[0]?.key}/vulnerable`, true);
  assert.deepEqual(second, first);
  const envelope = JSON.parse(JSON.stringify(createAdversaryRunEnvelope(first)));
  assert.equal(envelope.protocolVersion, 1);
  assert.equal(envelope.result.adversary.name, "lang/go");
});
