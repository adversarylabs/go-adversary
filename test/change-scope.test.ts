import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import test from "node:test";
import { createApp } from "../src/index.ts";

const execute = promisify(execFile);

test("an unrelated edit does not surface a legacy Go finding", async () => {
  const repo = await committedRepository(goSource("old diagnostic", true));
  await writeFile(join(repo, "main.go"), goSource("new diagnostic", true));

  const output = await changedReview(repo, ["main.go"]);

  assert.equal(
    output.findings.some((finding) => finding.ruleId === "go.tls-insecure"),
    false,
  );
});

test("a finding on a changed line remains eligible", async () => {
  const repo = await committedRepository(goSource("old diagnostic", false));
  await writeFile(join(repo, "main.go"), goSource("old diagnostic", true));

  const output = await changedReview(repo, ["main.go"]);

  const finding = output.findings.find((item) => item.ruleId === "go.tls-insecure");
  assert.ok(finding);
  assert.equal(finding.evidence[0]?.location?.line, 9);
});

test("a changed match is found after an unchanged legacy match", async () => {
  const original = `${goSource("old diagnostic", true)}
func secureClient() *tls.Config {
	return &tls.Config{InsecureSkipVerify: false}
}
`;
  const updated = original.replace(
    "return &tls.Config{InsecureSkipVerify: false}",
    "return &tls.Config{InsecureSkipVerify: true}",
  );
  const repo = await committedRepository(original);
  await writeFile(join(repo, "main.go"), updated);

  const output = await changedReview(repo, ["main.go"]);

  const finding = output.findings.find((item) => item.ruleId === "go.tls-insecure");
  assert.ok(finding);
  assert.equal(finding.evidence[0]?.location?.line, 17);
});

test("an added file remains eligible in full", async () => {
  const repo = await committedRepository("package main\n");
  await writeFile(join(repo, "added.go"), goSource("added file", true));

  const output = await changedReview(repo, ["added.go"]);

  assert.equal(
    output.findings.some((finding) => finding.ruleId === "go.tls-insecure"),
    true,
  );
});

test("an all-files review remains eligible in full", async () => {
  const repo = await committedRepository(goSource("repository review", true));
  await writeFile(join(repo, "main.go"), goSource("uncommitted edit", true));

  const output = await createApp().run({
    input: {
      source: { path: repo },
      change: {
        type: "diff",
        base_ref: "HEAD",
        head_ref: "WORKTREE",
        scan_mode: "all",
        changed_files: ["main.go"],
      },
    },
  });

  assert.equal(
    output.findings.some((finding) => finding.ruleId === "go.tls-insecure"),
    true,
  );
});

async function committedRepository(source: string): Promise<string> {
  const repo = await mkdtemp(join(tmpdir(), "go-adversary-scope-"));
  await execute("git", ["init", "--quiet"], { cwd: repo });
  await execute("git", ["config", "user.email", "tests@example.com"], { cwd: repo });
  await execute("git", ["config", "user.name", "Tests"], { cwd: repo });
  await writeFile(join(repo, "main.go"), source);
  await execute("git", ["add", "main.go"], { cwd: repo });
  await execute("git", ["commit", "--quiet", "-m", "fixture"], { cwd: repo });
  return repo;
}

async function changedReview(repoPath: string, changedFiles: string[]) {
  return createApp().run({
    input: {
      source: { path: repoPath },
      change: {
        type: "diff",
        base_ref: "HEAD",
        head_ref: "WORKTREE",
        scan_mode: "changed",
        changed_files: changedFiles,
      },
    },
  });
}

function goSource(diagnostic: string, insecure: boolean): string {
  return `package main

import (
	"crypto/tls"
	"fmt"
)

func client() *tls.Config {
	return &tls.Config{InsecureSkipVerify: ${insecure}}
}

func main() {
	fmt.Println(${JSON.stringify(diagnostic)})
}
`;
}
