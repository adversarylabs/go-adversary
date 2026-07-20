import { type Confidence, type Severity } from "@adversarylabs/sdk";

export interface MatchExpression { pattern: string; flags: string }
interface ContentMatch { kind: "content"; files: string[]; pattern: MatchExpression; requires: MatchExpression[] }
interface MissingContentMatch { kind: "missing-content"; files: string[]; trigger: MatchExpression; required: MatchExpression }
interface MissingFileMatch { kind: "missing-file"; triggerFiles: string[]; requiredFiles: string[] }
export interface RuleSpec {
  id: string; title: string; summary: string; category: string; severity: Severity; confidence: Confidence;
  whyItMatters: string; impact: string; recommendation: string; complexity: "trivial" | "small" | "medium" | "large"; tags: string[];
  match: ContentMatch | MissingContentMatch | MissingFileMatch;
}
export interface AdversarySpec { id: string; displayName: string; description: string; files: string[]; rules: RuleSpec[] }

export const spec = {
  "id": "go",
  "displayName": "Go",
  "description": "Reviews Go for TLS bypasses, shell commands, and unsafe filesystem permissions.",
  "files": [
    "**/*.go"
  ],
  "rules": [
    {
      "id": "go.tls-insecure",
      "title": "Go TLS client skips certificate verification",
      "summary": "Go TLS client skips certificate verification",
      "category": "security",
      "severity": "high",
      "confidence": "high",
      "whyItMatters": "Go TLS client skips certificate verification weakens an important security boundary.",
      "impact": "The repository may behave insecurely, unreliably, or differently from the reviewed configuration.",
      "recommendation": "Keep certificate verification enabled.",
      "complexity": "small",
      "tags": [
        "security",
        "tls-insecure"
      ],
      "match": {
        "kind": "content",
        "files": [
          "**/*.go"
        ],
        "pattern": {
          "pattern": "InsecureSkipVerify\\s*:\\s*true",
          "flags": "i"
        },
        "requires": []
      }
    },
    {
      "id": "go.shell-command",
      "title": "Go executes through a shell",
      "summary": "Go executes through a shell",
      "category": "security",
      "severity": "critical",
      "confidence": "high",
      "whyItMatters": "Go executes through a shell weakens an important security boundary.",
      "impact": "The repository may behave insecurely, unreliably, or differently from the reviewed configuration.",
      "recommendation": "Invoke the target binary directly.",
      "complexity": "small",
      "tags": [
        "security",
        "shell-command"
      ],
      "match": {
        "kind": "content",
        "files": [
          "**/*.go"
        ],
        "pattern": {
          "pattern": "exec\\.Command\\(\\s*[\"'](?:sh|bash)[\"']\\s*,\\s*[\"']-c",
          "flags": "i"
        },
        "requires": []
      }
    },
    {
      "id": "go.world-writable",
      "title": "Go creates a world-writable path",
      "summary": "Go creates a world-writable path",
      "category": "security",
      "severity": "medium",
      "confidence": "high",
      "whyItMatters": "Go creates a world-writable path weakens an important security boundary.",
      "impact": "The repository may behave insecurely, unreliably, or differently from the reviewed configuration.",
      "recommendation": "Use owner-scoped filesystem permissions.",
      "complexity": "small",
      "tags": [
        "security",
        "world-writable"
      ],
      "match": {
        "kind": "content",
        "files": [
          "**/*.go"
        ],
        "pattern": {
          "pattern": "(?:os\\.(?:Chmod|Mkdir|MkdirAll|OpenFile)|WriteFile)\\([^\\n]*(?:0?777|0?666)\\b",
          "flags": "i"
        },
        "requires": []
      }
    }
  ]
} as const satisfies AdversarySpec;
