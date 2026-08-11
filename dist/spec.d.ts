import { type Confidence, type Severity } from "@adversarylabs/sdk";
export interface MatchExpression {
    pattern: string;
    flags: string;
}
interface ContentMatch {
    kind: "content";
    files: string[];
    excludeFiles?: string[];
    pattern: MatchExpression;
    requires: MatchExpression[];
}
interface MissingContentMatch {
    kind: "missing-content";
    files: string[];
    trigger: MatchExpression;
    required: MatchExpression;
}
interface MissingFileMatch {
    kind: "missing-file";
    triggerFiles: string[];
    requiredFiles: string[];
}
export interface RuleSpec {
    id: string;
    title: string;
    summary: string;
    category: string;
    severity: Severity;
    confidence: Confidence;
    whyItMatters: string;
    impact: string;
    recommendation: string;
    complexity: "trivial" | "small" | "medium" | "large";
    tags: string[];
    match: ContentMatch | MissingContentMatch | MissingFileMatch;
}
export interface AdversarySpec {
    id: string;
    displayName: string;
    description: string;
    files: string[];
    rules: RuleSpec[];
}
export declare const spec: {
    readonly id: "go";
    readonly displayName: "Go";
    readonly description: "Reviews Go for TLS bypasses, shell commands, and unsafe filesystem permissions.";
    readonly files: ["**/*.go"];
    readonly rules: [{
        readonly id: "go.tls-insecure";
        readonly title: "Go TLS client skips certificate verification";
        readonly summary: "Go TLS client skips certificate verification";
        readonly category: "security";
        readonly severity: "high";
        readonly confidence: "high";
        readonly whyItMatters: "Go TLS client skips certificate verification weakens an important security boundary.";
        readonly impact: "The repository may behave insecurely, unreliably, or differently from the reviewed configuration.";
        readonly recommendation: "Keep certificate verification enabled.";
        readonly complexity: "small";
        readonly tags: ["security", "tls-insecure"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["**/*.go"];
            readonly pattern: {
                readonly pattern: "InsecureSkipVerify\\s*:\\s*true";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "go.shell-command";
        readonly title: "Go executes through a shell";
        readonly summary: "Go executes through a shell";
        readonly category: "security";
        readonly severity: "critical";
        readonly confidence: "high";
        readonly whyItMatters: "Go executes through a shell weakens an important security boundary.";
        readonly impact: "The repository may behave insecurely, unreliably, or differently from the reviewed configuration.";
        readonly recommendation: "Invoke the target binary directly.";
        readonly complexity: "small";
        readonly tags: ["security", "shell-command"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["**/*.go"];
            readonly pattern: {
                readonly pattern: "exec\\.Command\\(\\s*[\"'](?:sh|bash)[\"']\\s*,\\s*[\"']-c";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "go.world-writable";
        readonly title: "Go requests overly broad file or directory permissions";
        readonly summary: "Go requests overly broad file or directory permissions";
        readonly category: "security";
        readonly severity: "medium";
        readonly confidence: "high";
        readonly whyItMatters: "A directory call using ModePerm requests overly broad directory permissions before the process umask is applied; broad numeric modes can expose files similarly.";
        readonly impact: "The effective access depends on the deployment umask and can leave files writable or directories writable and executable by unintended users.";
        readonly recommendation: "Choose an explicit least-privilege mode, such as 0600 or 0644 for files and 0700 or 0755 for directories.";
        readonly complexity: "small";
        readonly tags: ["security", "world-writable"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["**/*.go"];
            readonly excludeFiles: ["**/*_test.go"];
            readonly pattern: {
                readonly pattern: "(?:(?:os\\.(?:Chmod|Mkdir|MkdirAll|OpenFile)|WriteFile)\\([^\\n]*(?:0?777|0?666)\\b|os\\.(?:Mkdir|MkdirAll)\\([^,\\n]*,\\s*(?=[^/\\n]*(?:os|fs)\\.ModePerm\\b)(?![^/\\n]*(?:&\\s*(?:os|fs)\\.ModePerm\\b|(?:os|fs)\\.ModePerm\\s*&))[^/\\n]*)";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }];
};
export {};
