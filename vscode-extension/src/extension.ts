import * as vscode from 'vscode';
import { execFile } from 'child_process';
import * as path from 'path';

let diagnosticCollection: vscode.DiagnosticCollection;
let statusBarItem: vscode.StatusBarItem;

export function activate(context: vscode.ExtensionContext): void {
    diagnosticCollection = vscode.languages.createDiagnosticCollection('release-gate');
    context.subscriptions.push(diagnosticCollection);

    statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
    statusBarItem.command = 'workbench.actions.view.problems';
    statusBarItem.tooltip = 'Click to open Problems panel';
    statusBarItem.show();
    context.subscriptions.push(statusBarItem);

    updateStatusBar(null);

    context.subscriptions.push(
        vscode.commands.registerCommand('release-gate.audit', () => {
            auditWorkspace();
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('release-gate.auditFile', () => {
            const editor = vscode.window.activeTextEditor;
            if (editor) {
                auditFile(editor.document);
            } else {
                vscode.window.showWarningMessage('release-gate: No active file to audit.');
            }
        })
    );

    const config = vscode.workspace.getConfiguration('release-gate');
    if (config.get<boolean>('runOnSave')) {
        context.subscriptions.push(
            vscode.workspace.onDidSaveTextDocument((doc) => {
                auditFile(doc);
            })
        );
    }

    configureYamlSchemas();
}

function configureYamlSchemas(): void {
    const schemaUrl = 'https://release-gate.com/schema/governance.schema.json';
    const fileGlob = 'governance.{yaml,yml}';

    const config = vscode.workspace.getConfiguration('yaml');
    const existing: Record<string, string> = config.get<Record<string, string>>('schemas') ?? {};

    if (existing[schemaUrl] === fileGlob) {
        return; // already configured
    }

    const updated = { ...existing, [schemaUrl]: fileGlob };
    config.update('schemas', updated, vscode.ConfigurationTarget.Workspace).then(
        () => {},
        (err) => {
            console.warn('release-gate: could not update yaml.schemas:', err);
        }
    );
}

function updateStatusBar(report: any): void {
    if (!report) {
        statusBarItem.text = '🚪 release-gate';
        return;
    }
    const score = report.score ?? '?';
    const decision = report.decision ?? 'UNKNOWN';
    const decisionEmoji: Record<string, string> = { PROMOTE: '✅', HOLD: '⚠️', BLOCK: '🚫' };
    statusBarItem.text = `🚪 ${score}/100 ${decisionEmoji[decision] ?? '❓'} ${decision}`;
}

function severityFromString(s: string): vscode.DiagnosticSeverity {
    const config = vscode.workspace.getConfiguration('release-gate');
    const minSeverity = config.get<string>('minSeverity', 'medium');
    const order = ['low', 'medium', 'high'];
    const minIdx = order.indexOf(minSeverity);
    const sIdx = order.indexOf(s.toLowerCase());
    if (sIdx < minIdx) return vscode.DiagnosticSeverity.Hint;

    switch (s.toLowerCase()) {
        case 'high': return vscode.DiagnosticSeverity.Error;
        case 'medium': return vscode.DiagnosticSeverity.Warning;
        default: return vscode.DiagnosticSeverity.Information;
    }
}

function applyDiagnostics(report: any, baseUri?: vscode.Uri): void {
    diagnosticCollection.clear();
    updateStatusBar(report);

    const diagsByFile = new Map<string, vscode.Diagnostic[]>();

    // Code findings → diagnostics on the file where found
    const codeRisks: any[] = report.code_risks ?? report.findings ?? [];
    for (const risk of codeRisks) {
        const filePath = risk.file ?? risk.path ?? '';
        const line = Math.max(0, (risk.line ?? 1) - 1);
        const range = new vscode.Range(line, 0, line, 200);
        const title = risk.title ?? risk.rule ?? 'Code risk';
        const recommendation = risk.recommendation ?? risk.message ?? '';
        const message = recommendation ? `${title}: ${recommendation}` : title;
        const severity = severityFromString(risk.severity ?? 'medium');
        const diag = new vscode.Diagnostic(range, message, severity);
        diag.source = 'release-gate';

        const uri = filePath
            ? (path.isAbsolute(filePath)
                ? vscode.Uri.file(filePath)
                : vscode.Uri.file(path.join(baseUri?.fsPath ?? '', filePath)))
            : (baseUri ?? vscode.Uri.file('.'));
        const key = uri.toString();
        if (!diagsByFile.has(key)) diagsByFile.set(key, []);
        diagsByFile.get(key)!.push(diag);
    }

    // Missing safeguards → diagnostics on governance.yaml or workspace root
    const safeguards: Record<string, any> = report.safeguards ?? {};
    const safeguardDiags: vscode.Diagnostic[] = [];
    for (const [name, info] of Object.entries(safeguards)) {
        if (typeof info === 'object' && info !== null && !info.present) {
            const range = new vscode.Range(0, 0, 0, 0);
            const message = `Missing safeguard: ${name} — ${info.risk ?? 'unknown risk'}`;
            const diag = new vscode.Diagnostic(range, message, vscode.DiagnosticSeverity.Warning);
            diag.source = 'release-gate';
            safeguardDiags.push(diag);
        }
    }
    if (safeguardDiags.length > 0) {
        const wsFolders = vscode.workspace.workspaceFolders;
        const wsRoot = wsFolders?.[0]?.uri.fsPath ?? '';
        const govPath = path.join(wsRoot, 'governance.yaml');
        const govUri = vscode.Uri.file(govPath);
        const key = govUri.toString();
        const existing = diagsByFile.get(key) ?? [];
        diagsByFile.set(key, [...existing, ...safeguardDiags]);
    }

    for (const [uriStr, diags] of diagsByFile) {
        diagnosticCollection.set(vscode.Uri.parse(uriStr), diags);
    }
}

function runAuditCli(targetPath: string, callback: (err: Error | null, report: any) => void): void {
    const config = vscode.workspace.getConfiguration('release-gate');
    const apiToken = config.get<string>('apiToken', '');
    const args = ['audit', targetPath, '--format', 'json'];
    if (apiToken) args.push('--api-token', apiToken);

    execFile('release-gate', args, { timeout: 60000 }, (err, stdout, stderr) => {
        if (err && !stdout) {
            callback(err, null);
            return;
        }
        try {
            const report = JSON.parse(stdout);
            callback(null, report);
        } catch (parseErr) {
            callback(parseErr as Error, null);
        }
    });
}

export function auditWorkspace(): void {
    const wsFolders = vscode.workspace.workspaceFolders;
    if (!wsFolders || wsFolders.length === 0) {
        vscode.window.showWarningMessage('release-gate: No workspace folder open.');
        return;
    }
    const wsPath = wsFolders[0].uri.fsPath;
    statusBarItem.text = '🚪 auditing…';
    vscode.window.withProgress(
        { location: vscode.ProgressLocation.Notification, title: 'release-gate: Auditing workspace…', cancellable: false },
        () => new Promise<void>((resolve) => {
            runAuditCli(wsPath, (err, report) => {
                if (err || !report) {
                    vscode.window.showErrorMessage(`release-gate audit failed: ${err?.message ?? 'unknown error'}`);
                    updateStatusBar(null);
                } else {
                    applyDiagnostics(report, vscode.Uri.file(wsPath));
                    const decision = report.decision ?? 'UNKNOWN';
                    vscode.window.showInformationMessage(`release-gate: ${report.score}/100 — ${decision}`);
                }
                resolve();
            });
        })
    );
}

export function auditFile(doc: vscode.TextDocument): void {
    if (doc.uri.scheme !== 'file') return;
    runAuditCli(doc.uri.fsPath, (err, report) => {
        if (err || !report) {
            console.error('release-gate auditFile error:', err?.message);
            return;
        }
        applyDiagnostics(report, doc.uri);
    });
}

export function deactivate(): void {
    diagnosticCollection?.dispose();
    statusBarItem?.dispose();
}
