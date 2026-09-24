package report

// htmlTemplate is a single self-contained, theme-aware, responsive report.
// All dynamic values pass through html/template auto-escaping.
const htmlTemplate = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Momus scan report</title>
<style>
  :root {
    --bg: #f7f7f8; --surface: #ffffff; --border: #e3e3e8; --text: #1a1a1f;
    --muted: #6b6b76; --accent: #4f46e5;
    --vuln: #d92d20; --vuln-bg: #fef3f2; --safe: #067647; --safe-bg: #ecfdf3;
    --incon: #b54708; --incon-bg: #fffaeb; --code-bg: #f4f4f6;
    --crit: #7a0916; --high: #d92d20; --med: #b54708; --low: #475467; --info: #667085;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --bg: #0e0e12; --surface: #17171d; --border: #2a2a33; --text: #e8e8ee;
      --muted: #9a9aa6; --accent: #8b85f5;
      --vuln: #ff6b5e; --vuln-bg: #2a1512; --safe: #4ade80; --safe-bg: #10231a;
      --incon: #fbbf5c; --incon-bg: #241a0d; --code-bg: #0f0f14;
      --crit: #ff8a8a; --high: #ff6b5e; --med: #fbbf5c; --low: #9aa4b2; --info: #8891a0;
    }
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; background: var(--bg); color: var(--text);
    font: 15px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  }
  .wrap { max-width: 960px; margin: 0 auto; padding: 32px 20px 64px; }
  header { display: flex; align-items: baseline; gap: 12px; flex-wrap: wrap; }
  .brand { font-size: 26px; font-weight: 800; letter-spacing: -0.02em; }
  .brand .dot { color: var(--accent); }
  .tagline { color: var(--muted); font-size: 14px; }
  .meta { margin: 16px 0 28px; color: var(--muted); font-size: 13px;
    display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 6px 24px; }
  .meta b { color: var(--text); font-weight: 600; }
  .tiles { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin-bottom: 8px; }
  .tile { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 16px 18px; }
  .tile .n { font-size: 34px; font-weight: 800; line-height: 1; }
  .tile .l { font-size: 12px; text-transform: uppercase; letter-spacing: 0.06em; color: var(--muted); margin-top: 6px; }
  .tile.vuln .n { color: var(--vuln); } .tile.safe .n { color: var(--safe); } .tile.incon .n { color: var(--incon); }
  .sevbar { display: flex; flex-wrap: wrap; gap: 8px; margin: 16px 0 28px; }
  .sevchip { font-size: 12px; padding: 4px 10px; border-radius: 999px; border: 1px solid var(--border); background: var(--surface); }
  .sevchip b { font-weight: 700; }
  .sev-critical { color: var(--crit); } .sev-high { color: var(--high); }
  .sev-medium { color: var(--med); } .sev-low { color: var(--low); } .sev-info { color: var(--info); }
  .card { background: var(--surface); border: 1px solid var(--border); border-left-width: 4px;
    border-radius: 10px; padding: 16px 18px; margin-bottom: 12px; }
  .card.v-vulnerable { border-left-color: var(--vuln); }
  .card.v-safe { border-left-color: var(--safe); }
  .card.v-inconclusive { border-left-color: var(--incon); }
  .row { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
  .badge { font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em;
    padding: 3px 9px; border-radius: 6px; }
  .badge.v-vulnerable { color: var(--vuln); background: var(--vuln-bg); }
  .badge.v-safe { color: var(--safe); background: var(--safe-bg); }
  .badge.v-inconclusive { color: var(--incon); background: var(--incon-bg); }
  .chip { font-size: 12px; color: var(--muted); border: 1px solid var(--border); border-radius: 6px; padding: 2px 8px; }
  .aid { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; color: var(--muted); }
  .name { font-weight: 650; margin: 8px 0 2px; }
  .reason { color: var(--muted); font-size: 13px; margin-bottom: 10px; }
  details { margin-top: 8px; }
  summary { cursor: pointer; font-size: 13px; color: var(--accent); }
  pre { background: var(--code-bg); border: 1px solid var(--border); border-radius: 8px;
    padding: 12px; overflow-x: auto; font: 12.5px/1.5 ui-monospace, SFMono-Regular, Menlo, monospace;
    white-space: pre-wrap; word-break: break-word; margin: 8px 0; }
  .ev { margin-top: 8px; font-size: 13px; }
  .ev .kv { display: grid; grid-template-columns: 130px 1fr; gap: 2px 10px; }
  .ev .kv span:nth-child(odd) { color: var(--muted); }
  .refs a { color: var(--accent); word-break: break-all; }
  footer { margin-top: 32px; color: var(--muted); font-size: 12px; text-align: center; }
  .empty { color: var(--muted); font-style: italic; }
  @media (max-width: 560px) { .tiles { grid-template-columns: 1fr; } }
</style>
</head>
<body>
<div class="wrap">
  <header>
    <span class="brand">Momus<span class="dot">.</span></span>
    <span class="tagline">The harshest critic your AI will ever face.</span>
  </header>

  <div class="meta">
    <div><b>Target</b><br>{{.Meta.Target}}</div>
    <div><b>Attack pack</b><br>{{.Meta.Pack}}</div>
    <div><b>Judge</b><br>{{.Meta.JudgeName}}</div>
    <div><b>Generated</b><br>{{.Meta.GeneratedAt}}</div>
    <div><b>Version</b><br>{{.Meta.Version}}</div>
    <div><b>Attacks run</b><br>{{.Total}}</div>
    {{if .Meta.PartialScope}}<div><b>Scope</b><br>⚠ {{.Meta.PartialScope}}</div>{{end}}
  </div>

  <div class="tiles">
    <div class="tile vuln"><div class="n">{{.Vulnerable}}</div><div class="l">Vulnerable</div></div>
    <div class="tile safe"><div class="n">{{.Safe}}</div><div class="l">Safe</div></div>
    <div class="tile incon"><div class="n">{{.Inconclusive}}</div><div class="l">Inconclusive</div></div>
  </div>

  {{if .SeverityRows}}
  <div class="sevbar">
    {{range .SeverityRows}}<span class="sevchip sev-{{.Severity}}"><b>{{.Count}}</b> {{title .Severity}}</span>{{end}}
  </div>
  {{end}}

  {{if .Findings}}
  {{range .Findings}}
  <div class="card v-{{.Verdict}}">
    <div class="row">
      <span class="badge v-{{.Verdict}}">{{.Verdict}}</span>
      {{if .Severity}}<span class="chip sev-{{.Severity}}">{{title (printf "%s" .Severity)}}</span>{{end}}
      {{if .Category}}<span class="chip">{{.Category}}</span>{{end}}
      {{if .OWASPLLM}}<span class="chip">{{.OWASPLLM}}</span>{{end}}
      <span class="aid">{{.AttackID}}</span>
    </div>
    <div class="name">{{.AttackName}}</div>
    <div class="reason">{{.Reason}}</div>

    <details>
      <summary>Payload sent</summary>
      <pre>{{.Payload}}</pre>
    </details>

    {{if .ResponseText}}
    <details>
      <summary>Target response{{if .Truncated}} (truncated){{end}}</summary>
      <pre>{{.ResponseText}}</pre>
    </details>
    {{end}}

    {{range .Evidence}}
    <div class="ev">
      <details>
        <summary>Judge evidence &mdash; {{.DecisionStr}}{{if .Model}} ({{.Model}}){{end}}</summary>
        <div class="kv">
          <span>Decision</span><span>{{.DecisionStr}}</span>
          <span>Confidence</span><span>{{printf "%.2f" .Confidence}}</span>
          <span>Nonce authenticated</span><span>{{.NonceOK}}</span>
          <span>Cache hit</span><span>{{.CacheHit}}</span>
          {{if .ResolvedModel}}<span>Model</span><span>{{.ResolvedModel}}</span>{{end}}
        </div>
        {{if .EvidenceQuote}}<pre>{{.EvidenceQuote}}</pre>{{end}}
        {{if .Rationale}}<div class="reason">{{.Rationale}}</div>{{end}}
      </details>
    </div>
    {{end}}

    {{if .References}}
    <details class="refs">
      <summary>References</summary>
      <ul>{{range .References}}<li><a href="{{.}}" rel="noopener noreferrer">{{.}}</a></li>{{end}}</ul>
    </details>
    {{end}}
  </div>
  {{end}}
  {{else}}
  <p class="empty">No findings.</p>
  {{end}}

  <footer>
    Generated by <b>Momus</b> {{.Meta.Version}} &middot; open-source AI security &middot;
    <a href="https://github.com/momusai/momus" rel="noopener noreferrer">github.com/momusai/momus</a>
  </footer>
</div>
</body>
</html>
`
