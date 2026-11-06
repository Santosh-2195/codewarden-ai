"""Self-contained, print-friendly HTML report. All repository/AI text is HTML-escaped."""
from __future__ import annotations

import html
import re
from typing import List

from .. import __tool_name__, __version__
from ..models import SEVERITIES
from . import SCOPE_LIMITATIONS, Context, counts, source_label

E = html.escape

CSS = """
:root{--paper:#F3F5F7;--surface:#FFFFFF;--ink:#17202A;--muted:#566270;--line:#D8DDE3;--brand:#0B6E69;
--code-bg:#F7F8FA;--hit:#FFF1D6;--crit:#A11423;--high:#C2410C;--med:#946200;--low:#235AA6;--info:#5B6472;
color-scheme:light}
@media (prefers-color-scheme:dark){:root{--paper:#11161C;--surface:#182029;--ink:#E5E9ED;--muted:#9BA6B2;
--line:#2B3540;--brand:#4FC2B8;--code-bg:#0F141A;--hit:#3A2E12;--crit:#FF6B76;--high:#FF8A4C;--med:#E6B84A;
--low:#7FB0FF;--info:#9BA6B2;color-scheme:dark}}
*{box-sizing:border-box}html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--paper);color:var(--ink);font:15px/1.6 "Segoe UI Variable Text","Segoe UI",system-ui,-apple-system,Roboto,"Helvetica Neue",Arial,sans-serif}
.wrap{max-width:1080px;margin:0 auto;padding:32px 20px 64px}
code,pre,.mono{font-family:"Cascadia Mono","Cascadia Code",Consolas,"SF Mono",Menlo,monospace}
a{color:var(--brand)}
header.top{display:grid;grid-template-columns:1fr auto;gap:24px;align-items:end;border-bottom:2px solid var(--ink);padding-bottom:20px}
header.top h1{margin:0;font-size:clamp(28px,4.4vw,44px);line-height:1.08;letter-spacing:-.02em;font-weight:700}
header.top .kind{margin:0 0 6px;color:var(--muted);font-size:15px}
.meta{margin:10px 0 0;color:var(--muted);font-size:14px}
.rating{min-width:190px;padding:14px 18px;border:2px solid currentColor;text-align:left}
.rating span{display:block;font-size:13px;color:var(--muted)}
.rating strong{display:block;font-size:34px;line-height:1.05;letter-spacing:-.01em}
.r-Critical{color:var(--crit)}.r-High{color:var(--high)}.r-Medium{color:var(--med)}.r-Low{color:var(--low)}
.dist{margin:26px 0 8px}
.bar{display:flex;height:16px;border-radius:2px;overflow:hidden;background:var(--line)}
.bar i{display:block;height:100%}
.legend{display:flex;flex-wrap:wrap;gap:6px 20px;margin-top:10px;font-size:14px}
.legend b{font-size:20px;margin-right:6px;font-variant-numeric:tabular-nums}
.k-Critical{background:var(--crit)}.k-High{background:var(--high)}.k-Medium{background:var(--med)}.k-Low{background:var(--low)}.k-Info{background:var(--info)}
.t-Critical{color:var(--crit)}.t-High{color:var(--high)}.t-Medium{color:var(--med)}.t-Low{color:var(--low)}.t-Info{color:var(--info)}
section{margin-top:40px}
h2{font-size:22px;margin:0 0 12px;letter-spacing:-.01em}
h3{font-size:16px;margin:22px 0 6px}
p{margin:0 0 12px;max-width:78ch}
.panel{background:var(--surface);border:1px solid var(--line);padding:18px 20px}
.lead{font-size:17px;max-width:72ch}
table{border-collapse:collapse;width:100%;background:var(--surface);border:1px solid var(--line);font-size:14px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-weight:600;color:var(--muted);background:var(--paper)}
td.num{text-align:right;font-variant-numeric:tabular-nums}
td.mono{white-space:nowrap}
code{font-size:.92em}
.scroll{overflow-x:auto}
.toolbar{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:0 0 14px}
.toolbar button{font:inherit;font-size:14px;padding:6px 12px;border:1px solid var(--line);background:var(--surface);color:var(--ink);cursor:pointer;border-radius:3px}
.toolbar button[aria-pressed=true]{background:var(--ink);color:var(--paper);border-color:var(--ink)}
.toolbar input{font:inherit;font-size:14px;padding:6px 10px;border:1px solid var(--line);background:var(--surface);color:var(--ink);border-radius:3px;min-width:220px;flex:1}
:focus-visible{outline:3px solid var(--brand);outline-offset:2px}
details.finding{background:var(--surface);border:1px solid var(--line);border-left:6px solid var(--sev);margin:0 0 10px}
details.finding>summary{list-style:none;cursor:pointer;display:grid;grid-template-columns:76px 92px 1fr;gap:12px;align-items:baseline;padding:12px 16px}
details.finding>summary::-webkit-details-marker{display:none}
.fid{font-weight:700;font-variant-numeric:tabular-nums}
.sev{font-weight:700;color:var(--sev)}
.ftitle{font-weight:600}
.floc{grid-column:3;color:var(--muted);font-size:13px;word-break:break-all}
.fbody{padding:4px 20px 20px;border-top:1px solid var(--line)}
.facts{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:8px 18px;margin:14px 0 6px;font-size:14px}
.facts div span{display:block;color:var(--muted);font-size:12.5px}
pre{margin:6px 0 14px;background:var(--code-bg);border:1px solid var(--line);padding:10px 0;overflow-x:auto;font-size:13px;line-height:1.5}
pre .ln{display:block;padding:0 14px;white-space:pre}
pre .ln.hit{background:var(--hit);box-shadow:inset 3px 0 0 var(--sev)}
pre .no{display:inline-block;width:3.2em;color:var(--muted);user-select:none}
pre.fix{padding:12px 14px;white-space:pre}
.locname{font-size:13px;color:var(--muted);margin-top:10px}
.note{border-left:3px solid var(--line);padding:2px 0 2px 12px;color:var(--muted)}
.sev-Critical{--sev:var(--crit)}.sev-High{--sev:var(--high)}.sev-Medium{--sev:var(--med)}.sev-Low{--sev:var(--low)}.sev-Info{--sev:var(--info)}
ol.steps{padding-left:20px;max-width:78ch}ol.steps li{margin-bottom:6px}
.chain{margin:0 0 12px}
footer{margin-top:48px;padding-top:14px;border-top:1px solid var(--line);color:var(--muted);font-size:13px}
.hidden{display:none}
@media (max-width:640px){header.top{grid-template-columns:1fr}details.finding>summary{grid-template-columns:64px 1fr}
.ftitle{grid-column:1/-1}.floc{grid-column:1/-1}}
@media print{body{background:#fff;color:#000;font-size:11pt}.toolbar{display:none}details.finding{break-inside:avoid-page}
details.finding>.fbody{display:block}a{color:#000}.wrap{padding:0}}
@media (prefers-reduced-motion:reduce){*{scroll-behavior:auto}}
"""

JS = """
(function(){
  var sev='all', confirmedOnly=false, q='';
  var items=[].slice.call(document.querySelectorAll('details.finding'));
  function apply(){
    var shown=0;
    items.forEach(function(d){
      var ok=(sev==='all'||d.dataset.sev===sev)&&(!confirmedOnly||d.dataset.status==='Confirmed')&&
        (!q||d.textContent.toLowerCase().indexOf(q)>-1);
      d.classList.toggle('hidden',!ok); if(ok) shown++;
    });
    var c=document.getElementById('shown'); if(c) c.textContent=shown+' of '+items.length+' shown';
  }
  document.querySelectorAll('[data-filter]').forEach(function(b){
    b.addEventListener('click',function(){
      sev=b.dataset.filter;
      document.querySelectorAll('[data-filter]').forEach(function(x){x.setAttribute('aria-pressed',x===b)});
      apply();
    });
  });
  var cb=document.getElementById('confirmed');
  if(cb) cb.addEventListener('click',function(){confirmedOnly=!confirmedOnly;cb.setAttribute('aria-pressed',confirmedOnly);apply();});
  var s=document.getElementById('search');
  if(s) s.addEventListener('input',function(){q=s.value.trim().toLowerCase();apply();});
  var ex=document.getElementById('expand');
  if(ex) ex.addEventListener('click',function(){var open=ex.getAttribute('aria-pressed')!=='true';
    items.forEach(function(d){d.open=open}); ex.setAttribute('aria-pressed',open); ex.textContent=open?'Collapse all':'Expand all';});
  window.addEventListener('beforeprint',function(){items.forEach(function(d){d.open=true;d.classList.remove('hidden')})});
  if(location.hash){var t=document.getElementById(location.hash.slice(1)); if(t&&t.tagName==='DETAILS'){t.open=true;}}
  apply();
})();
"""


def _p(text: str) -> str:
    if not text:
        return ""
    paras = [x.strip() for x in re.split(r"\n\s*\n", text) if x.strip()]
    out = []
    for para in paras:
        esc = E(para)
        esc = re.sub(r"`([^`]+)`", r"<code>\1</code>", esc)
        esc = esc.replace("\n", "<br>")
        out.append(f"<p>{esc}</p>")
    return "".join(out)


def _t(text: str) -> str:
    """Escape a title and render `code` spans."""
    return re.sub(r"`([^`]+)`", r"<code>\1</code>", E(text or ""))


def to_html(result) -> str:
    ctx = Context(result)
    c = counts(result)
    s = result.summary
    m = result.metrics
    total = len(result.findings)
    rating = s.get("risk_rating", "Low")
    parts: List[str] = []
    w = parts.append
    w("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">")
    w("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1, viewport-fit=cover\">")
    w(f"<title>Security assessment - {E(result.project)}</title>")
    w("<link rel=\"icon\" href=\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'%3E%3Ctext y='.9em' font-size='90'%3E%F0%9F%9B%A1%EF%B8%8F%3C/text%3E%3C/svg%3E\">")
    w(f"<style>{CSS}</style></head><body><div class=\"wrap\">")

    # header
    w("<header class=\"top\"><div>")
    w(f"<p class=\"kind\">Security assessment report, generated by {E(__tool_name__)} v{E(__version__)}</p>")
    w(f"<h1>{E(result.project)}</h1>")
    w(f"<p class=\"meta\">{E(result.started)}. {m.files_collected} files, {m.lines_scanned:,} lines. "
      f"AI model: {E(result.ai_label)}. Stack: {E(', '.join(result.frameworks) or 'n/a')}.</p>")
    w(f"</div><div class=\"rating r-{E(rating)}\"><span>Overall risk</span><strong>{E(rating)}</strong>"
      f"<span>{total} finding{'s' if total != 1 else ''}, score {s.get('risk_score', 0)}</span></div></header>")

    # distribution
    w("<div class=\"dist\" aria-label=\"Findings by severity\"><div class=\"bar\" role=\"img\" aria-label=\""
      + E(", ".join(f"{c[x]} {x}" for x in SEVERITIES if c[x])) + "\">")
    for sev in SEVERITIES:
        if c[sev] and total:
            w(f"<i class=\"k-{sev}\" style=\"width:{c[sev] / total * 100:.2f}%\" title=\"{c[sev]} {sev}\"></i>")
    w("</div><div class=\"legend\">")
    for sev in SEVERITIES:
        if sev == "Info" and not c[sev]:
            continue
        w(f"<span class=\"t-{sev}\"><b>{c[sev]}</b>{sev}</span>")
    w("</div></div>")

    # executive summary
    w("<section id=\"summary\"><h2>Executive summary</h2>")
    w(f"<div class=\"lead\">{_p(s.get('executive_summary', ''))}</div>")
    if not result.ai_enabled:
        w("<p class=\"note\">Rules-only mode: AI verification, contextual explanations and AI-discovered findings "
          "are not included in this report.</p>")
    w("</section>")

    # index
    if result.findings:
        w("<section id=\"index\"><h2>Findings at a glance</h2><div class=\"scroll\"><table><thead><tr>"
          "<th>ID</th><th>Severity</th><th>Title</th><th>Location</th><th>Status</th></tr></thead><tbody>")
        for f in result.findings:
            more = f" (+{len(f.locations) - 1})" if len(f.locations) > 1 else ""
            w(f"<tr><td class=\"mono\"><a href=\"#{E(f.id)}\">{E(f.id)}</a></td><td class=\"t-{f.severity}\"><b>{E(f.severity)}</b></td>"
              f"<td>{_t(f.title)}</td><td class=\"mono\">{E(f.primary.label())}{more}</td><td>{E(f.status)}</td></tr>")
        w("</tbody></table></div></section>")

    # details
    w("<section id=\"findings\"><h2>Detailed findings</h2><div class=\"toolbar\" role=\"toolbar\" aria-label=\"Filter findings\">")
    w("<button type=\"button\" data-filter=\"all\" aria-pressed=\"true\">All</button>")
    for sev in SEVERITIES:
        if c[sev]:
            w(f"<button type=\"button\" data-filter=\"{sev}\" aria-pressed=\"false\">{sev} ({c[sev]})</button>")
    w("<button type=\"button\" id=\"confirmed\" aria-pressed=\"false\">Confirmed only</button>")
    w("<button type=\"button\" id=\"expand\" aria-pressed=\"false\">Expand all</button>")
    w("<input id=\"search\" type=\"search\" placeholder=\"Search findings, files, CWE\" aria-label=\"Search findings\">"
      "<span id=\"shown\" class=\"meta\"></span></div>")
    for f in result.findings:
        w(f"<details class=\"finding sev-{f.severity}\" id=\"{E(f.id)}\" data-sev=\"{f.severity}\" data-status=\"{E(f.status)}\">")
        w(f"<summary><span class=\"fid mono\">{E(f.id)}</span><span class=\"sev\">{E(f.severity)}</span>"
          f"<span class=\"ftitle\">{_t(f.title)}</span><span class=\"floc mono\">{E(f.primary.label())}"
          f"{' and ' + str(len(f.locations) - 1) + ' more' if len(f.locations) > 1 else ''}</span></summary>")
        w("<div class=\"fbody\"><div class=\"facts\">")
        facts = [("Status", f.status), ("Confidence", f.confidence), ("Category", f.category), ("CWE", f.cwe),
                 ("OWASP Top 10", f.owasp or "-"), ("Detection", source_label(f))]
        if f.ai_severity_change:
            facts.append(("AI severity calibration", f.ai_severity_change))
        for k, v in facts:
            w(f"<div><span>{E(k)}</span>{E(v)}</div>")
        w("</div>")
        w("<h3>What is wrong</h3>" + _p(f.description))
        w("<h3>Evidence</h3>")
        for l in f.locations[:6]:
            w(f"<div class=\"locname mono\">{E(l.label())}</div><pre>")
            for n, txt, hit in ctx.excerpt(l):
                w(f"<span class=\"ln{' hit' if hit else ''}\"><span class=\"no\">{n}</span>{E(txt)}</span>")
            w("</pre>")
        if len(f.locations) > 6:
            w(f"<p class=\"meta\">and {len(f.locations) - 6} more location(s)</p>")
        w("<h3>Why it matters</h3>" + _p(f.impact or "-"))
        w("<h3>How to fix it</h3>" + _p(f.recommendation or "-"))
        if f.secure_code:
            w(f"<h3>Secure code</h3><pre class=\"fix\">{E(f.secure_code)}</pre>")
        if f.validation_notes:
            w(f"<h3>Validation notes</h3><div class=\"note\">{_p(f.validation_notes)}</div>")
        if f.references:
            w("<p class=\"meta\">References: " + ", ".join(
                f"<a href=\"{E(r)}\" rel=\"noopener noreferrer\" target=\"_blank\">{E(r)}</a>"
                for r in f.references[:3] if r.startswith("https://")) + "</p>")
        w("</div></details>")
    if not result.findings:
        w("<p>No findings at or above the selected severity threshold.</p>")
    w("</section>")

    # chains + plan
    if s.get("attack_chains"):
        w("<section id=\"chains\"><h2>Attack chains</h2><p>How individual weaknesses combine into higher-impact paths.</p>")
        for ch in s["attack_chains"]:
            links = ", ".join(f"<a href=\"#{E(i)}\">{E(i)}</a>" for i in ch["finding_ids"])
            w(f"<div class=\"panel chain\"><h3 style=\"margin-top:0\">{E(ch['title'])}</h3><p class=\"meta\">{links}</p>{_p(ch['narrative'])}</div>")
        w("</section>")
    w("<section id=\"plan\"><h2>Remediation plan</h2><div class=\"scroll\"><table><thead><tr><th>#</th><th>Action</th>"
      "<th>Findings</th><th>Effort</th></tr></thead><tbody>")
    for i, a in enumerate(s.get("prioritized_actions", []), start=1):
        links = ", ".join(f"<a href=\"#{E(x)}\">{E(x)}</a>" for x in a["finding_ids"])
        w(f"<tr><td class=\"num\">{i}</td><td>{E(a['action'])}</td><td class=\"mono\">{links}</td><td>{E(a.get('effort', ''))}</td></tr>")
    w("</tbody></table></div></section>")

    # overall
    w("<section id=\"assessment\"><h2>Overall assessment</h2>")
    w(f"<p><b class=\"t-{E(rating)}\">Risk rating: {E(rating)}</b> (weighted score {s.get('risk_score', 0)}).</p>")
    w(_p(s.get("overall_assessment", "")))
    if s.get("positive_observations"):
        w("<h3>Positive observations</h3><ul>" + "".join(f"<li>{E(x)}</li>" for x in s["positive_observations"]) + "</ul>")
    w("</section>")

    # methodology
    w("<section id=\"method\"><h2>Methodology and AI pipeline</h2><ol class=\"steps\">"
      "<li><b>Collect.</b> Source is loaded from a folder, ZIP or GitHub URL and treated as untrusted data; nothing is executed.</li>"
      "<li><b>Detect candidates.</b> Generic language-aware rules flag secrets, injection, XSS, access-control and database-policy weaknesses.</li>"
      "<li><b>Protect.</b> Credential-like values are masked before code leaves the machine.</li>"
      "<li><b>AI review.</b> An LLM reviews each file with project context (stack, file map, schema and RLS policies), confirms or rejects every candidate, recalibrates severity and finds logic flaws rules cannot see.</li>"
      "<li><b>Ground.</b> Every AI finding must quote an exact code line; unverifiable claims are dropped.</li>"
      "<li><b>Deduplicate.</b> Findings sharing a root cause are merged into one finding with several locations.</li>"
      "<li><b>Synthesise.</b> The AI writes the summary, attack chains and plan from verified findings only.</li></ol>")
    rows = [("Files analysed", m.files_collected), ("Files reviewed by AI", m.files_ai_reviewed),
            ("Rule candidates", m.rule_candidates), ("Rejected by AI as false positives", m.ai_rejected),
            ("Severity recalibrations by AI", m.ai_severity_adjusted), ("New findings discovered by AI", m.ai_new_findings),
            ("AI findings dropped by evidence grounding", m.grounding_dropped), ("Duplicates merged", m.merged_duplicates),
            ("Secret values masked before AI", m.secrets_redacted), ("AI requests (cache hits)", f"{m.ai_calls} ({m.ai_cache_hits})"),
            ("Scan duration", f"{result.duration_s}s")]
    w("<div class=\"scroll\"><table><tbody>" + "".join(
        f"<tr><th scope=\"row\">{E(k)}</th><td class=\"num\">{E(str(v))}</td></tr>" for k, v in rows) + "</tbody></table></div>")
    if m.ai_errors:
        w(f"<p class=\"note\">{m.ai_errors} AI request(s) failed; affected files fall back to rule findings.</p>")
    w("<h3>Scope and limitations</h3><ul>" + "".join(f"<li>{E(x)}</li>" for x in SCOPE_LIMITATIONS) + "</ul></section>")
    w(f"<footer>{E(__tool_name__)} v{E(__version__)}. AI-assisted static analysis, not a penetration test. "
      "Validate findings before closing remediation.</footer>")
    w(f"</div><script>{JS}</script></body></html>")
    return "".join(parts)
