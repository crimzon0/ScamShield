import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import { api, downloadBundle, Label, PhoneRow, RadarRow, ScanResult, ScanRow } from "./api";
import { dict, fmtUtc, humanDuration, Key, Lang } from "./i18n";

// ------------------------------------------------------------------ i18n context
interface I18n { lang: Lang; t: (k: Key) => string; setLang: (l: Lang) => void }
const I18nCtx = createContext<I18n>({ lang: "en", t: (k) => k, setLang: () => {} });
const useI18n = () => useContext(I18nCtx);

function initialLang(): Lang {
  try { const v = localStorage.getItem("ss_lang"); if (v === "ar" || v === "en") return v; } catch { /* ignore */ }
  return "en";
}

// ------------------------------------------------------------------ routing (hash)
function useRoute(): [string, (r: string) => void] {
  const [route, setRoute] = useState(() => window.location.hash.slice(1) || "/");
  useEffect(() => {
    const on = () => setRoute(window.location.hash.slice(1) || "/");
    window.addEventListener("hashchange", on);
    return () => window.removeEventListener("hashchange", on);
  }, []);
  return [route, (r: string) => { window.location.hash = r; }];
}

// ------------------------------------------------------------------ small pieces
function LabelPill({ label }: { label?: Label | null }) {
  const { t } = useI18n();
  if (!label) return <span className="pill pill-none">—</span>;
  return <span className={`pill pill-${label}`}>{t(`label_${label}` as Key)}</span>;
}

function Gauge({ score, label }: { score: number; label: Label }) {
  const { t } = useI18n();
  const r = 52, c = Math.PI * r, pct = Math.max(0, Math.min(100, score)) / 100;
  return (
    <div className="gauge" role="img" aria-label={`${t("score")} ${score}/100`}>
      <svg viewBox="0 0 128 76" width="180" height="107">
        <path d="M12 68 A52 52 0 0 1 116 68" className="gauge-track" />
        <path d="M12 68 A52 52 0 0 1 116 68" className={`gauge-fill fill-${label}`}
          strokeDasharray={`${c * pct} ${c}`} />
      </svg>
      <div className="gauge-num"><span>{score}</span><small>/100</small></div>
      <div className="gauge-cap">{t("score")}</div>
    </div>
  );
}

function Card({ title, children, actions, className = "" }: { title?: string; children: React.ReactNode; actions?: React.ReactNode; className?: string }) {
  return (
    <section className={`card ${className}`}>
      {(title || actions) && <header className="card-h"><h2>{title}</h2><div className="card-actions">{actions}</div></header>}
      {children}
    </section>
  );
}

const Ltr = ({ children }: { children: React.ReactNode }) => <bdi dir="ltr" className="ltr">{children}</bdi>;

// ------------------------------------------------------------------ verdict detail
function VerdictCard({ r }: { r: ScanResult }) {
  const { t, lang } = useI18n();
  const v = r.verdict;
  const reasons = [...v.reasons].sort((a, b) => Math.abs(b.weight) - Math.abs(a.weight));
  return (
    <Card className={`verdict verdict-${v.label}`}>
      <div className="verdict-top">
        <Gauge score={v.score} label={v.label} />
        <div className="verdict-main">
          <div className="verdict-label-row">
            <span className="muted">{t("verdict")}</span>
            <span className={`big-label lbl-${v.label}`}>{t(`label_${v.label}` as Key)}</span>
            <span className={`badge ${v.mode === "domain_only" ? "badge-warn" : "badge-info"}`}>
              {v.mode === "domain_only" ? t("modeDomainOnly") : t("modeFull")}
            </span>
          </div>
          <p className="summary">{lang === "ar" ? v.summary_ar || v.summary_en : v.summary_en || v.summary_ar}</p>
          <dl className="kv">
            <dt>{t("colUrl")}</dt><dd><Ltr>{v.url}</Ltr></dd>
            {v.final_url && v.final_url !== v.url && <><dt>{t("finalUrl")}</dt><dd><Ltr>{v.final_url}</Ltr></dd></>}
            <dt>{t("domain")}</dt><dd><Ltr>{v.registrable_domain || "—"}</Ltr></dd>
            <dt>{t("scanId")}</dt><dd><Ltr>{v.scan_id}</Ltr> · <Ltr>{fmtUtc(v.created_at)}</Ltr></dd>
          </dl>
        </div>
      </div>
      <h3>{t("reasons")}</h3>
      {reasons.length === 0 ? <p className="muted">{t("noReasons")}</p> : (
        <ul className="reasons">
          {reasons.map((s) => (
            <li key={s.id} className={s.weight > 0 ? "r-bad" : s.weight < 0 ? "r-good" : ""}>
              <span className="r-w">{s.weight > 0 ? `+${s.weight}` : s.weight}</span>
              <div>
                <div>{lang === "ar" ? s.ar || s.en : s.en || s.ar}</div>
                {s.evidence && <div className="r-ev"><Ltr>{s.evidence}</Ltr></div>}
              </div>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}

function BrandCard({ r }: { r: ScanResult }) {
  const { t, lang } = useI18n();
  const b = r.brand, look = r.lookalike || b?.lookalike;
  return (
    <Card title={t("brand")}>
      {b && b.brand_id ? (
        <dl className="kv">
          <dt>{t("brandClaimed")}</dt>
          <dd><strong>{lang === "ar" ? b.name_ar || b.name_en : b.name_en}</strong> <span className="muted">({Math.round(b.confidence * 100)}% · {b.methods.join(", ")})</span></dd>
          <dt>{t("officialDomains")}</dt>
          <dd>{b.official_domains.length ? b.official_domains.map((d) => <code key={d}>{d}</code>) : "—"}</dd>
          <dt>{t("domain")}</dt>
          <dd><code>{r.verdict.registrable_domain}</code> <span className={`badge ${b.is_official_domain ? "badge-ok" : "badge-bad"}`}>{b.is_official_domain ? t("onOfficial") : t("notOfficial")}</span></dd>
          {b.asks_for.length > 0 && <><dt>{t("asksFor")}</dt><dd>{b.asks_for.map((a) => <span key={a} className="chip">{a}</span>)}</dd></>}
        </dl>
      ) : <p className="muted">{t("noBrand")}</p>}
      {look && look.brand_id && look.score > 0 && look.domain !== look.closest_official && !b?.is_official_domain && (
        <p className="look"><span className="badge badge-warn">{t("lookalike")}</span> <code>{look.domain}</code> → {t("closestOfficial")} <code>{look.closest_official || "—"}</code> {look.techniques.map((x) => <span key={x} className="chip">{x}</span>)}</p>
      )}
    </Card>
  );
}

function ScreenshotCard({ r }: { r: ScanResult }) {
  const { t } = useI18n();
  const personas = r.detonations.map((d) => d.persona);
  const [sel, setSel] = useState(personas[0]);
  const det = r.detonations.find((d) => d.persona === sel);
  const src = r.screenshots?.[sel];
  return (
    <Card title={t("screenshots")}>
      {r.cloak?.cloaked && <div className="alert alert-bad">⚠ {t("cloakWarning")}<ul>{r.cloak.differences.map((d, i) => <li key={i}>{d}</li>)}</ul></div>}
      <div className="tabs" role="tablist">
        {personas.map((p) => (
          <button key={p} role="tab" aria-selected={p === sel} className={p === sel ? "tab on" : "tab"} onClick={() => setSel(p)}>
            {t(`persona_${p}` as Key) || p}
          </button>
        ))}
      </div>
      {det && <div className="shot-meta"><span className={`badge ${det.status === "ok" ? "badge-ok" : "badge-warn"}`}>{det.status}</span> {det.http_status && <code>HTTP {det.http_status}</code>} <span className="muted">{det.title}</span></div>}
      {src ? <div className="shot-wrap"><a href={src} target="_blank" rel="noreferrer"><img className="shot" src={src} alt={`${sel} screenshot`} /></a></div>
        : <div className="shot-empty">{t("noScreenshot")}</div>}
    </Card>
  );
}

function ChainCard({ r }: { r: ScanResult }) {
  const { t } = useI18n();
  const det = r.detonations.find((d) => d.redirect_chain.length) || r.detonations[0];
  const chain = det?.redirect_chain || [];
  return (
    <Card title={t("redirectChain")}>
      {chain.length === 0 ? <p className="muted">{t("noRedirects")}</p> : (
        <ol className="chain">
          {chain.map((h, i) => (
            <li key={i}>
              <span className={`kind kind-${h.kind}`}>{h.kind}</span>
              <div className="hop">
                <Ltr>{h.url}</Ltr>
                <div className="muted small">{h.status != null && <code>{h.status}</code>} <Ltr>{fmtUtc(h.at)}</Ltr></div>
              </div>
            </li>
          ))}
        </ol>
      )}
    </Card>
  );
}

function IntelCard({ r }: { r: ScanResult }) {
  const { t } = useI18n();
  const i = r.intel;
  if (!i) return null;
  const young = i.age_days != null && i.age_days < 30;
  const bl = [...(i.blocklist_hits || []), ...(i.safe_browsing || []).map((x) => `GSB:${x}`)];
  return (
    <Card title={t("intel")}>
      <dl className="kv">
        <dt>{t("age")}</dt><dd className={young ? "bad" : ""}>{i.age_days != null ? `${i.age_days} ${t("days")}` : t("unknown")} {i.created && <span className="muted small">(<Ltr>{fmtUtc(i.created)}</Ltr>)</span>}</dd>
        <dt>{t("registrar")}</dt><dd>{i.registrar || t("unknown")}</dd>
        <dt>{t("hosting")}</dt><dd><Ltr>{[i.asn, i.asn_org, i.hosting_country].filter(Boolean).join(" · ") || t("unknown")}</Ltr></dd>
        <dt>{t("ip")}</dt><dd><code>{i.ip || "—"}</code></dd>
        <dt>{t("certFirstSeen")}</dt><dd><Ltr>{fmtUtc(i.cert_first_seen)}</Ltr>{i.cert_count != null && <span className="muted small"> · {t("certCount")}: {i.cert_count}</span>}</dd>
        <dt>{t("blocklists")}</dt><dd>{bl.length ? bl.map((x) => <span key={x} className="chip chip-bad">{x}</span>) : <span className="muted">{t("notListed")}</span>}</dd>
        {i.tranco_rank != null && <><dt>{t("tranco")}</dt><dd>#{i.tranco_rank}</dd></>}
        <dt>{t("sources")}</dt><dd>{Object.entries(i.sources || {}).map(([k, v]) => <span key={k} className={`chip ${v === "ok" || v === "cached" ? "" : "chip-dim"}`}>{k}: {v}</span>)}</dd>
      </dl>
    </Card>
  );
}

function ExportCard({ r }: { r: ScanResult }) {
  const { t, lang } = useI18n();
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [c, setC] = useState<{ zip_url?: string | null; pdf_url?: string | null; notice_en?: string; notice_ar?: string } | null>(r.case || null);
  const run = async () => {
    setBusy(true); setErr("");
    try {
      const out = await api.buildCase(r.scan_id);
      setC(out);
      if (out.zip_url) { const a = document.createElement("a"); a.href = out.zip_url; a.download = ""; document.body.appendChild(a); a.click(); a.remove(); }
    } catch (e) { setErr(String((e as Error).message)); } finally { setBusy(false); }
  };
  return (
    <Card title={t("export")} className="export">
      <button className="btn btn-accent" onClick={run} disabled={busy}>{busy ? t("exporting") : `⬇ ${t("export")}`}</button>
      {err && <div className="alert alert-bad">{err}</div>}
      {c && (
        <div className="downloads">
          {c.zip_url && <a className="btn" href={c.zip_url}>📦 {t("downloadZip")}</a>}
          {c.pdf_url ? <a className="btn" href={c.pdf_url} target="_blank" rel="noreferrer">📄 {t("downloadPdf")}</a> : <span className="muted small">{t("pdfUnavailable")}</span>}
        </div>
      )}
      {c && (c.notice_en || c.notice_ar) && (
        <details className="notice"><summary>{t("takedown")}</summary><pre dir={lang === "ar" ? "rtl" : "ltr"}>{lang === "ar" ? c.notice_ar || c.notice_en : c.notice_en || c.notice_ar}</pre></details>
      )}
    </Card>
  );
}

function ScanDetail({ r }: { r: ScanResult }) {
  return (
    <div className="detail">
      <VerdictCard r={r} />
      <div className="grid2">
        <BrandCard r={r} />
        <IntelCard r={r} />
      </div>
      <div className="grid2">
        <ScreenshotCard key={r.scan_id} r={r} />
        <div className="stack"><ChainCard r={r} /><ExportCard key={r.scan_id} r={r} /></div>
      </div>
    </div>
  );
}

function BundleButton({ ids }: { ids: string[] }) {
  const { t } = useI18n();
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  if (!ids.length) return null;
  const run = async () => { setBusy(true); setErr(""); try { await downloadBundle(ids); } catch (e) { setErr((e as Error).message); } finally { setBusy(false); } };
  return <button className="btn" onClick={run} disabled={busy} title={err || undefined}>{busy ? t("exportingBundle") : `📦 ${t("exportBundle")}`} {err && "⚠"}</button>;
}

// ------------------------------------------------------------------ scan page
function ScanBox({ onDone }: { onDone: (r: ScanResult) => void }) {
  const { t } = useI18n();
  const [url, setUrl] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!url.trim()) return;
    setBusy(true); setErr("");
    try { onDone(await api.scan(url.trim())); } catch (e) { setErr(`${t("scanError")}: ${(e as Error).message}`); } finally { setBusy(false); }
  };
  return (
    <form className="scanbox" onSubmit={submit}>
      <input dir="ltr" type="text" value={url} onChange={(e) => setUrl(e.target.value)} placeholder={t("scanPlaceholder")} aria-label={t("scanPlaceholder")} />
      <button className="btn btn-accent" disabled={busy}>{busy ? <span className="spin" /> : null}{busy ? t("scanning") : t("scanButton")}</button>
      {err && <div className="alert alert-bad">{err}</div>}
    </form>
  );
}

function BatchBox({ go }: { go: (r: string) => void }) {
  const { t } = useI18n();
  const [job, setJob] = useState<Awaited<ReturnType<typeof api.batchStatus>> | null>(null);
  const timer = useRef<number>();
  const upload = async (f?: File | null) => {
    if (!f) return;
    const { job_id } = await api.batchCsv(f);
    const poll = async () => {
      const s = await api.batchStatus(job_id); setJob(s);
      if (s.status !== "done") timer.current = window.setTimeout(poll, 1500);
    };
    poll();
  };
  useEffect(() => () => window.clearTimeout(timer.current), []);
  return (
    <details className="batch">
      <summary>{t("batchTitle")}</summary>
      <label className="btn"><input type="file" accept=".csv,text/csv" hidden onChange={(e) => upload(e.target.files?.[0])} />{t("batchUpload")}</label>
      {job && (
        <div>
          <div className="muted small">{t("batchProgress")}: {job.done}/{job.total}</div>
          <progress max={job.total} value={job.done} />
          <table className="tbl"><tbody>{job.results.map((x, i) => (
            <tr key={i} className={x.scan_id ? "click" : ""} onClick={() => x.scan_id && go(`/scan/${x.scan_id}`)}>
              <td><Ltr>{x.url}</Ltr></td><td>{x.score ?? ""}</td><td>{x.label ? <LabelPill label={x.label} /> : x.status}</td>
            </tr>))}</tbody></table>
        </div>
      )}
    </details>
  );
}

function RecentScans({ go, refreshKey }: { go: (r: string) => void; refreshKey: number }) {
  const { t } = useI18n();
  const [rows, setRows] = useState<ScanRow[] | null>(null);
  useEffect(() => { api.scans().then(setRows).catch(() => setRows([])); }, [refreshKey]);
  return (
    <Card title={t("recentTitle")} actions={<BundleButton ids={(rows || []).filter((s) => s.label !== "legitimate").slice(0, 25).map((s) => s.scan_id)} />}>
      {!rows ? <p className="muted">{t("loading")}</p> : rows.length === 0 ? <p className="muted">{t("noScans")}</p> : (
        <div className="tblwrap"><table className="tbl">
          <thead><tr><th>{t("colWhen")}</th><th>{t("colUrl")}</th><th>{t("score")}</th><th>{t("colVerdict")}</th></tr></thead>
          <tbody>{rows.map((s) => (
            <tr key={s.scan_id} className="click" onClick={() => go(`/scan/${s.scan_id}`)}>
              <td className="nowrap"><Ltr>{fmtUtc(s.created_at)}</Ltr></td><td className="url"><Ltr>{s.url}</Ltr></td>
              <td className="num">{s.score}</td><td><LabelPill label={s.label} /></td>
            </tr>))}</tbody>
        </table></div>
      )}
    </Card>
  );
}

function ScanPage({ id, go }: { id?: string; go: (r: string) => void }) {
  const { t } = useI18n();
  const [res, setRes] = useState<ScanResult | null>(null);
  const [err, setErr] = useState("");
  const [rk, setRk] = useState(0);
  useEffect(() => {
    setErr("");
    if (!id) { setRes(null); return; }
    if (res?.scan_id === id && res.screenshots) return;
    api.getScan(id).then(setRes).catch((e) => setErr(String(e.message)));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id]);
  const onDone = (r: ScanResult) => { setRk((x) => x + 1); go(`/scan/${r.scan_id}`); };
  return (
    <>
      <Card className="hero">
        <h1>{t("tagline")}</h1>
        <ScanBox onDone={onDone} />
        <BatchBox go={go} />
      </Card>
      {err && <div className="alert alert-bad">{err}</div>}
      {id && !res && !err && <p className="muted">{t("loading")}</p>}
      {res && id && <ScanDetail r={res} />}
      <RecentScans go={go} refreshKey={rk} />
    </>
  );
}

// ------------------------------------------------------------------ radar
function RadarPage({ go }: { go: (r: string) => void }) {
  const { t } = useI18n();
  const [rows, setRows] = useState<RadarRow[] | null>(null);
  const [running, setRunning] = useState(false);
  const load = useCallback(() => api.radar().then(setRows).catch(() => setRows([])), []);
  useEffect(() => { load(); }, [load]);
  useEffect(() => {
    if (!running) return;
    const id = window.setInterval(async () => {
      const s = await api.radarStatus().catch(() => ({ running: false }));
      load();
      if (!s.running) setRunning(false);
    }, 2000);
    return () => window.clearInterval(id);
  }, [running, load]);
  const backfill = async () => { setRunning(true); await api.backfill().catch(() => setRunning(false)); };
  return (
    <Card title={t("radarTitle")} actions={<>
      <BundleButton ids={(rows || []).filter((h) => h.scan_id).map((h) => h.scan_id as string)} />
      <button className="btn" onClick={load}>{t("refresh")}</button>
      <button className="btn btn-accent" onClick={backfill} disabled={running}>{running ? t("radarRunning") : t("radarBackfill")}</button></>}>
      {!rows ? <p className="muted">{t("loading")}</p> : rows.length === 0 ? <p className="muted">{t("noRadar")}</p> : (
        <div className="tblwrap"><table className="tbl">
          <thead><tr><th>{t("colDomain")}</th><th>{t("colSource")}</th><th>{t("colTerm")}</th><th>{t("colBrand")}</th><th>{t("colFirstSeen")}</th><th>{t("colFlagged")}</th><th>{t("colTtd")}</th><th>{t("colVerdict")}</th></tr></thead>
          <tbody>{rows.map((h) => (
            <tr key={h.id} className={h.scan_id ? "click" : ""} onClick={() => h.scan_id && go(`/scan/${h.scan_id}`)}>
              <td><Ltr><code>{h.domain}</code></Ltr></td><td><span className="chip">{h.source}</span></td><td><Ltr>{h.matched_term}</Ltr></td>
              <td>{h.brand_id || "—"}</td><td className="nowrap"><Ltr>{fmtUtc(h.first_seen)}</Ltr></td><td className="nowrap"><Ltr>{fmtUtc(h.flagged_at)}</Ltr></td>
              <td className="nowrap ttd">{humanDuration(h.time_to_detection_seconds, t)}</td>
              <td className="nowrap">{h.score != null && <span className="num">{h.score} </span>}<LabelPill label={h.label} /></td>
            </tr>))}</tbody>
        </table></div>
      )}
    </Card>
  );
}

// ------------------------------------------------------------------ helpline
const STATUS_ORDER: Record<string, number> = { likely_scam: 0, unverified: 1, official: 2 };
function HelplinePage() {
  const { t, lang } = useI18n();
  const [rows, setRows] = useState<PhoneRow[] | null>(null);
  const [busy, setBusy] = useState(false);
  const load = useCallback(() => api.helpline().then((r) => setRows([...r].sort((a, b) => (STATUS_ORDER[a.status] ?? 3) - (STATUS_ORDER[b.status] ?? 3)))).catch(() => setRows([])), []);
  useEffect(() => { load(); }, [load]);
  const run = async () => { setBusy(true); try { await api.helplineRun(); await load(); } finally { setBusy(false); } };
  const anySynthetic = rows?.some((r) => r.synthetic);
  return (
    <Card title={t("helplineTitle")} actions={<button className="btn btn-accent" onClick={run} disabled={busy}>{busy ? t("helplineRunning") : t("helplineRun")}</button>}>
      {anySynthetic && <p className="muted small">{t("syntheticNote")}</p>}
      {!rows ? <p className="muted">{t("loading")}</p> : rows.length === 0 ? <p className="muted">{t("noHelpline")}</p> : (
        <div className="tblwrap"><table className="tbl">
          <thead><tr><th>{t("colBrand")}</th><th>{t("colListing")}</th><th>{t("colNumber")}</th><th>{t("colOfficial")}</th><th>{t("colStatus")}</th><th>{t("colSignals")}</th></tr></thead>
          <tbody>{rows.map((f) => (
            <tr key={f.id}>
              <td>{(lang === "ar" ? f.brand_name_ar : f.brand_name_en) || f.brand_id}</td>
              <td>{f.listing_url ? <a href={f.listing_url} target="_blank" rel="noreferrer noopener">{f.listing_name}</a> : f.listing_name}
                {f.synthetic && <span className="badge badge-synth">{t("synthetic")}</span>}
                {f.address && <div className="muted small">{f.address}</div>}
                <div className="muted small">{f.source} · <span dir={lang === "ar" ? "rtl" : "ltr"}>{lang === "ar" ? f.reasons_ar || f.reasons_en : f.reasons_en || f.reasons_ar}</span></div></td>
              <td className="nowrap"><Ltr><code>{f.number_e164 || f.raw_number}</code></Ltr>{f.number_e164 && f.raw_number && <div className="muted small"><Ltr>{f.raw_number}</Ltr></div>}</td>
              <td>{f.official_numbers.map((n) => <div key={n}><Ltr><code>{n}</code></Ltr></div>)}</td>
              <td><span className={`pill st-${f.status}`}>{t(`status_${f.status}` as Key)}</span></td>
              <td>{f.second_signals.map((s) => <span key={s} className="chip">{s}</span>)}</td>
            </tr>))}</tbody>
        </table></div>
      )}
    </Card>
  );
}

// ------------------------------------------------------------------ shell
export default function App() {
  const [lang, setLangState] = useState<Lang>(initialLang);
  const [route, go] = useRoute();
  useEffect(() => {
    document.documentElement.lang = lang;
    document.documentElement.dir = lang === "ar" ? "rtl" : "ltr";
    document.title = `${dict[lang].appName} · UAE`;
    try { localStorage.setItem("ss_lang", lang); } catch { /* ignore */ }
  }, [lang]);
  const i18n = useMemo<I18n>(() => ({ lang, t: (k) => dict[lang][k] ?? dict.en[k] ?? k, setLang: setLangState }), [lang]);
  const t = i18n.t;
  const scanId = route.startsWith("/scan/") ? decodeURIComponent(route.slice(6)) : undefined;
  const page = route.startsWith("/radar") ? "radar" : route.startsWith("/helpline") ? "helpline" : "scan";
  return (
    <I18nCtx.Provider value={i18n}>
      <header className="top">
        <div className="brandmark" onClick={() => go("/")}>
          <svg viewBox="0 0 32 32" width="30" height="30" aria-hidden><path d="M16 2 4 7v8c0 8 5 13 12 15 7-2 12-7 12-15V7z" fill="none" stroke="currentColor" strokeWidth="2.2" /><path d="m11 16 4 4 7-8" fill="none" stroke="currentColor" strokeWidth="2.4" /></svg>
          <div><div className="bm-name">{t("appName")}</div><div className="bm-sub">{t("partner")}</div></div>
        </div>
        <nav>
          <a className={page === "scan" ? "on" : ""} href="#/">{t("navScan")}</a>
          <a className={page === "radar" ? "on" : ""} href="#/radar">{t("navRadar")}</a>
          <a className={page === "helpline" ? "on" : ""} href="#/helpline">{t("navHelpline")}</a>
        </nav>
        <button className="btn lang" onClick={() => setLangState(lang === "en" ? "ar" : "en")} lang={lang === "en" ? "ar" : "en"}>{t("langToggle")}</button>
      </header>
      <main>
        {page === "scan" && <ScanPage id={scanId} go={go} />}
        {page === "radar" && <RadarPage go={go} />}
        {page === "helpline" && <HelplinePage />}
      </main>
      <footer className="foot">{t("footer")}</footer>
    </I18nCtx.Provider>
  );
}
