import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import { api, Collectors, downloadBundle, EvalResult, Label, PhoneRow, RadarRow, RelatedRow, ScanResult, ScanRow } from "./api";
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

function FixtureBadge({ show }: { show?: boolean }) {
  const { t } = useI18n();
  if (!show) return null;
  return <span className="badge badge-fixture" title={t("fixtureTip")}>{t("fixture")}</span>;
}

function SignalChip({ id }: { id: string }) {
  const { t } = useI18n();
  const k = `sig_${id}` as Key;
  const label = t(k);
  return <span className="chip chip-sig" title={id}>{label === k ? id.replace(/_/g, " ") : label}</span>;
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
            <FixtureBadge show={r.is_fixture} />
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
      <RelatedCard key={`rel-${r.scan_id}`} scanId={r.scan_id} />
    </div>
  );
}

function RelatedCard({ scanId }: { scanId: string }) {
  const { t, lang } = useI18n();
  const [rows, setRows] = useState<RelatedRow[] | null>(null);
  useEffect(() => { api.related(scanId).then((o) => setRows(o.related || [])).catch(() => setRows([])); }, [scanId]);
  const open = (id?: string | null) => { if (id) window.location.hash = `/scan/${id}`; };
  return (
    <Card title={t("relatedTitle")} actions={rows && rows.length > 0 ? <span className="muted small">{rows.length}</span> : undefined}>
      {!rows ? <p className="muted">{t("loading")}</p> : rows.length === 0 ? <p className="muted">{t("relatedNone")}</p> : (<>
        <p className="muted small rel-hint">{t("relatedHint")}</p>
        <div className="tblwrap"><table className="tbl tbl-rel">
          <thead><tr><th>{t("colDomain")}</th><th>{t("relatedWhy")}</th><th>{t("score")}</th><th>{t("colVerdict")}</th></tr></thead>
          <tbody>{rows.map((x) => (
            <tr key={x.domain} className={x.scan_id ? "click" : ""} onClick={() => open(x.scan_id)}
              title={x.scan_id ? undefined : t("relatedNotScanned")}>
              <td><Ltr><code>{x.display}</code></Ltr> <FixtureBadge show={x.is_fixture} /></td>
              <td>{x.reasons.map((rs) => (
                <span key={rs.kind} className="chip" title={rs.values.join(", ")}>{lang === "ar" ? rs.ar : rs.en}{rs.values.length > 1 ? ` ×${rs.values.length}` : ""}</span>))}</td>
              <td className="num">{x.score ?? "—"}</td>
              <td className="nowrap">{x.label ? <LabelPill label={x.label} /> : <span className="muted small">{t("relatedNotScanned")}</span>}</td>
            </tr>))}</tbody>
        </table></div>
      </>)}
    </Card>
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
              <td className="nowrap"><Ltr>{fmtUtc(s.created_at)}</Ltr></td><td className="url"><Ltr>{s.url}</Ltr> <FixtureBadge show={s.is_fixture} /></td>
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
  const [filter, setFilter] = useState<"live" | "backfill" | "scanned" | "all">("live");
  const [running, setRunning] = useState(false);
  const [since, setSince] = useState<string | null>(null);
  const load = useCallback(() => api.radar().then(setRows).catch(() => setRows([])), []);
  const syncStatus = useCallback(async () => {
    const s = await api.radarStatus().catch(() => ({ running: false, last_started: null }));
    setRunning(!!s.running);
    setSince(s.running ? s.last_started ?? null : null);
    return !!s.running;
  }, []);
  useEffect(() => { load(); syncStatus(); }, [load, syncStatus]);
  useEffect(() => {
    if (!running) return;
    const id = window.setInterval(async () => { load(); await syncStatus(); }, 5000);
    return () => window.clearInterval(id);
  }, [running, load, syncStatus]);
  // single-flight: the server refuses a second run; the button just reflects the running one
  const backfill = async () => {
    if (await syncStatus()) return;
    setRunning(true);
    await api.backfill().catch(() => undefined);
    await syncStatus();
  };
  const sinceHm = since ? fmtUtc(since).slice(11, 16) : "";
  return (
    <>
    <CollectorBar />
    {rows && <RadarKpis rows={rows} />}
    <Card title={t("radarTitle")} actions={<>
      <BundleButton ids={(rows || []).filter((h) => h.scan_id).map((h) => h.scan_id as string)} />
      <button className="btn" onClick={load}>{t("refresh")}</button>
      <button className="btn btn-accent" onClick={backfill} disabled={running}>{running ? (sinceHm ? `${t("radarRunningSince")} ${sinceHm} UTC` : t("radarRunning")) : t("radarBackfill")}</button></>}>
      {rows && rows.length > 0 && (
        <div className="tabs" role="tablist">
          {(["live", "scanned", "backfill", "all"] as const).map((f) => {
            const n = rows.filter((h) => f === "all" || (f === "live" ? h.source !== "crtsh" : f === "backfill" ? h.source === "crtsh" : !!h.scan_id)).length;
            return <button key={f} role="tab" aria-selected={filter === f} className={filter === f ? "tab on" : "tab"} onClick={() => setFilter(f)}>
              {t(f === "live" ? "fLive" : f === "backfill" ? "fBackfill" : f === "scanned" ? "fScanned" : "fAll")} ({n})</button>;
          })}
        </div>
      )}
      {!rows ? <p className="muted">{t("loading")}</p> : rows.length === 0 ? <p className="muted">{t("noRadar")}</p> : (
        <div className="tblwrap"><table className="tbl">
          <thead><tr><th>{t("colDomain")}</th><th>{t("colSource")}</th><th>{t("colTerm")}</th><th>{t("colBrand")}</th><th>{t("colFirstSeen")}</th><th>{t("colFlagged")}</th><th>{t("colTtd")}</th><th>{t("colVerdict")}</th></tr></thead>
          <tbody>{rows.filter((h) => filter === "all" || (filter === "live" ? h.source !== "crtsh" : filter === "backfill" ? h.source === "crtsh" : !!h.scan_id)).slice(0, 300).map((h) => (
            <tr key={h.id} className={h.scan_id ? "click" : ""} onClick={() => h.scan_id && go(`/scan/${h.scan_id}`)}>
              <td><Ltr><code>{h.domain}</code></Ltr> <FixtureBadge show={h.is_fixture} />
                {h.extra?.official && <div className="muted small">{t("imitates")} <Ltr><code>{h.extra.official}</code></Ltr>{h.extra.fuzzer && <> (<span className="chip">{h.extra.fuzzer}</span>)</>}</div>}</td><td><span className="chip">{h.source}</span></td><td><Ltr>{h.matched_term}</Ltr></td>
              <td>{h.brand_id || "—"}</td><td className="nowrap"><Ltr>{fmtUtc(h.first_seen)}</Ltr></td><td className="nowrap"><Ltr>{fmtUtc(h.flagged_at)}</Ltr></td>
              <td className="nowrap ttd" title={h.time_to_detection_human}>{humanDuration(h.time_to_detection_seconds, t)}</td>
              <td className="nowrap">{h.score != null && <span className="num">{h.score} </span>}<LabelPill label={h.label} /></td>
            </tr>))}</tbody>
        </table></div>
      )}
    </Card>
    <AccuracyCard />
    </>
  );
}

function CollectorBar() {
  const { t, lang } = useI18n();
  const [c, setC] = useState<Collectors | null>(null);
  useEffect(() => {
    const load = () => api.collectors().then(setC).catch(() => undefined);
    load();
    const id = window.setInterval(load, 10000);
    return () => window.clearInterval(id);
  }, []);
  if (!c) return null;
  const ct = c.certstream || {};
  const st = ct.state === "running" ? "on" : ct.state === "stopped" ? "off" : "na";
  const word = st === "on" ? t("ctConnected") : st === "off" ? t("ctStopped") : t("ctUnavailable");
  const n = (x?: number) => (x == null ? "—" : x.toLocaleString(lang === "ar" ? "ar-AE" : "en-US"));
  const s = c.search || {};
  return (
    <div className="collectors" role="status">
      <span className={`dot dot-${st}`} aria-hidden />
      <strong>{t("ctStream")}:</strong> {word}
      {st === "on" && <>, {n(ct.certs ?? ct.messages)} {t("certsProcessed")} <span className="muted small">({t("sinceLabel")} <Ltr>{fmtUtc(ct.started_at)}</Ltr>)</span></>}
      {st !== "on" && ct.reason && <span className="muted small"> ({ct.reason})</span>}
      <span className="sep" />
      <span className={`dot dot-${s.state === "running" || s.state === "ok" ? "on" : "na"}`} aria-hidden />
      <strong>{t("searchCollector")}:</strong> {s.state === "unavailable" ? t("ctUnavailable") : s.state || "—"}
      {s.reason && <span className="muted small"> ({s.reason})</span>}
    </div>
  );
}

function median(xs: number[]): number | null {
  if (!xs.length) return null;
  const s = [...xs].sort((a, b) => a - b), m = Math.floor(s.length / 2);
  return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2;
}

function Kpi({ value, label, sub }: { value: React.ReactNode; label: string; sub?: React.ReactNode }) {
  return <div className="kpi"><div className="kpi-v">{value}</div><div className="kpi-l">{label}</div>{sub && <div className="kpi-s">{sub}</div>}</div>;
}

function RadarKpis({ rows }: { rows: RadarRow[] }) {
  const { t } = useI18n();
  const live = rows.filter((r) => !r.is_fixture);
  const base = live; // fixture rows never count towards results
  const secs = (rs: RadarRow[]) => rs.map((r) => r.time_to_detection_seconds).filter((x): x is number => x != null && x >= 0);
  // live collectors measure detection speed; crt.sh backfill measures retrospective catch-up
  const ttd = secs(base.filter((r) => r.source !== "crtsh"));
  const back = secs(base.filter((r) => r.source === "crtsh"));
  const counts: Record<string, number> = {};
  base.forEach((r) => { const k = r.label || "unlabelled"; counts[k] = (counts[k] || 0) + 1; });
  const order = ["scam", "likely_scam", "suspicious", "legitimate", "unlabelled"];
  return (
    <section className="card kpis" aria-label={t("resultsTitle")}>
      <Kpi value={live.length} label={t("kpiHits")} sub={rows.length !== live.length ? <><FixtureBadge show /> +{rows.length - live.length}</> : undefined} />
      <Kpi value={humanDuration(median(ttd), t)} label={t("kpiMedianTtd")} sub={<span className="muted">{t("kpiLiveNote")} · n={ttd.length}</span>} />
      <Kpi value={humanDuration(ttd.length ? Math.min(...ttd) : null, t)} label={t("kpiFastest")} sub={<span className="muted">{t("kpiLiveNote")}</span>} />
      {back.length > 0 && (
        <div className="kpi kpi-retro" title={t("kpiBackfillTip")}>
          <div className="kpi-v kpi-v-sm">{humanDuration(median(back), t)}</div>
          <div className="kpi-l">{t("kpiBackfill")}</div>
          <div className="kpi-s muted">{t("kpiBackfillTip")} · n={back.length}</div>
        </div>
      )}
      <Kpi value={base.filter((r) => r.scan_id).length} label={t("kpiScanned")} />
      <div className="kpi kpi-wide">
        <div className="kpi-labels">{order.filter((k) => counts[k]).map((k) => (
          <span key={k} className="kpi-lab">{k === "unlabelled" ? <span className="pill pill-none">{t("unlabelled")}</span> : <LabelPill label={k as Label} />} <b>{counts[k]}</b></span>
        ))}{!base.length && "—"}</div>
        <div className="kpi-l">{t("kpiLabels")}</div>
      </div>
    </section>
  );
}

const pct = (x?: number) => (x == null ? "—" : `${(x * 100).toFixed(1)}%`);

function AccuracyCard() {
  const { t } = useI18n();
  const [ev, setEv] = useState<EvalResult | null | undefined>(undefined);
  useEffect(() => { api.evalResults().then(setEv).catch(() => setEv(null)); }, []);
  if (ev === undefined) return null;
  return (
    <Card title={t("accuracyTitle")}>
      {!ev ? <p className="muted">{t("accNone")}</p> : ev.error ? <div className="alert alert-bad">{ev.error}</div> : (
        <>
          <div className="tblwrap"><table className="tbl acc">
            <thead><tr><th>{t("accRun")}</th><th>{t("accPrecision")}</th><th>{t("accRecall")}</th><th>{t("accF1")}</th><th>{t("accFpr")}</th><th>{t("accN")}</th></tr></thead>
            <tbody>
              <tr><th>{t("accHeadline")}</th><td>{pct(ev.precision)}</td><td>{pct(ev.recall)}</td><td>{pct(ev.f1)}</td><td>{pct(ev.fpr)}</td><td>{ev.n ?? "—"}</td></tr>
              {ev.ablation_no_blocklist && (
                <tr className="acc-honest" title={t("accNoBlocklistTip")}><th>{t("accNoBlocklist")} <span className="badge badge-warn">{t("accHonest")}</span></th>
                  <td>{pct(ev.ablation_no_blocklist.precision)}</td><td>{pct(ev.ablation_no_blocklist.recall)}</td><td>{pct(ev.ablation_no_blocklist.f1)}</td><td>{pct(ev.ablation_no_blocklist.fpr)}</td><td>{ev.ablation_no_blocklist.n ?? ev.n ?? "—"}</td></tr>
              )}
              {ev.holdout && (
                <tr className="acc-honest" title={t("accHoldoutTip")}><th>{t("accHoldout")}</th>
                  <td>{pct(ev.holdout.precision)}</td><td>{pct(ev.holdout.recall)}</td><td>{pct(ev.holdout.f1)}</td><td>{pct(ev.holdout.fpr)}</td><td>{ev.holdout.n ?? "—"}</td></tr>
              )}
              {ev.holdout?.ablation_no_blocklist && (
                <tr className="acc-honest" title={t("accNoBlocklistTip")}><th>{t("accHoldout")} · {t("accNoBlocklist")} <span className="badge badge-warn">{t("accHonest")}</span></th>
                  <td>{pct(ev.holdout.ablation_no_blocklist.precision)}</td><td>{pct(ev.holdout.ablation_no_blocklist.recall)}</td><td>{pct(ev.holdout.ablation_no_blocklist.f1)}</td><td>{pct(ev.holdout.ablation_no_blocklist.fpr)}</td><td>{ev.holdout.n ?? "—"}</td></tr>
              )}
            </tbody>
          </table></div>
          {ev.ablation_no_blocklist && <p className="muted small">{t("accNoBlocklistTip")}</p>}
          {ev.official_fp && <div className="kpis kpis-inner"><Kpi value={`${ev.official_fp.flagged}/${ev.official_fp.total}`} label={t("accOfficialFp")} /></div>}
          {ev.tp != null && (
            <table className="tbl confusion">
              <thead><tr><th>{t("accConfusion")}</th><th>{t("accPredScam")}</th><th>{t("accPredLegit")}</th></tr></thead>
              <tbody>
                <tr><th>{t("accTruthScam")}</th><td className="num good">{ev.tp}</td><td className="num bad">{ev.fn}</td></tr>
                <tr><th>{t("accTruthLegit")}</th><td className="num bad">{ev.fp}</td><td className="num good">{ev.tn}</td></tr>
              </tbody>
            </table>
          )}
          {(["false_positives", "false_negatives"] as const).map((k) => (ev[k]?.length ? (
            <details key={k}><summary>{t(k === "false_positives" ? "accFalsePos" : "accFalseNeg")} ({ev[k]!.length})</summary>
              <ul className="small">{ev[k]!.map((x, i) => <li key={i}><Ltr>{x.url}</Ltr> {x.label && <LabelPill label={x.label as Label} />} {x.score}</li>)}</ul>
            </details>) : null))}
          <p className="muted small">{t("accDataset")}: <Ltr>{ev.dataset || "—"}</Ltr>{ev.threshold && <> · ≥ {ev.threshold}</>} · <Ltr>{fmtUtc(ev.generated_at)}</Ltr></p>
        </>
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
              <td>{f.second_signals.map((s) => <SignalChip key={s} id={s} />)}</td>
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
