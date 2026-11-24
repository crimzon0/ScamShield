export type Label = "scam" | "likely_scam" | "suspicious" | "legitimate";

export interface Signal { id: string; weight: number; en: string; ar: string; evidence?: string }
export interface RedirectHop { url: string; status?: number | null; kind: string; at: string }
export interface Detonation {
  url: string; persona: string; status: string; final_url: string; http_status?: number | null;
  redirect_chain: RedirectHop[]; title: string; screenshot_path?: string | null; error?: string;
  form_fields?: { name: string; type: string; label: string }[];
  tls?: { issuer: string; subject: string; valid_from?: string | null } | null;
}
export interface Intel {
  domain: string; registrable_domain: string; created?: string | null; age_days?: number | null; registrar: string;
  ip: string; asn: string; asn_org: string; hosting_country: string; cert_first_seen?: string | null;
  cert_count?: number | null; blocklist_hits: string[]; safe_browsing: string[]; tranco_rank?: number | null;
  nameservers: string[]; sources: Record<string, string>; abuse_emails: string[];
}
export interface Lookalike { domain: string; brand_id?: string | null; closest_official?: string | null; distance?: number | null; techniques: string[]; score: number }
export interface BrandMatch {
  brand_id?: string | null; name_en: string; name_ar: string; confidence: number; methods: string[]; evidence: string[];
  official_domains: string[]; is_official_domain: boolean; asks_for: string[]; lookalike?: Lookalike | null; llm_used: boolean;
}
export interface Verdict {
  scan_id: string; url: string; final_url: string; registrable_domain: string; score: number; label: Label;
  mode: "full" | "domain_only"; reasons: Signal[]; summary_en: string; summary_ar: string; brand_id?: string | null; created_at: string;
}
export interface ScanResult {
  scan_id: string; url: string; detonations: Detonation[]; cloak?: { cloaked: boolean; personas: string[]; differences: string[]; similarity: number } | null;
  intel?: Intel | null; brand?: BrandMatch | null; lookalike?: Lookalike | null; verdict: Verdict; created_at: string;
  screenshots?: Record<string, string>; is_fixture?: boolean; case?: { zip_url?: string | null; pdf_url?: string | null } | null;
}
export interface ScanRow { scan_id: string; url: string; created_at: string; score: number; label: Label; domain?: string; is_fixture?: boolean }
export interface RadarRow {
  id: number; domain: string; source: string; matched_term: string; brand_id?: string | null; first_seen: string;
  flagged_at: string; scan_id?: string | null; score?: number | null; label?: Label | null; time_to_detection_seconds?: number | null; is_fixture?: boolean; time_to_detection_human?: string;
  extra?: { official?: string; fuzzer?: string; match_kind?: string; crtsh_url?: string; host?: string; [k: string]: unknown };
}
export interface PhoneRow {
  id: number; brand_id: string; brand_name_en?: string; brand_name_ar?: string; query: string; source: string;
  listing_name: string; listing_url: string; address: string; raw_number: string; number_e164: string; official_numbers: string[];
  status: "official" | "unverified" | "likely_scam"; second_signals: string[]; reasons_en: string; reasons_ar: string;
  synthetic: boolean; found_at: string;
}
export interface CaseOut { zip_url?: string | null; pdf_url?: string | null; notice_en: string; notice_ar: string }

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const r = await fetch(path, init);
  if (!r.ok) {
    let msg = `${r.status}`;
    try { msg = (await r.json()).detail || msg; } catch { /* ignore */ }
    throw new Error(msg);
  }
  return r.json();
}

const json = (body: unknown): RequestInit => ({ method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });

export interface CollectorStatus { state?: string; reason?: string; certs?: number; messages?: number; hits?: number; started_at?: string; last_error?: string; queries?: number; at?: string }
export interface Collectors { certstream?: CollectorStatus; search?: CollectorStatus; backfill?: { running: boolean; last_started?: string | null } }
export interface EvalMetrics { ablation_no_blocklist?: EvalMetrics | null; precision?: number; recall?: number; f1?: number; fpr?: number; n?: number; dataset?: string; tp?: number; fp?: number; fn?: number; tn?: number }
export interface EvalResult {
  generated_at?: string; dataset?: string; n?: number; threshold?: string; error?: string;
  tp?: number; fp?: number; fn?: number; tn?: number; precision?: number; recall?: number; f1?: number; fpr?: number;
  official_fp?: { flagged: number; total: number }; labels?: Record<string, number>; modes?: Record<string, number>;
  false_positives?: { url: string; label?: string; score?: number }[]; false_negatives?: { url: string; label?: string; score?: number }[];
  ablation_no_blocklist?: EvalMetrics | null; holdout?: EvalMetrics | null;
}

export async function downloadBundle(scanIds: string[]): Promise<void> {
  const r = await fetch("/api/bundle", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ scan_ids: scanIds }) });
  if (!r.ok) throw new Error(`${r.status}`);
  const blob = await r.blob();
  const cd = r.headers.get("content-disposition") || "";
  const m = /filename="?([^";]+)"?/.exec(cd);
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob); a.download = m ? m[1] : "scamshield_bundle.zip";
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 5000);
}

export const api = {
  scan: (url: string) => req<ScanResult>("/api/scan", json({ url })),
  getScan: (id: string) => req<ScanResult>(`/api/scans/${encodeURIComponent(id)}`),
  scans: () => req<ScanRow[]>("/api/scans"),
  radar: () => req<RadarRow[]>("/api/radar?limit=1000"),
  radarStatus: () => req<{ running: boolean; last_started?: string | null; last_count?: number | null; error?: string }>("/api/radar/status"),
  backfill: () => req<{ started: boolean }>("/api/radar/backfill", { method: "POST" }),
  collectors: () => req<Collectors>("/api/radar/collectors"),
  evalResults: () => req<EvalResult | null>("/api/eval"),
  helpline: () => req<PhoneRow[]>("/api/helpline"),
  helplineRun: () => req<{ findings: number }>("/api/helpline/run", json({})),
  buildCase: (id: string) => req<CaseOut>(`/api/scans/${encodeURIComponent(id)}/case`, { method: "POST" }),
  batchCsv: (file: File) => { const fd = new FormData(); fd.append("file", file); return req<{ job_id: string; total: number }>("/api/batch", { method: "POST", body: fd }); },
  batchStatus: (id: string) => req<{ status: string; total: number; done: number; results: { url: string; status: string; scan_id?: string; score?: number; label?: Label }[] }>(`/api/batch/${id}`),
};
