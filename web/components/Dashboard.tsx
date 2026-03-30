'use client'

import { useState, useEffect, useCallback, useMemo } from 'react'
import {
  Search, Copy, Check, RefreshCw, Shield,
  Globe, Server, Hash, Bug, Link2,
  ChevronLeft, ChevronRight, Code2, ExternalLink,
  Database, FileJson, Wifi,
} from 'lucide-react'

// ─── Constants ────────────────────────────────────────────────────────────────

const RAW_BASE = 'https://raw.githubusercontent.com/MysticX662/ThreatMonitoring/main/api/v1'

const ENDPOINTS = [
  {
    file:        'latest.json',
    url:         `${RAW_BASE}/latest.json`,
    description: 'Latest 500 IOCs across all sources, sorted newest-first.',
    returns:     'ThreatRecord[]',
    accent:      '#00D4FF',
    icon:        Database,
  },
  {
    file:        'ips.json',
    url:         `${RAW_BASE}/ips.json`,
    description: 'IP-type IOCs only (type == "ip"). Filtered subset of latest.',
    returns:     'ThreatRecord[]',
    accent:      '#FF8C00',
    icon:        Server,
  },
  {
    file:        'vulnerabilities.json',
    url:         `${RAW_BASE}/vulnerabilities.json`,
    description: 'CVE entries only (type == "vulnerability"). Sourced from CISA KEV.',
    returns:     'ThreatRecord[]',
    accent:      '#FF2D55',
    icon:        Bug,
  },
  {
    file:        'summary.json',
    url:         `${RAW_BASE}/summary.json`,
    description: 'Aggregated counts by source, type, and severity. Refreshed every 30 min.',
    returns:     'SummaryRecord',
    accent:      '#22CC66',
    icon:        FileJson,
  },
]

const PAGE_SIZE = 30
const REFRESH_MS = 5 * 60 * 1000

// ─── Types ────────────────────────────────────────────────────────────────────

interface ThreatRecord {
  ioc: string
  type: string
  severity: string
  source: string
  description: string
  timestamp: string
}

type ActiveTab = 'feed' | 'developer'

// ─── Config maps ──────────────────────────────────────────────────────────────

const SEV_CONFIG: Record<string, { label: string; cls: string; dot: string }> = {
  critical: { label: 'CRITICAL', cls: 'badge badge-critical', dot: '#FF2D55' },
  high:     { label: 'HIGH',     cls: 'badge badge-high',     dot: '#FF5555' },
  medium:   { label: 'MEDIUM',   cls: 'badge badge-medium',   dot: '#FF9F1C' },
  low:      { label: 'LOW',      cls: 'badge badge-low',      dot: '#22AAFF' },
  unknown:  { label: '???',      cls: 'badge badge-unknown',  dot: '#3D6070' },
}

const SOURCE_COLOR: Record<string, string> = {
  'URLhaus':   '#FF6B35',
  'CISA KEV':  '#FF2D55',
  'ThreatFox': '#00D4FF',
}

const TYPE_ICONS: Record<string, React.ElementType> = {
  url:           Link2,
  ip:            Server,
  domain:        Globe,
  hash:          Hash,
  vulnerability: Bug,
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function sevConfig(severity: string) {
  return SEV_CONFIG[severity.toLowerCase()] ?? SEV_CONFIG.unknown
}

function formatTs(raw: string): string {
  if (!raw) return '—'
  const d = new Date(raw)
  if (isNaN(d.getTime())) return raw.slice(0, 16)
  return d.toISOString().replace('T', ' ').slice(0, 16) + 'Z'
}

function truncate(s: string, n: number) {
  return s.length > n ? s.slice(0, n) + '…' : s
}

// ─── SeverityBadge ────────────────────────────────────────────────────────────

function SeverityBadge({ severity }: { severity: string }) {
  const cfg = sevConfig(severity)
  return (
    <span className={cfg.cls}>
      <span className="blink-live" style={{ width: 6, height: 6, borderRadius: '50%', background: cfg.dot, display: 'inline-block', flexShrink: 0 }} />
      {cfg.label}
    </span>
  )
}

// ─── CopyBtn ──────────────────────────────────────────────────────────────────

function CopyBtn({ text, label = 'COPY' }: { text: string; label?: string }) {
  const [done, setDone] = useState(false)

  const copy = useCallback(() => {
    navigator.clipboard.writeText(text).then(() => {
      setDone(true)
      setTimeout(() => setDone(false), 1500)
    })
  }, [text])

  return (
    <button onClick={copy} className={`copy-btn ${done ? 'copied' : ''}`} title={`Copy: ${text}`}>
      {done
        ? <><Check size={10} style={{ display: 'inline', marginRight: 3 }} />COPIED</>
        : <><Copy size={10} style={{ display: 'inline', marginRight: 3 }} />{label}</>
      }
    </button>
  )
}

// ─── StatCard ─────────────────────────────────────────────────────────────────

function StatCard({ label, value, accent }: { label: string; value: number; accent: string }) {
  return (
    <div className="stat-card" style={{ '--card-accent': accent } as React.CSSProperties}>
      <div style={{ color: 'var(--text-dim)', fontSize: 10, letterSpacing: '0.12em' }}>{label}</div>
      <div style={{ color: accent, fontSize: 22, lineHeight: 1.2, fontFamily: "'Saira Condensed', sans-serif", fontWeight: 700 }}>
        {value.toLocaleString()}
      </div>
    </div>
  )
}

// ─── CodeBlock ───────────────────────────────────────────────────────────────

function CodeBlock({ lang, code }: { lang: string; code: string }) {
  return (
    <div style={{ border: '1px solid var(--border2)', background: '#020508', position: 'relative' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '5px 12px', borderBottom: '1px solid var(--border)', background: 'var(--surface2)' }}>
        <span style={{ color: 'var(--text-dim)', fontSize: 10, letterSpacing: '0.12em' }}>{lang}</span>
        <CopyBtn text={code} label="COPY CODE" />
      </div>
      <pre style={{ margin: 0, padding: '14px 16px', overflowX: 'auto', fontSize: 11.5, lineHeight: 1.7, color: 'var(--text-bright)', fontFamily: "'Share Tech Mono', monospace" }}>
        {code}
      </pre>
    </div>
  )
}

// ─── DeveloperPanel ──────────────────────────────────────────────────────────

function DeveloperPanel() {
  const pythonSnippet = `import requests

BASE = "${RAW_BASE}"

# ── Fetch all feeds ───────────────────────────────────────────
latest = requests.get(f"{BASE}/latest.json").json()
ips    = requests.get(f"{BASE}/ips.json").json()
vulns  = requests.get(f"{BASE}/vulnerabilities.json").json()
meta   = requests.get(f"{BASE}/summary.json").json()

# ── Filter for actionable IOCs ────────────────────────────────
high_iocs = [r for r in latest if r["severity"] in ("high", "critical")]
cves      = [r["ioc"] for r in vulns]

# ── Schema for each record ─────────────────────────────────────
# {
#   "ioc":         str  — defanged indicator (e.g. 185[.]220[.]1[.]1)
#   "type":        str  — url | ip | domain | hash | vulnerability
#   "severity":    str  — critical | high | medium | low
#   "source":      str  — URLhaus | CISA KEV | ThreatFox
#   "description": str  — human-readable context
#   "timestamp":   str  — ISO-8601 UTC
# }

print(f"Total IOCs : {meta['total_iocs']}")
print(f"By source  : {meta['by_source']}")
print(f"High/Crit  : {len(high_iocs)}")`

  const elasticSnippet = `from elasticsearch import Elasticsearch
import requests

es      = Elasticsearch(["http://localhost:9200"])
records = requests.get("${RAW_BASE}/latest.json").json()

for record in records:
    es.index(
        index    = "threat-intel",
        id       = record["ioc"],          # dedup by IOC string
        document = record,
    )

print(f"Indexed {len(records)} records into Elasticsearch.")`

  const curlSnippet = `# Latest 500 IOCs
curl -s "${RAW_BASE}/latest.json" | jq '.[] | select(.severity == "critical")'

# IPs only
curl -s "${RAW_BASE}/ips.json" | jq '.[].ioc'

# Feed summary / counts
curl -s "${RAW_BASE}/summary.json" | jq '{total: .total_iocs, by_source: .by_source}'`

  const splunkSnippet = `| makeresults
| eval url="${RAW_BASE}/latest.json"
| streamstats count
| where count=1
| map search="| eval raw=urlencode(\\"$url$\\") | rest splunk_server=local /services/data/inputs/http | eval iocs=json_extract(body, \\".\\")"

| spath input=body path={}
| mvexpand {}
| spath input={} path=severity output=severity
| spath input={} path=ioc      output=ioc
| where severity IN ("high","critical")
| table ioc severity source description timestamp`

  return (
    <div style={{ padding: '24px 24px', maxWidth: 1100 }}>

      {/* ── CORS note ──────────────────────────────────────────────────── */}
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 12, padding: '12px 16px', border: '1px solid #22CC6640', background: '#021A0A', marginBottom: 28 }}>
        <Wifi size={14} style={{ color: '#22CC66', marginTop: 2, flexShrink: 0 }} />
        <div>
          <div style={{ color: '#22CC66', fontSize: 11, letterSpacing: '0.1em', marginBottom: 4 }}>CORS-FRIENDLY — NO PROXY REQUIRED</div>
          <div style={{ color: 'var(--text)', fontSize: 12, lineHeight: 1.7 }}>
            GitHub Raw serves <code style={{ background: 'var(--surface2)', padding: '1px 5px', color: 'var(--accent)' }}>Access-Control-Allow-Origin: *</code> on every response.
            All four endpoints can be fetched directly from a browser, a Python script, a SIEM, or any HTTP client without a CORS proxy.
            JSON is formatted with <code style={{ background: 'var(--surface2)', padding: '1px 5px', color: 'var(--accent)' }}>indent=2</code> for human readability and diff-friendly git commits.
          </div>
        </div>
      </div>

      {/* ── Endpoint index ─────────────────────────────────────────────── */}
      <div style={{ marginBottom: 32 }}>
        <div style={{ color: 'var(--text-dim)', fontSize: 10, letterSpacing: '0.18em', marginBottom: 12 }}>
          ── API ENDPOINTS
        </div>
        <div style={{ display: 'grid', gap: 1 }}>
          {ENDPOINTS.map(ep => {
            const Icon = ep.icon
            return (
              <div
                key={ep.file}
                style={{ display: 'grid', gridTemplateColumns: '170px 1fr auto', alignItems: 'center', gap: 0, border: '1px solid var(--border)', background: 'var(--surface)', borderBottom: 'none' }}
                className="threat-row"
              >
                {/* File name + icon */}
                <div style={{ padding: '10px 14px', borderRight: '1px solid var(--border)', display: 'flex', alignItems: 'center', gap: 8 }}>
                  <Icon size={12} style={{ color: ep.accent, flexShrink: 0 }} />
                  <span style={{ color: ep.accent, fontSize: 12 }}>{ep.file}</span>
                </div>

                {/* URL + description */}
                <div style={{ padding: '8px 14px', borderRight: '1px solid var(--border)' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 3 }}>
                    <code style={{ color: 'var(--text-bright)', fontSize: 11, wordBreak: 'break-all' }}>{ep.url}</code>
                    <a href={ep.url} target="_blank" rel="noopener noreferrer" style={{ color: 'var(--text-dim)', flexShrink: 0 }} title="Open raw URL">
                      <ExternalLink size={10} />
                    </a>
                  </div>
                  <div style={{ color: 'var(--text-dim)', fontSize: 11 }}>
                    {ep.description} &nbsp;<span style={{ color: 'var(--text-dim)', opacity: 0.6 }}>→ {ep.returns}</span>
                  </div>
                </div>

                {/* Copy */}
                <div style={{ padding: '8px 12px' }}>
                  <CopyBtn text={ep.url} label="URL" />
                </div>
              </div>
            )
          })}
          {/* close border on last row */}
          <div style={{ height: 1, background: 'var(--border)' }} />
        </div>
      </div>

      {/* ── IOC schema ─────────────────────────────────────────────────── */}
      <div style={{ marginBottom: 32 }}>
        <div style={{ color: 'var(--text-dim)', fontSize: 10, letterSpacing: '0.18em', marginBottom: 12 }}>
          ── NORMALIZED RECORD SCHEMA  (ThreatRecord)
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 1 }}>
          {[
            { field: 'ioc',         type: 'string', note: 'Defanged indicator — dots replaced with [.]' },
            { field: 'type',        type: 'string', note: 'url | ip | domain | hash | vulnerability' },
            { field: 'severity',    type: 'string', note: 'critical | high | medium | low' },
            { field: 'source',      type: 'string', note: 'URLhaus | CISA KEV | ThreatFox' },
            { field: 'description', type: 'string', note: 'Human-readable threat context' },
            { field: 'timestamp',   type: 'string', note: 'ISO-8601 UTC from source feed' },
          ].map(s => (
            <div key={s.field} style={{ padding: '8px 12px', border: '1px solid var(--border)', background: 'var(--surface)' }}>
              <div style={{ display: 'flex', alignItems: 'baseline', gap: 8, marginBottom: 2 }}>
                <span style={{ color: 'var(--accent)', fontSize: 12 }}>{s.field}</span>
                <span style={{ color: 'var(--text-dim)', fontSize: 10 }}>{s.type}</span>
              </div>
              <div style={{ color: 'var(--text)', fontSize: 11 }}>{s.note}</div>
            </div>
          ))}
        </div>
      </div>

      {/* ── Code snippets ─────────────────────────────────────────────── */}
      <div style={{ marginBottom: 32 }}>
        <div style={{ color: 'var(--text-dim)', fontSize: 10, letterSpacing: '0.18em', marginBottom: 12 }}>
          ── PYTHON INTEGRATION
        </div>
        <CodeBlock lang="PYTHON 3.8+" code={pythonSnippet} />
      </div>

      <div style={{ marginBottom: 32 }}>
        <div style={{ color: 'var(--text-dim)', fontSize: 10, letterSpacing: '0.18em', marginBottom: 12 }}>
          ── ELASTICSEARCH / SIEM INGEST
        </div>
        <CodeBlock lang="PYTHON — ELASTICSEARCH" code={elasticSnippet} />
      </div>

      <div style={{ marginBottom: 32 }}>
        <div style={{ color: 'var(--text-dim)', fontSize: 10, letterSpacing: '0.18em', marginBottom: 12 }}>
          ── CURL / SHELL
        </div>
        <CodeBlock lang="BASH / ZSH" code={curlSnippet} />
      </div>

      <div style={{ marginBottom: 12 }}>
        <div style={{ color: 'var(--text-dim)', fontSize: 10, letterSpacing: '0.18em', marginBottom: 12 }}>
          ── SPLUNK INTEGRATION (BETA)
        </div>
        <CodeBlock lang="SPLUNK SPL" code={splunkSnippet} />
      </div>

    </div>
  )
}

// ─── Dashboard ───────────────────────────────────────────────────────────────

export default function Dashboard() {
  const [data, setData]               = useState<ThreatRecord[]>([])
  const [loading, setLoading]         = useState(true)
  const [error, setError]             = useState<string | null>(null)
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null)
  const [search, setSearch]           = useState('')
  const [page, setPage]               = useState(0)
  const [refreshing, setRefreshing]   = useState(false)
  const [activeTab, setActiveTab]     = useState<ActiveTab>('feed')

  const fetchData = useCallback(async (isManual = false) => {
    if (isManual) setRefreshing(true)
    try {
      const res = await fetch(`${RAW_BASE}/latest.json?t=${Date.now()}`)
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const json: ThreatRecord[] = await res.json()
      setData(json)
      setLastUpdated(new Date())
      setError(null)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Fetch failed')
    } finally {
      setLoading(false)
      if (isManual) setRefreshing(false)
    }
  }, [])

  useEffect(() => {
    fetchData()
    const timer = setInterval(() => fetchData(), REFRESH_MS)
    return () => clearInterval(timer)
  }, [fetchData])

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase()
    if (!q) return data
    return data.filter(r =>
      r.ioc.toLowerCase().includes(q) ||
      r.type.toLowerCase().includes(q) ||
      r.source.toLowerCase().includes(q) ||
      r.severity.toLowerCase().includes(q) ||
      r.description.toLowerCase().includes(q)
    )
  }, [data, search])

  const totalPages  = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE))
  const currentPage = Math.min(page, totalPages - 1)
  const pageData    = filtered.slice(currentPage * PAGE_SIZE, (currentPage + 1) * PAGE_SIZE)

  const counts = useMemo(() => ({
    total:    data.length,
    critical: data.filter(r => r.severity.toLowerCase() === 'critical').length,
    high:     data.filter(r => r.severity.toLowerCase() === 'high').length,
    medium:   data.filter(r => r.severity.toLowerCase() === 'medium').length,
    low:      data.filter(r => r.severity.toLowerCase() === 'low').length,
  }), [data])

  const handleSearch = (v: string) => { setSearch(v); setPage(0) }

  const TABS: { id: ActiveTab; label: string; icon: React.ElementType }[] = [
    { id: 'feed',      label: 'LIVE FEED',  icon: Shield },
    { id: 'developer', label: 'DEVELOPER',  icon: Code2  },
  ]

  return (
    <div style={{ position: 'relative', zIndex: 1, minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>

      {/* ── Header ────────────────────────────────────────────────────────── */}
      <header style={{ borderBottom: '1px solid var(--border)', background: 'var(--surface)', padding: '12px 20px 0' }}>

        {/* Brand row */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', paddingBottom: 10 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <Shield size={16} style={{ color: 'var(--accent)' }} />
              <span style={{ fontFamily: "'Saira Condensed', sans-serif", fontWeight: 700, fontSize: 20, color: 'var(--text-bright)', letterSpacing: '0.06em' }}>
                CIPHER WATCH
              </span>
            </div>
            <span style={{ color: 'var(--text-dim)', fontSize: 10, letterSpacing: '0.1em' }}>
              THREAT INTELLIGENCE HUB // v1.0
            </span>
            <div style={{ display: 'flex', alignItems: 'center', gap: 5, padding: '2px 8px', border: '1px solid #FF2D5530', background: '#1A0008' }}>
              <span className="blink-live" style={{ width: 7, height: 7, borderRadius: '50%', background: '#FF2D55', display: 'inline-block' }} />
              <span style={{ color: '#FF2D55', fontSize: 10, letterSpacing: '0.15em' }}>LIVE</span>
            </div>
          </div>

          <div style={{ textAlign: 'right' }}>
            <div style={{ color: 'var(--text-dim)', fontSize: 10, letterSpacing: '0.1em' }}>LAST SYNC</div>
            <div style={{ color: 'var(--accent)', fontSize: 13 }}>
              {lastUpdated ? lastUpdated.toISOString().replace('T', ' ').slice(0, 19) + ' UTC' : '——'}
            </div>
          </div>
        </div>

        <div className="hr-rule-accent" />

        {/* Tab nav */}
        <div style={{ display: 'flex', gap: 0, marginTop: 2 }}>
          {TABS.map(tab => {
            const Icon    = tab.icon
            const isActive = activeTab === tab.id
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                style={{
                  display:        'flex',
                  alignItems:     'center',
                  gap:            6,
                  padding:        '7px 16px',
                  fontSize:       11,
                  letterSpacing:  '0.12em',
                  background:     isActive ? 'rgba(0,212,255,0.06)' : 'transparent',
                  color:          isActive ? 'var(--accent)' : 'var(--text-dim)',
                  border:         'none',
                  borderBottom:   isActive ? '2px solid var(--accent)' : '2px solid transparent',
                  cursor:         'pointer',
                  fontFamily:     "'Share Tech Mono', monospace",
                  transition:     'color 0.12s, background 0.12s',
                }}
              >
                <Icon size={11} />
                {tab.label}
              </button>
            )
          })}
        </div>

        {/* Feed-only: stats + search */}
        {activeTab === 'feed' && (
          <>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 1, padding: '10px 0 10px' }}>
              <StatCard label="TOTAL IOCS" value={counts.total}    accent="var(--accent)" />
              <StatCard label="CRITICAL"   value={counts.critical} accent="#FF2D55" />
              <StatCard label="HIGH"       value={counts.high}     accent="#FF5555" />
              <StatCard label="MEDIUM"     value={counts.medium}   accent="#FF9F1C" />
              <StatCard label="LOW"        value={counts.low}      accent="#22AAFF" />
            </div>

            <div className="hr-rule" />

            <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '8px 0' }}>
              <Search size={13} style={{ color: 'var(--text-dim)', flexShrink: 0 }} />
              <input
                className="search-input"
                style={{ flex: 1, padding: '5px 10px' }}
                placeholder="FILTER BY IOC / CVE / SOURCE / TYPE..."
                value={search}
                onChange={e => handleSearch(e.target.value)}
                spellCheck={false}
              />
              <div style={{ color: 'var(--text-dim)', fontSize: 11, letterSpacing: '0.08em', whiteSpace: 'nowrap' }}>
                {filtered.length.toLocaleString()} MATCH{filtered.length !== 1 ? 'ES' : ''}
              </div>
              <button
                onClick={() => fetchData(true)}
                className="copy-btn"
                style={{ display: 'flex', alignItems: 'center', gap: 5 }}
                title="Force refresh"
              >
                <RefreshCw size={10} style={{ ...(refreshing ? { animation: 'spin 0.8s linear infinite' } : {}) }} />
                SYNC
              </button>
            </div>
          </>
        )}
      </header>

      {/* ── Main content ────────────────────────────────────────────────── */}
      <main style={{ flex: 1, overflow: 'auto', position: 'relative' }}>

        {activeTab === 'developer' && <DeveloperPanel />}

        {activeTab === 'feed' && (
          <>
            {loading && (
              <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-dim)', letterSpacing: '0.2em' }}>
                RECEIVING INTELLIGENCE FEED...
              </div>
            )}

            {error && (
              <div style={{ padding: 20, margin: 16, border: '1px solid #FF2D5540', background: '#1A0008', color: '#FF2D55', fontSize: 12 }}>
                ⚠ FEED ERROR: {error} — DATA FROM CACHE
              </div>
            )}

            {!loading && (
              <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                <thead style={{ position: 'sticky', top: 0, zIndex: 10, background: 'var(--surface2)', borderBottom: '1px solid var(--border2)' }}>
                  <tr>
                    {['IOC', 'TYPE', 'SEVERITY', 'SOURCE', 'DESCRIPTION', 'TIMESTAMP', ''].map((h, i) => (
                      <th
                        key={i}
                        style={{
                          padding: '6px 10px',
                          textAlign: 'left',
                          color: 'var(--text-dim)',
                          fontSize: 10,
                          letterSpacing: '0.15em',
                          fontWeight: 400,
                          whiteSpace: 'nowrap',
                          borderRight: i < 6 ? '1px solid var(--border)' : 'none',
                        }}
                      >
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>

                <tbody>
                  {pageData.map((row, i) => {
                    const TypeIcon = TYPE_ICONS[row.type.toLowerCase()] ?? Link2
                    const srcColor = SOURCE_COLOR[row.source] ?? 'var(--text-dim)'
                    const isEven   = i % 2 === 0

                    return (
                      <tr
                        key={`${row.ioc}-${i}`}
                        className="threat-row fade-in-up"
                        style={{
                          background: isEven ? 'transparent' : 'rgba(0,0,0,0.15)',
                          borderBottom: '1px solid var(--border)',
                          animationDelay: `${Math.min(i * 12, 200)}ms`,
                        }}
                      >
                        <td style={{ padding: '5px 10px', borderRight: '1px solid var(--border)', maxWidth: 280 }}>
                          <span title={row.ioc} style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 12, color: 'var(--text-bright)', display: 'block', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 260 }}>
                            {truncate(row.ioc, 52)}
                          </span>
                        </td>

                        <td style={{ padding: '5px 10px', borderRight: '1px solid var(--border)', whiteSpace: 'nowrap' }}>
                          <span style={{ display: 'flex', alignItems: 'center', gap: 5, color: 'var(--text)', fontSize: 11 }}>
                            <TypeIcon size={11} style={{ color: 'var(--accent)', opacity: 0.7, flexShrink: 0 }} />
                            {row.type.toUpperCase()}
                          </span>
                        </td>

                        <td style={{ padding: '5px 10px', borderRight: '1px solid var(--border)' }}>
                          <SeverityBadge severity={row.severity} />
                        </td>

                        <td style={{ padding: '5px 10px', borderRight: '1px solid var(--border)', whiteSpace: 'nowrap' }}>
                          <span style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                            <span style={{ width: 6, height: 6, borderRadius: '50%', background: srcColor, display: 'inline-block', flexShrink: 0 }} />
                            <span style={{ color: srcColor, fontSize: 11 }}>{row.source}</span>
                          </span>
                        </td>

                        <td style={{ padding: '5px 10px', borderRight: '1px solid var(--border)', maxWidth: 320 }}>
                          <span title={row.description} style={{ color: 'var(--text)', fontSize: 11, display: 'block', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                            {truncate(row.description, 68)}
                          </span>
                        </td>

                        <td style={{ padding: '5px 10px', borderRight: '1px solid var(--border)', whiteSpace: 'nowrap' }}>
                          <span style={{ color: 'var(--text-dim)', fontSize: 11 }}>{formatTs(row.timestamp)}</span>
                        </td>

                        <td style={{ padding: '4px 10px' }}>
                          <CopyBtn text={row.ioc} />
                        </td>
                      </tr>
                    )
                  })}

                  {pageData.length === 0 && !loading && (
                    <tr>
                      <td colSpan={7} style={{ padding: 40, textAlign: 'center', color: 'var(--text-dim)', letterSpacing: '0.15em' }}>
                        NO MATCHES FOR &quot;{search}&quot;
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            )}
          </>
        )}
      </main>

      {/* ── Pagination (feed tab only) ────────────────────────────────── */}
      {activeTab === 'feed' && !loading && totalPages > 1 && (
        <footer style={{ borderTop: '1px solid var(--border)', background: 'var(--surface)', padding: '8px 20px', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <span style={{ color: 'var(--text-dim)', fontSize: 11, letterSpacing: '0.08em' }}>
            SHOWING {currentPage * PAGE_SIZE + 1}–{Math.min((currentPage + 1) * PAGE_SIZE, filtered.length)} OF {filtered.length.toLocaleString()}
          </span>

          <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
            <button className="pg-btn" onClick={() => setPage(0)} disabled={currentPage === 0}>«</button>
            <button className="pg-btn" onClick={() => setPage(p => p - 1)} disabled={currentPage === 0}>
              <ChevronLeft size={11} style={{ display: 'inline' }} /> PREV
            </button>

            {Array.from({ length: totalPages }, (_, i) => i)
              .filter(i => Math.abs(i - currentPage) <= 3 || i === 0 || i === totalPages - 1)
              .reduce<(number | '…')[]>((acc, i, idx, arr) => {
                if (idx > 0 && (i as number) - (arr[idx - 1] as number) > 1) acc.push('…')
                acc.push(i)
                return acc
              }, [])
              .map((item, idx) =>
                item === '…'
                  ? <span key={`e${idx}`} style={{ color: 'var(--text-dim)', padding: '0 4px', fontSize: 11 }}>…</span>
                  : <button key={item} className={`pg-btn ${item === currentPage ? 'active' : ''}`} onClick={() => setPage(item as number)}>
                      {(item as number) + 1}
                    </button>
              )
            }

            <button className="pg-btn" onClick={() => setPage(p => p + 1)} disabled={currentPage >= totalPages - 1}>
              NEXT <ChevronRight size={11} style={{ display: 'inline' }} />
            </button>
            <button className="pg-btn" onClick={() => setPage(totalPages - 1)} disabled={currentPage >= totalPages - 1}>»</button>
          </div>

          <span style={{ color: 'var(--text-dim)', fontSize: 11, letterSpacing: '0.08em' }}>
            PAGE {currentPage + 1} / {totalPages}
          </span>
        </footer>
      )}

      <style>{`
        @keyframes spin { to { transform: rotate(360deg); } }
      `}</style>
    </div>
  )
}
