'use client'

import { useState, useEffect, useCallback, useMemo } from 'react'
import {
  Search, Copy, Check, RefreshCw, Shield,
  Globe, Server, Hash, Bug, Link2, ChevronLeft, ChevronRight,
} from 'lucide-react'

// ─── Constants ────────────────────────────────────────────────────────────────

const RAW_URL =
  'https://raw.githubusercontent.com/MysticX662/ThreatMonitoring/main/api/v1/latest.json'

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

// ─── Small helpers ────────────────────────────────────────────────────────────

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

// ─── Severity Badge ───────────────────────────────────────────────────────────

function SeverityBadge({ severity }: { severity: string }) {
  const cfg = sevConfig(severity)
  return (
    <span className={cfg.cls}>
      <span
        className="blink-live"
        style={{ width: 6, height: 6, borderRadius: '50%', background: cfg.dot, display: 'inline-block', flexShrink: 0 }}
      />
      {cfg.label}
    </span>
  )
}

// ─── Copy Button ──────────────────────────────────────────────────────────────

function CopyBtn({ text }: { text: string }) {
  const [done, setDone] = useState(false)

  const copy = useCallback(() => {
    navigator.clipboard.writeText(text).then(() => {
      setDone(true)
      setTimeout(() => setDone(false), 1500)
    })
  }, [text])

  return (
    <button onClick={copy} className={`copy-btn ${done ? 'copied' : ''}`} title="Copy defanged IOC">
      {done
        ? <><Check size={10} style={{ display: 'inline', marginRight: 3 }} />COPIED</>
        : <><Copy size={10} style={{ display: 'inline', marginRight: 3 }} />COPY</>
      }
    </button>
  )
}

// ─── Stat Card ────────────────────────────────────────────────────────────────

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

// ─── Dashboard ────────────────────────────────────────────────────────────────

export default function Dashboard() {
  const [data, setData]               = useState<ThreatRecord[]>([])
  const [loading, setLoading]         = useState(true)
  const [error, setError]             = useState<string | null>(null)
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null)
  const [search, setSearch]           = useState('')
  const [page, setPage]               = useState(0)
  const [refreshing, setRefreshing]   = useState(false)

  const fetchData = useCallback(async (isManual = false) => {
    if (isManual) setRefreshing(true)
    try {
      const res = await fetch(RAW_URL + '?t=' + Date.now())
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

  // ── Derived ──────────────────────────────────────────────────────────────

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

  // ── Layout ───────────────────────────────────────────────────────────────

  return (
    <div style={{ position: 'relative', zIndex: 1, minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>

      {/* ── Top header ───────────────────────────────────────────────────── */}
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

        {/* Stats row */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 1, padding: '10px 0' }}>
          <StatCard label="TOTAL IOCS"   value={counts.total}    accent="var(--accent)" />
          <StatCard label="CRITICAL"     value={counts.critical} accent="#FF2D55" />
          <StatCard label="HIGH"         value={counts.high}     accent="#FF5555" />
          <StatCard label="MEDIUM"       value={counts.medium}   accent="#FF9F1C" />
          <StatCard label="LOW"          value={counts.low}      accent="#22AAFF" />
        </div>

        <div className="hr-rule" />

        {/* Search row */}
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
      </header>

      {/* ── Table area ───────────────────────────────────────────────────── */}
      <main style={{ flex: 1, overflow: 'auto', position: 'relative' }}>

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
            {/* Column headers */}
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

            {/* Data rows */}
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
                    {/* IOC */}
                    <td style={{ padding: '5px 10px', borderRight: '1px solid var(--border)', maxWidth: 280 }}>
                      <span
                        title={row.ioc}
                        style={{
                          fontFamily: "'Share Tech Mono', monospace",
                          fontSize: 12,
                          color: 'var(--text-bright)',
                          display: 'block',
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                          whiteSpace: 'nowrap',
                          maxWidth: 260,
                        }}
                      >
                        {truncate(row.ioc, 52)}
                      </span>
                    </td>

                    {/* Type */}
                    <td style={{ padding: '5px 10px', borderRight: '1px solid var(--border)', whiteSpace: 'nowrap' }}>
                      <span style={{ display: 'flex', alignItems: 'center', gap: 5, color: 'var(--text)', fontSize: 11 }}>
                        <TypeIcon size={11} style={{ color: 'var(--accent)', opacity: 0.7, flexShrink: 0 }} />
                        {row.type.toUpperCase()}
                      </span>
                    </td>

                    {/* Severity */}
                    <td style={{ padding: '5px 10px', borderRight: '1px solid var(--border)' }}>
                      <SeverityBadge severity={row.severity} />
                    </td>

                    {/* Source */}
                    <td style={{ padding: '5px 10px', borderRight: '1px solid var(--border)', whiteSpace: 'nowrap' }}>
                      <span style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                        <span style={{ width: 6, height: 6, borderRadius: '50%', background: srcColor, display: 'inline-block', flexShrink: 0 }} />
                        <span style={{ color: srcColor, fontSize: 11 }}>{row.source}</span>
                      </span>
                    </td>

                    {/* Description */}
                    <td style={{ padding: '5px 10px', borderRight: '1px solid var(--border)', maxWidth: 320 }}>
                      <span
                        title={row.description}
                        style={{ color: 'var(--text)', fontSize: 11, display: 'block', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}
                      >
                        {truncate(row.description, 68)}
                      </span>
                    </td>

                    {/* Timestamp */}
                    <td style={{ padding: '5px 10px', borderRight: '1px solid var(--border)', whiteSpace: 'nowrap' }}>
                      <span style={{ color: 'var(--text-dim)', fontSize: 11 }}>{formatTs(row.timestamp)}</span>
                    </td>

                    {/* Copy */}
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
      </main>

      {/* ── Pagination footer ─────────────────────────────────────────────── */}
      {!loading && totalPages > 1 && (
        <footer style={{ borderTop: '1px solid var(--border)', background: 'var(--surface)', padding: '8px 20px', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <span style={{ color: 'var(--text-dim)', fontSize: 11, letterSpacing: '0.08em' }}>
            SHOWING {currentPage * PAGE_SIZE + 1}–{Math.min((currentPage + 1) * PAGE_SIZE, filtered.length)} OF {filtered.length.toLocaleString()}
          </span>

          <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
            <button className="pg-btn" onClick={() => setPage(0)} disabled={currentPage === 0}>«</button>
            <button className="pg-btn" onClick={() => setPage(p => p - 1)} disabled={currentPage === 0}>
              <ChevronLeft size={11} style={{ display: 'inline' }} /> PREV
            </button>

            {/* Page number pills — show up to 7 around current */}
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
