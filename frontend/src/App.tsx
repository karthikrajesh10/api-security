// import { useState } from 'react'
// import reactLogo from './assets/react.svg'
// import viteLogo from './assets/vite.svg'
// import heroImg from './assets/hero.png'
// import './App.css'

// function App() {
//   const [count, setCount] = useState(0)

//   return (
//     <>
//       <section id="center">
//         <div className="hero">
//           <img src={heroImg} className="base" width="170" height="179" alt="" />
//           <img src={reactLogo} className="framework" alt="React logo" />
//           <img src={viteLogo} className="vite" alt="Vite logo" />
//         </div>
//         <div>
//           <h1>Get started</h1>
//           <p>
//             Edit <code>src/App.tsx</code> and save to test <code>HMR</code>
//           </p>
//         </div>
//         <button
//           type="button"
//           className="counter"
//           onClick={() => setCount((count) => count + 1)}
//         >
//           Count is {count}
//         </button>
//       </section>

//       <div className="ticks"></div>

//       <section id="next-steps">
//         <div id="docs">
//           <svg className="icon" role="presentation" aria-hidden="true">
//             <use href="/icons.svg#documentation-icon"></use>
//           </svg>
//           <h2>Documentation</h2>
//           <p>Your questions, answered</p>
//           <ul>
//             <li>
//               <a href="https://vite.dev/" target="_blank">
//                 <img className="logo" src={viteLogo} alt="" />
//                 Explore Vite
//               </a>
//             </li>
//             <li>
//               <a href="https://react.dev/" target="_blank">
//                 <img className="button-icon" src={reactLogo} alt="" />
//                 Learn more
//               </a>
//             </li>
//           </ul>
//         </div>
//         <div id="social">
//           <svg className="icon" role="presentation" aria-hidden="true">
//             <use href="/icons.svg#social-icon"></use>
//           </svg>
//           <h2>Connect with us</h2>
//           <p>Join the Vite community</p>
//           <ul>
//             <li>
//               <a href="https://github.com/vitejs/vite" target="_blank">
//                 <svg
//                   className="button-icon"
//                   role="presentation"
//                   aria-hidden="true"
//                 >
//                   <use href="/icons.svg#github-icon"></use>
//                 </svg>
//                 GitHub
//               </a>
//             </li>
//             <li>
//               <a href="https://chat.vite.dev/" target="_blank">
//                 <svg
//                   className="button-icon"
//                   role="presentation"
//                   aria-hidden="true"
//                 >
//                   <use href="/icons.svg#discord-icon"></use>
//                 </svg>
//                 Discord
//               </a>
//             </li>
//             <li>
//               <a href="https://x.com/vite_js" target="_blank">
//                 <svg
//                   className="button-icon"
//                   role="presentation"
//                   aria-hidden="true"
//                 >
//                   <use href="/icons.svg#x-icon"></use>
//                 </svg>
//                 X.com
//               </a>
//             </li>
//             <li>
//               <a href="https://bsky.app/profile/vite.dev" target="_blank">
//                 <svg
//                   className="button-icon"
//                   role="presentation"
//                   aria-hidden="true"
//                 >
//                   <use href="/icons.svg#bluesky-icon"></use>
//                 </svg>
//                 Bluesky
//               </a>
//             </li>
//           </ul>
//         </div>
//       </section>

//       <div className="ticks"></div>
//       <section id="spacer"></section>
//     </>
//   )
// }

// export default App


import { useState, useEffect, useCallback } from 'react'
import {
  AreaChart, Area, BarChart, Bar,
  XAxis, YAxis, Tooltip, ResponsiveContainer, Cell
} from 'recharts'
import {
  Shield, AlertTriangle, Activity, Database,
  RefreshCw, Cpu, ChevronRight, Circle,
  BookOpen, Zap, Terminal,FileDown
} from 'lucide-react'
import {
  getTrafficStats, getRecentTraffic, getFlaggedRequests,
  getAllSchemas, trainModel, reloadRules, analyzeAll, analyzeLog,getHealth,downloadReport
} from './api/endpoints'

import { formatDistanceToNow } from 'date-fns'
import './App.css'

// ── Types ─────────────────────────────────────────────────────────────────────

interface Stats {
  total_requests: number
  flagged_count: number
  by_risk_level: Record<string, number>
}

interface TrafficLog {
  id: string
  method: string
  endpoint: string
  status_code: number
  latency_ms: number
  risk_level: string
  anomaly_score: number
  is_flagged: boolean
  source_ip: string
  timestamp: string
}

interface FlaggedLog {
  id: string
  method: string
  endpoint: string
  status_code: number
  latency_ms: number
  anomaly_score: number
  risk_level: string
  source_ip: string
  timestamp: string
}

interface Schema {
  endpoint: string
  method: string
  sample_count: number
  is_stable: boolean
  avg_latency_ms: number
  status_codes: Record<string, number>
  request_fields: Record<string, { required: boolean; frequency: number }>
}

interface Health {
  status: string
  model_provider: string
  ml_available: boolean
  env: string
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const RISK_COLOR: Record<string, string> = {
  high:   'var(--red)',
  medium: 'var(--yellow)',
  low:    'var(--green)',
}

const METHOD_COLOR: Record<string, string> = {
  GET:    '#388bfd',
  POST:   '#3fb950',
  PUT:    '#d29922',
  DELETE: '#f85149',
  PATCH:  '#ab7df8',
}

const riskColor = (r: string) => RISK_COLOR[r] ?? 'var(--text-muted)'
const methodColor = (m: string) => METHOD_COLOR[m] ?? 'var(--text-muted)'

// ── Sub-components ────────────────────────────────────────────────────────────

function StatCard({ icon: Icon, label, value, sub, color = 'var(--blue)' }: {
  icon: React.ElementType
  label: string
  value: string | number
  sub?: string
  color?: string
}) {
  return (
    <div className="stat-card">
      <div className="stat-icon" style={{ color }}>
        <Icon size={18} />
      </div>
      <div className="stat-body">
        <div className="stat-label">{label}</div>
        <div className="stat-value" style={{ color }}>{value}</div>
        {sub && <div className="stat-sub">{sub}</div>}
      </div>
    </div>
  )
}

function RiskBadge({ level }: { level: string }) {
  return (
    <span className="risk-badge" style={{
      color: riskColor(level),
      background: level === 'high' ? 'var(--red-dim)'
                : level === 'medium' ? 'var(--yellow-dim)'
                : 'var(--green-dim)',
      border: `1px solid ${riskColor(level)}40`,
    }}>
      <Circle size={5} fill={riskColor(level)} style={{ flexShrink: 0 }} />
      {level}
    </span>
  )
}

function MethodTag({ method }: { method: string }) {
  return (
    <span className="method-tag" style={{
      color: methodColor(method),
      border: `1px solid ${methodColor(method)}40`,
      background: `${methodColor(method)}15`,
    }}>
      {method}
    </span>
  )
}

function ActionBtn({ onClick, loading, icon: Icon, label, variant = 'default' }: {
  onClick: () => void
  loading?: boolean
  icon: React.ElementType
  label: string
  variant?: 'default' | 'danger' | 'success'
}) {
  const colors = {
    default: 'var(--blue)',
    danger:  'var(--red)',
    success: 'var(--green)',
  }
  const c = colors[variant]
  return (
    <button
      className="action-btn"
      onClick={onClick}
      disabled={loading}
      style={{ borderColor: `${c}50`, color: c }}
    >
      <Icon size={13} className={loading ? 'spin' : ''} />
      {label}
    </button>
  )
}

// ── Main App ──────────────────────────────────────────────────────────────────

export default function App() {
  const [tab, setTab] = useState<'overview' | 'traffic' | 'flagged' | 'schemas'>('overview')
  const [stats, setStats] = useState<Stats | null>(null)
  const [recent, setRecent] = useState<TrafficLog[]>([])
  const [flagged, setFlagged] = useState<FlaggedLog[]>([])
  const [schemas, setSchemas] = useState<Schema[]>([])
  const [health, setHealth] = useState<Health | null>(null)
  const [loading, setLoading] = useState(false)
  const [actionMsg, setActionMsg] = useState('')
  const [lastUpdated, setLastUpdated] = useState<Date>(new Date())
  const [expandedLog, setExpandedLog] = useState<string | null>(null)
  const [logDetail, setLogDetail] = useState<Record<string, any>>({})
  const [analyzingId, setAnalyzingId] = useState<string | null>(null)

  const msg = (text: string) => {
    setActionMsg(text)
    setTimeout(() => setActionMsg(''), 4000)
  }

  const fetchAll = useCallback(async () => {
    try {
      const [s, r, f, sc, h] = await Promise.all([
        getTrafficStats(),
        getRecentTraffic(100),
        getFlaggedRequests(),
        getAllSchemas(),
        getHealth(),
      ])
      setStats(s.data)
      setRecent(r.data)
      setFlagged(f.data)
      setSchemas(sc.data)
      setHealth(h.data)
      setLastUpdated(new Date())
    } catch (e) {
      msg('⚠ Could not reach backend — is uvicorn running?')
    }
  }, [])

  useEffect(() => {
    fetchAll()
    const t = setInterval(fetchAll, 15000)
    return () => clearInterval(t)
  }, [fetchAll])

  // ── Action handlers ──────────────────────────────────────────────────────

  const handleTrain = async () => {
    setLoading(true)
    try {
      const r = await trainModel()
      msg(`✓ Model trained on ${r.data.samples_used} samples`)
    } catch { msg('✗ Training failed — need 20+ traffic logs') }
    setLoading(false)
  }

  const handleReload = async () => {
    setLoading(true)
    try {
      const r = await reloadRules()
      msg(`✓ Rules reloaded — ${r.data.schemas_seeded} schemas seeded, model retrained`)
      fetchAll()
    } catch { msg('✗ Rules reload failed') }
    setLoading(false)
  }
  const handleAnalyzeLog = async (id: string) => {
      if (logDetail[id]) {
        setExpandedLog(expandedLog === id ? null : id)
        return
      }
      setAnalyzingId(id)
      setExpandedLog(id)
      try {
        const r = await analyzeLog(id)
        setLogDetail(prev => ({ ...prev, [id]: r.data }))
      } catch {
        msg('✗ Could not analyze log')
        setExpandedLog(null)
      }
      setAnalyzingId(null)
    }

  const handleAnalyzeAll = async () => {
    setLoading(true)
    try {
      const r = await analyzeAll()
      msg(`✓ Scored ${r.data.total} logs — High:${r.data.high} Med:${r.data.medium} Low:${r.data.low}`)
      fetchAll()
    } catch { msg('✗ Analysis failed') }
    setLoading(false)
  }
  const handleDownloadReport = async () => {
    setLoading(true)
    try {
      const r = await downloadReport()
      const url = window.URL.createObjectURL(new Blob([r.data]))
      const a = document.createElement('a')
      a.href = url
      a.download = `APISec_Report_${new Date().toISOString().slice(0,10)}.pdf`
      a.click()
      window.URL.revokeObjectURL(url)
      msg('✓ Report downloaded')
    } catch { msg('✗ Report generation failed') }
    setLoading(false)
  }

  // ── Chart data ───────────────────────────────────────────────────────────

  const riskChartData = stats ? [
    { name: 'HIGH',   value: stats.by_risk_level?.high   ?? 0, fill: 'var(--red)' },
    { name: 'MEDIUM', value: stats.by_risk_level?.medium ?? 0, fill: 'var(--yellow)' },
    { name: 'LOW',    value: stats.by_risk_level?.low    ?? 0, fill: 'var(--green)' },
  ] : []

  const latencyData = recent.slice(0, 40).map((l, i) => ({
    i,
    ms: l.latency_ms ?? 0,
    risk: l.risk_level,
  }))

  const endpointHeatmap = recent.reduce<Record<string, { total: number; flagged: number }>>((acc, l) => {
    const k = `${l.method} ${l.endpoint}`
    if (!acc[k]) acc[k] = { total: 0, flagged: 0 }
    acc[k].total++
    if (l.is_flagged) acc[k].flagged++
    return acc
  }, {})

  const heatmapData = Object.entries(endpointHeatmap)
    .map(([ep, d]) => ({ ep, ...d, ratio: d.flagged / d.total }))
    .sort((a, b) => b.flagged - a.flagged)
    .slice(0, 8)

  // ── Render ───────────────────────────────────────────────────────────────

  return (
    <div className="app">

      {/* ── Sidebar ── */}
      <aside className="sidebar">
        <div className="sidebar-logo">
          <Shield size={20} style={{ color: 'var(--cyan)' }} />
          <span>APISec</span>
        </div>

        <nav className="sidebar-nav">
          {([
            ['overview', Activity,   'Overview'],
            ['traffic',  Terminal,   'Traffic'],
            ['flagged',  AlertTriangle, 'Flagged'],
            ['schemas',  BookOpen,   'Schemas'],
          ] as const).map(([id, Icon, label]) => (
            <button
              key={id}
              className={`nav-item ${tab === id ? 'active' : ''}`}
              onClick={() => setTab(id)}
            >
              <Icon size={15} />
              {label}
              {id === 'flagged' && flagged.length > 0 && (
                <span className="nav-badge">{flagged.length}</span>
              )}
            </button>
          ))}
        </nav>

        <div className="sidebar-actions">
          <div className="sidebar-section-label">Actions</div>
          <ActionBtn onClick={handleReload}     loading={loading} icon={RefreshCw}  label="Reload Rules"   variant="default" />
          <ActionBtn onClick={handleTrain}      loading={loading} icon={Cpu}        label="Train Model"    variant="success" />
          <ActionBtn onClick={handleAnalyzeAll} loading={loading} icon={Zap}        label="Score All Logs" variant="default" />
          <ActionBtn onClick={fetchAll}         loading={loading} icon={RefreshCw}  label="Refresh Data"   variant="default" />
          <ActionBtn onClick={handleDownloadReport} loading={loading} icon={FileDown}   label="Download Report" variant="default" />
        </div>

        <div className="sidebar-footer">
          {health && (
            <>
              <div className="health-row">
                <Circle size={6} fill={health.ml_available ? 'var(--green)' : 'var(--red)'}
                  style={{ color: health.ml_available ? 'var(--green)' : 'var(--red)' }} />
                <span>ML {health.ml_available ? 'online' : 'offline'}</span>
              </div>
              <div className="health-row">
                <Circle size={6} fill="var(--green)" style={{ color: 'var(--green)' }} />
                <span>{health.model_provider}</span>
              </div>
            </>
          )}
          <div className="health-row" style={{ color: 'var(--text-dim)', marginTop: 4 }}>
            Updated {formatDistanceToNow(lastUpdated, { addSuffix: true })}
          </div>
        </div>
      </aside>

      {/* ── Main ── */}
      <main className="main">

        {/* Header */}
        <header className="topbar">
          <div className="topbar-title">
            <span style={{ color: 'var(--text-muted)' }}>APISec /</span>{' '}
            {{ overview: 'Overview', traffic: 'Live Traffic', flagged: 'Flagged Requests', schemas: 'Learned Schemas' }[tab]}
          </div>
          {actionMsg && <div className="action-msg">{actionMsg}</div>}
        </header>

        {/* ── OVERVIEW TAB ── */}
        {tab === 'overview' && (
          <div className="tab-content">

            {/* Stat cards */}
            <div className="stats-row">
              <StatCard icon={Activity}      label="Total Requests"   value={stats?.total_requests ?? '—'}  color="var(--blue)" />
              <StatCard icon={AlertTriangle} label="Flagged"          value={stats?.flagged_count ?? '—'}   color="var(--red)"
                sub={stats ? `${((stats.flagged_count / stats.total_requests) * 100).toFixed(1)}% of traffic` : ''} />
              <StatCard icon={Shield}        label="High Risk"        value={stats?.by_risk_level?.high ?? 0}   color="var(--red)" />
              <StatCard icon={Database}      label="Schemas Learned"  value={schemas.length}                color="var(--cyan)"
                sub={`${schemas.filter(s => s.is_stable).length} stable`} />
            </div>

            {/* Charts row */}
            <div className="charts-row">

              {/* Latency timeline */}
              <div className="chart-card wide">
                <div className="chart-title">Latency Timeline <span>(last 40 requests)</span></div>
                <ResponsiveContainer width="100%" height={180}>
                  <AreaChart data={latencyData} margin={{ top: 8, right: 8, left: -20, bottom: 0 }}>
                    <defs>
                      <linearGradient id="latGrad" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%"  stopColor="var(--blue)" stopOpacity={0.3} />
                        <stop offset="95%" stopColor="var(--blue)" stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <XAxis dataKey="i" hide />
                    <YAxis tick={{ fill: 'var(--text-dim)', fontSize: 10 }} />
                    <Tooltip
                      contentStyle={{ background: 'var(--bg-elevated)', border: '1px solid var(--border)', borderRadius: 6, fontFamily: 'var(--font-mono)', fontSize: 11 }}
                      labelFormatter={() => ''}
                      formatter={(v: number) => [`${v}ms`, 'latency']}
                    />
                    <Area type="monotone" dataKey="ms" stroke="var(--blue)" strokeWidth={1.5} fill="url(#latGrad)" dot={false} />
                  </AreaChart>
                </ResponsiveContainer>
              </div>

              {/* Risk breakdown */}
              <div className="chart-card narrow">
                <div className="chart-title">Risk Breakdown</div>
                <ResponsiveContainer width="100%" height={180}>
                  <BarChart data={riskChartData} margin={{ top: 8, right: 8, left: -20, bottom: 0 }}>
                    <XAxis dataKey="name" tick={{ fill: 'var(--text-muted)', fontSize: 10 }} />
                    <YAxis tick={{ fill: 'var(--text-dim)', fontSize: 10 }} />
                    <Tooltip
                      contentStyle={{ background: 'var(--bg-elevated)', border: '1px solid var(--border)', borderRadius: 6, fontFamily: 'var(--font-mono)', fontSize: 11 }}
                      cursor={{ fill: 'var(--bg-elevated)' }}
                    />
                    <Bar dataKey="value" radius={[3, 3, 0, 0]}>
                      {riskChartData.map((entry, i) => <Cell key={i} fill={entry.fill} />)}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>

            {/* Endpoint heatmap */}
            <div className="chart-card" style={{ marginTop: 16 }}>
              <div className="chart-title">Endpoint Risk Heatmap <span>(top 8 by flagged count)</span></div>
              <div className="heatmap">
                {heatmapData.map((row, i) => (
                  <div key={i} className="heatmap-row">
                    <div className="heatmap-ep">{row.ep}</div>
                    <div className="heatmap-bar-wrap">
                      <div className="heatmap-bar" style={{
                        width: `${Math.max(row.ratio * 100, 2)}%`,
                        background: row.ratio >= 0.5 ? 'var(--red)' : row.ratio > 0.2 ? 'var(--yellow)' : 'var(--green)',
                      }} />
                    </div>
                    <div className="heatmap-count" style={{ color: row.flagged > 0 ? 'var(--red)' : 'var(--text-muted)' }}>
                      {row.flagged}/{row.total}
                    </div>
                  </div>
                ))}
                {heatmapData.length === 0 && <div className="empty">No traffic data yet — run seed.py</div>}
              </div>
            </div>

          </div>
        )}

        {/* ── TRAFFIC TAB ── */}
        {tab === 'traffic' && (
          <div className="tab-content">
            <div className="table-card">
              <div className="table-header">
                <span>Recent Traffic <span style={{ color: 'var(--text-muted)' }}>({recent.length} records)</span></span>
              </div>
              <div className="table-wrap">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Method</th>
                      <th>Endpoint</th>
                      <th>Status</th>
                      <th>Latency</th>
                      <th>Risk</th>
                      <th>Score</th>
                      <th>Source IP</th>
                      <th>Time</th>
                    </tr>
                  </thead>
                  <tbody>
                    {recent.map(log => (
                      <tr key={log.id} className={log.is_flagged ? 'flagged-row' : ''}>
                        <td><MethodTag method={log.method} /></td>
                        <td className="endpoint-cell">{log.endpoint}</td>
                        <td style={{ color: log.status_code >= 500 ? 'var(--red)' : log.status_code >= 400 ? 'var(--yellow)' : 'var(--green)' }}>
                          {log.status_code}
                        </td>
                        <td style={{ color: log.latency_ms > 1000 ? 'var(--red)' : 'var(--text-muted)' }}>
                          {log.latency_ms}ms
                        </td>
                        <td><RiskBadge level={log.risk_level} /></td>
                        <td style={{ color: 'var(--text-muted)' }}>
                          {log.anomaly_score != null ? log.anomaly_score.toFixed(3) : '—'}
                        </td>
                        <td style={{ color: 'var(--text-muted)' }}>{log.source_ip}</td>
                        <td style={{ color: 'var(--text-dim)' }}>
                          {log.timestamp ? formatDistanceToNow(new Date(log.timestamp), { addSuffix: true }) : '—'}
                        </td>
                      </tr>
                    ))}
                    {recent.length === 0 && (
                      <tr><td colSpan={8} className="empty">No traffic yet — run seed.py or ingest some requests</td></tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {/* ── FLAGGED TAB ── */}
        {tab === 'flagged' && (
          <div className="tab-content">
            <div className="table-card">
              <div className="table-header">
                <span>
                  Flagged Requests
                  <span style={{ color: 'var(--red)', marginLeft: 8 }}>{flagged.length} alerts</span>
                </span>
              </div>
              <div className="table-wrap">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Method</th>
                      <th>Endpoint</th>
                      <th>Status</th>
                      <th>Score</th>
                      <th>Latency</th>
                      <th>Source IP</th>
                      <th>Time</th>
                      <th></th>
                    </tr>
                  </thead>
                  <tbody>
                    {flagged.map(log => (
                      <>
                        <tr
                          key={log.id}
                          className="flagged-row clickable-row"
                          onClick={() => handleAnalyzeLog(log.id)}
                        >
                          <td><MethodTag method={log.method} /></td>
                          <td className="endpoint-cell">{log.endpoint}</td>
                          <td style={{ color: log.status_code >= 500 ? 'var(--red)' : log.status_code >= 400 ? 'var(--yellow)' : 'var(--text)' }}>
                            {log.status_code}
                          </td>
                          <td>
                            <span style={{ color: 'var(--red)', fontWeight: 600 }}>
                              {log.anomaly_score?.toFixed(3) ?? '—'}
                            </span>
                          </td>
                          <td style={{ color: 'var(--text-muted)' }}>{log.latency_ms}ms</td>
                          <td style={{ color: 'var(--yellow)' }}>{log.source_ip}</td>
                          <td style={{ color: 'var(--text-dim)' }}>
                            {log.timestamp ? formatDistanceToNow(new Date(log.timestamp), { addSuffix: true }) : '—'}
                          </td>
                          <td>
                            <ChevronRight
                              size={13}
                              style={{
                                color: 'var(--text-dim)',
                                transform: expandedLog === log.id ? 'rotate(90deg)' : 'none',
                                transition: 'transform 0.2s',
                              }}
                            />
                          </td>
                        </tr>

                        {/* Expanded detail row */}
                        {expandedLog === log.id && (
                          <tr key={`${log.id}-detail`} className="detail-row">
                            <td colSpan={8}>

                              {/* ── Analyzing spinner ── */}
                              {analyzingId === log.id && (
                                <div className="analyzing-panel">
                                  <div className="analyzing-inner">
                                    <div className="analyzing-spinner">
                                      <div className="spinner-ring" />
                                      <Shield size={16} style={{ color: 'var(--cyan)' }} />
                                    </div>
                                    <div className="analyzing-text">
                                      <span className="analyzing-title">Analyzing request...</span>
                                      <span className="analyzing-sub">
                                        Running Isolation Forest · Checking rules · Generating explanation
                                      </span>
                                    </div>
                                  </div>
                                </div>
                              )}

                              {/* ── Full detail panel ── */}
                              {!analyzingId && logDetail[log.id] && (
                                <div className="detail-panel">

                                  {/* Score + risk */}
                                  <div className="detail-scores">
                                    <div className="detail-score-item">
                                      <span>Anomaly Score</span>
                                      <strong style={{ color: 'var(--red)' }}>
                                        {logDetail[log.id].anomaly_score}
                                      </strong>
                                    </div>
                                    <div className="detail-score-item">
                                      <span>Risk Level</span>
                                      <RiskBadge level={logDetail[log.id].risk_level} />
                                    </div>
                                    <div className="detail-score-item">
                                      <span>Model Trained</span>
                                      <strong style={{ color: logDetail[log.id].model_trained ? 'var(--green)' : 'var(--red)' }}>
                                        {logDetail[log.id].model_trained ? 'Yes' : 'No'}
                                      </strong>
                                    </div>
                                    <div className="detail-score-item">
                                      <span>Explanation Source</span>
                                      <strong style={{ color: 'var(--cyan)' }}>
                                        {logDetail[log.id].explanation_source ?? '—'}
                                      </strong>
                                    </div>
                                  </div>

                                  {/* Deviations */}
                                  {logDetail[log.id].deviations?.length > 0 && (
                                    <div className="detail-section">
                                      <div className="detail-section-label">
                                        Rule Violations & Deviations
                                      </div>
                                      <div className="deviations-list">
                                        {logDetail[log.id].deviations.map((d: any, i: number) => (
                                          <div key={i} className="deviation-item">
                                            <span
                                              className="deviation-severity"
                                              style={{
                                                color: d.severity === 'high' ? 'var(--red)'
                                                    : d.severity === 'medium' ? 'var(--yellow)'
                                                    : 'var(--green)',
                                                borderColor: d.severity === 'high' ? 'var(--red)'
                                                          : d.severity === 'medium' ? 'var(--yellow)'
                                                          : 'var(--green)',
                                              }}
                                            >
                                              {d.severity}
                                            </span>
                                            <span className="deviation-type">{d.type}</span>
                                            <span className="deviation-detail">{d.detail}</span>
                                            {d.source && (
                                              <span className="deviation-source">{d.source}</span>
                                            )}
                                          </div>
                                        ))}
                                      </div>
                                    </div>
                                  )}

                                  {/* Explanation */}
                                  {logDetail[log.id].explanation && (
                                    <div className="detail-section">
                                      <div className="detail-section-label">
                                        {logDetail[log.id].explanation_source === 'llm'
                                          ? '🤖 LLM Analysis'
                                          : '⚙ Rules Engine Analysis'}
                                      </div>
                                      <div className="explanation-text">
                                        {logDetail[log.id].explanation}
                                      </div>
                                    </div>
                                  )}

                                </div>
                              )}

                            </td>
                          </tr>
                        )}
                      </>
                    ))}
                    {flagged.length === 0 && (
                      <tr>
                        <td colSpan={8} className="empty">
                          No flagged requests — system is clean ✓
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {/* ── SCHEMAS TAB ── */}
        {tab === 'schemas' && (
          <div className="tab-content">
            <div className="schemas-grid">
              {schemas.map((s, i) => (
                <div key={i} className="schema-card">
                  <div className="schema-header">
                    <MethodTag method={s.method} />
                    <span className="schema-path">{s.endpoint}</span>
                    <span className={`schema-stable ${s.is_stable ? 'yes' : 'no'}`}>
                      {s.is_stable ? '✓ stable' : '⏳ learning'}
                    </span>
                  </div>
                  <div className="schema-stats">
                    <div className="schema-stat">
                      <span>Samples</span>
                      <strong>{s.sample_count}</strong>
                    </div>
                    <div className="schema-stat">
                      <span>Avg latency</span>
                      <strong>{s.avg_latency_ms?.toFixed(0)}ms</strong>
                    </div>
                    <div className="schema-stat">
                      <span>Status codes</span>
                      <strong>{Object.keys(s.status_codes ?? {}).join(', ')}</strong>
                    </div>
                  </div>
                  {Object.keys(s.request_fields ?? {}).length > 0 && (
                    <div className="schema-fields">
                      <div className="schema-fields-label">Request fields</div>
                      {Object.entries(s.request_fields).map(([field, meta]) => (
                        <div key={field} className="schema-field">
                          <span style={{ color: meta.required ? 'var(--cyan)' : 'var(--text-muted)' }}>
                            {field}
                          </span>
                          <span style={{ color: 'var(--text-dim)' }}>
                            {(meta.frequency * 100).toFixed(0)}%
                            {meta.required && ' · required'}
                          </span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              ))}
              {schemas.length === 0 && (
                <div className="empty" style={{ gridColumn: '1/-1' }}>
                  No schemas yet — ingest some traffic or reload rules
                </div>
              )}
            </div>
          </div>
        )}

      </main>
    </div>
  )
}