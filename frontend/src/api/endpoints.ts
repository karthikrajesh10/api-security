import api from './client'

// ── Traffic ───────────────────────────────────────────────
export const getRecentTraffic = (limit = 50) =>
  api.get(`/api/traffic/recent?limit=${limit}`)

export const getTrafficStats = () =>
  api.get('/api/traffic/stats')

export const ingestTraffic = (payload: object) =>
  api.post('/api/traffic/ingest', payload)

// ── Anomaly ───────────────────────────────────────────────
export const getFlaggedRequests = () =>
  api.get('/api/anomaly/flagged')

export const trainModel = () =>
  api.post('/api/anomaly/train')

export const analyzeAll = () =>
  api.post('/api/anomaly/analyze-all')

export const analyzeLog = (id: string) =>
  api.post(`/api/anomaly/analyze/${id}`)

// ── Schema ────────────────────────────────────────────────
export const getAllSchemas = () =>
  api.get('/api/schema/all')

// ── Rules ─────────────────────────────────────────────────
export const reloadRules = () =>
  api.post('/api/rules/reload')

export const viewRules = () =>
  api.get('/api/rules/view')

// ── Health ────────────────────────────────────────────────
export const getHealth = () =>
  api.get('/health')


// ── Report ───────────────────────────────────────────────

export const downloadReport = () =>
  api.get('/api/report/download', { responseType: 'blob' })