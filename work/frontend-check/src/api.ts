/** Thin API boundary. Demo mode stays local until VITE_API_BASE_URL is configured. */
const API_BASE = import.meta.env.VITE_API_BASE_URL?.trim().replace(/\/+$/, '')
export const isApiConfigured = Boolean(API_BASE)

export type ApiHealth = { status: 'ok' | 'degraded'; mode: 'demo' | 'api'; ai_configured: boolean; external_intel_configured?: boolean }

async function requestJson<T>(path: string, init?: RequestInit): Promise<T> {
  if (!API_BASE) throw new Error('Backend API is not configured. Set VITE_API_BASE_URL to enable server-side requests.')
  let response: Response
  try {
    response = await fetch(`${API_BASE}${path}`, init)
  } catch {
    throw new Error(`Cannot reach the SentinelForge API at ${API_BASE}. Start the backend and check its CORS_ORIGINS setting. The local synthetic dashboard remains available.`)
  }
  if (!response.ok) {
    const detail = await response.json().catch(() => null) as { detail?: string } | null
    throw new Error(detail?.detail || `SentinelForge API request failed (${response.status} ${response.statusText}).`)
  }
  return response.json() as Promise<T>
}

export async function getApiHealth(): Promise<ApiHealth> {
  if (!API_BASE) return { status: 'ok', mode: 'demo', ai_configured: false, external_intel_configured: false }
  return requestJson<ApiHealth>('/health', { headers: { Accept: 'application/json' } })
}

type BrowserEvent = {
  time?: string; timestamp?: string; source?: string; source_ip?: string; destination?: string; destination_ip?: string
  user?: string; username?: string; action?: string; event_type?: string; outcome?: string; asset?: string
  destination_port?: number; detail?: string
}

function toApiEvent(input: unknown) {
  if (!input || typeof input !== 'object') throw new Error('Each event must be an object.')
  const event = input as BrowserEvent
  const timestamp = event.timestamp || event.time
  const sourceIp = event.source_ip || event.source
  if (!timestamp || Number.isNaN(Date.parse(timestamp))) throw new Error('Each event must include a valid timestamp or time.')
  if (!sourceIp) throw new Error('Each event must include a source IP address.')
  const action = event.action || event.event_type || 'unknown'
  const normalizedAction = action.toLowerCase()
  const inferredType = normalizedAction.includes('ssh') ? 'ssh'
    : normalizedAction.includes('login') || normalizedAction.includes('auth') ? 'authentication'
      : normalizedAction.includes('http') || normalizedAction.includes('request') ? 'http'
        : normalizedAction.includes('connection') || normalizedAction.includes('network') || normalizedAction.includes('tcp') ? 'network'
          : action
  const inferredOutcome = /fail|denied|blocked|reject/i.test(action) ? 'failed' : 'success'
  const destination = event.destination_ip || event.destination
  const candidatePort = event.destination_port ?? Number(event.asset?.match(/:(\d{1,5})$/)?.[1])
  const parsedPort = Number.isInteger(candidatePort) && candidatePort > 0 && candidatePort <= 65535 ? candidatePort : undefined
  return {
    timestamp: new Date(timestamp).toISOString(), source_ip: sourceIp,
    ...(destination && /^[\d.]+$|^[0-9a-f:]+$/i.test(destination) ? { destination_ip: destination } : {}),
    username: event.username || event.user || 'unknown', event_type: inferredType,
    outcome: event.outcome || inferredOutcome, ...(parsedPort ? { destination_port: parsedPort } : {}),
    asset: event.asset || 'unknown', metadata: event.detail ? { detail: event.detail } : {},
  }
}

export async function analyzeEvents(events: unknown[]) {
  const normalized = events.map(toApiEvent)
  return requestJson('/api/v1/detections/analyze', {
    method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, body: JSON.stringify({ events: normalized }),
  })
}
