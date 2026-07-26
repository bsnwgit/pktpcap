/**
 * pktPCAP API client — typed fetch wrappers.
 * Access token is stored in memory (not localStorage).
 */

let _accessToken: string | null = null
let _tokenRole: string | null = null

export function setToken(token: string, role: string) {
  _accessToken = token
  _tokenRole = role
}

export function clearToken() {
  _accessToken = null
  _tokenRole = null
}

export function getRole(): string | null {
  return _tokenRole
}

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options.headers as Record<string, string>),
  }
  if (_accessToken) headers['Authorization'] = `Bearer ${_accessToken}`

  const res = await fetch(`/api${path}`, { ...options, headers })

  if (res.status === 401) {
    const refreshed = await tryRefresh()
    if (refreshed) {
      headers['Authorization'] = `Bearer ${_accessToken}`
      const retry = await fetch(`/api${path}`, { ...options, headers })
      if (!retry.ok) throw new Error(`${retry.status} ${retry.statusText}`)
      return retry.status === 204 ? (null as T) : retry.json()
    }
    clearToken()
    window.location.href = '/login'
    throw new Error('Session expired')
  }

  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }))
    throw new Error(err.detail || res.statusText)
  }

  if (res.status === 204) return null as T
  return res.json()
}

async function authedBlobFetch(path: string): Promise<Blob> {
  const headers: Record<string, string> = {}
  if (_accessToken) headers['Authorization'] = `Bearer ${_accessToken}`
  const res = await fetch(`/api${path}`, { headers })
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }))
    throw new Error(err.detail || res.statusText)
  }
  return res.blob()
}

/** Push an already-fetched Blob through the browser's normal save-file flow. */
export function triggerBrowserDownload(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  URL.revokeObjectURL(url)
}

async function tryRefresh(): Promise<boolean> {
  try {
    const res = await fetch('/api/auth/refresh', { method: 'POST', credentials: 'include' })
    if (!res.ok) return false
    const data = await res.json()
    setToken(data.access_token, data.role)
    return true
  } catch {
    return false
  }
}

export const api = {
  // -- Auth --------------------------------------------------------------------
  // Deliberately bypasses request() — a bad password here is a normal login
  // failure, not an expired session, and must not trigger the 401 handler's
  // refresh-then-redirect-to-/login flow (that would hard-reload the login
  // page itself before the error message is even visible).
  login: async (username: string, password: string) => {
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    })
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }))
      throw new Error(err.detail || res.statusText)
    }
    return res.json() as Promise<{ access_token: string; role: string }>
  },
  // Deliberately bypasses request() for the same reason as login() above.
  autoLogin: async () => {
    const res = await fetch('/api/auth/auto-login', { method: 'POST' })
    if (!res.ok) throw new Error('Auto-login not available')
    return res.json() as Promise<{ access_token: string; role: string }>
  },
  logout: () => request('/auth/logout', { method: 'POST' }),
  getAuthConfig: () => request<{ saml_enabled: boolean; local_enabled: boolean }>('/auth/config'),

  // -- Users ---------------------------------------------------------------------
  getMe: () => request<User>('/users/me'),
  getUsers: () => request<User[]>('/users'),
  createUser: (body: UserIn) =>
    request<User>('/users', { method: 'POST', body: JSON.stringify(body) }),
  updateUser: (id: number, body: Partial<UserIn> & { is_active?: boolean }) =>
    request<User>(`/users/${id}`, { method: 'PATCH', body: JSON.stringify(body) }),
  deleteUser: (id: number) => request(`/users/${id}`, { method: 'DELETE' }),
  setDefaultAdmin: (id: number) => request(`/users/${id}/set-default-admin`, { method: 'PATCH' }),
  resetUserPassword: (id: number, newPassword: string) =>
    request(`/users/${id}/reset-password`, { method: 'PATCH', body: JSON.stringify({ new_password: newPassword }) }),
  changeMyPassword: (current_password: string, new_password: string) =>
    request('/users/me/change-password', { method: 'POST', body: JSON.stringify({ current_password, new_password }) }),

  // -- Logs ---------------------------------------------------------------------
  getLogs: (params: LogQueryParams) =>
    request<LogResponse>(`/logs?${new URLSearchParams(params as Record<string, string>)}`),
  getLogStats: () => request<LogStats>('/logs/stats'),
  clearLogs: () => request('/logs', { method: 'DELETE' }),
  setLogLevel: (level: string) => request(`/logs/level?level=${level}`, { method: 'POST' }),

  // -- Integrations (suite-token client of sibling pkt apps) -----------------------
  getIntegrations: () => request<Integration[]>('/integrations'),
  createIntegration: (body: IntegrationInput) =>
    request<Integration>('/integrations', { method: 'POST', body: JSON.stringify(body) }),
  updateIntegration: (id: number, body: Partial<IntegrationInput>) =>
    request<Integration>(`/integrations/${id}`, { method: 'PUT', body: JSON.stringify(body) }),
  deleteIntegration: (id: number) => request(`/integrations/${id}`, { method: 'DELETE' }),
  testIntegration: (id: number) => request<{ healthy: boolean; detail: string }>(`/integrations/${id}/test`, { method: 'POST' }),

  // -- Suite (inbound — pktHub registering this app) --------------------------------
  getSuiteToken: () => request<{ suite_token: string; has_token: boolean }>('/suite/token'),
  regenerateSuiteToken: () => request<{ suite_token: string; status: string }>('/suite/regenerate', { method: 'POST' }),

  // -- Settings ---------------------------------------------------------------------
  getSettings: () => request<Record<string, unknown>>('/settings'),
  updateSettings: (values: Record<string, unknown>) => request('/settings', { method: 'PUT', body: JSON.stringify({ values }) }),
  testNotification: (channel: string) =>
    request<{ status: string; detail?: string }>('/settings/test-notification', {
      method: 'POST',
      body: JSON.stringify({ channel }),
    }),

  // -- System ---------------------------------------------------------------------
  getSystemInfo: () => request<{ version: string; install_dir: string; port: number }>('/system/info'),
  listBackups: () => request<Array<{ name: string; path: string; size_bytes: number; files: string[] }>>('/system/backups'),
  runBackupNow: () => request<{ status: string; path: string; files: string[]; kept: number }>('/system/backups/run', { method: 'POST' }),
  restartService: () => request<{ status: string; message: string }>('/system/restart', { method: 'POST' }),
  getPort: () => request<{ port: number }>('/system/port'),
  setPort: (port: number) =>
    request<{ port: number; message: string }>('/system/port', {
      method: 'POST',
      body: JSON.stringify({ port }),
    }),
  getNetInterfaces: () => request<{ interfaces: string[] }>('/system/net-interfaces'),

  // ── SSL ───────────────────────────────────────────────────────────────────
  getSslStatus: () => request<SslStatus>('/system/ssl/status'),
  uploadSsl: async (cert: File, key: File): Promise<SslStatus> => {
    const formData = new FormData()
    formData.append('cert', cert)
    formData.append('key', key)
    const headers: Record<string, string> = {}
    if (_accessToken) headers['Authorization'] = `Bearer ${_accessToken}`
    const res = await fetch('/api/system/ssl/upload', { method: 'POST', headers, body: formData })
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }))
      throw new Error(err.detail || res.statusText)
    }
    return res.json()
  },
  deleteSsl: () => request<SslStatus>('/system/ssl/cert', { method: 'DELETE' }),
  uploadSslPfx: async (pfx: File, passphrase: string): Promise<SslStatus> => {
    const formData = new FormData()
    formData.append('pfx', pfx)
    formData.append('passphrase', passphrase)
    const headers: Record<string, string> = {}
    if (_accessToken) headers['Authorization'] = `Bearer ${_accessToken}`
    const res = await fetch('/api/system/ssl/upload-pfx', { method: 'POST', headers, body: formData })
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }))
      throw new Error(err.detail || res.statusText)
    }
    return res.json()
  },

  // ── AI Assistant ─────────────────────────────────────────────────────────
  aiChat: (question: string, context: Record<string, unknown> = {}) =>
    request<{ answer: string; tokens_used: number }>('/ai/chat', { method: 'POST', body: JSON.stringify({ question, context }) }),
  testAiKey: (provider: string, api_key: string, model?: string) =>
    request<{ ok: boolean; reply?: string; error?: string }>('/ai/test', { method: 'POST', body: JSON.stringify({ provider, api_key, model }) }),

  // ── User API Keys / IP Info ─────────────────────────────────────────────
  getUserApiKeys: () => request<UserApiKey[]>('/user-api-keys'),
  setUserApiKey: (provider: string, api_key: string) =>
    request<UserApiKey>(`/user-api-keys/${provider}`, { method: 'PUT', body: JSON.stringify({ api_key }) }),
  testUserApiKey: (provider: string, api_key: string) =>
    request<{ status: string; detail: string }>(`/user-api-keys/${provider}/test`, { method: 'POST', body: JSON.stringify({ api_key }) }),
  setIpinfoFields: (enabled_fields: string[]) =>
    request<UserApiKey>('/user-api-keys/ipinfo/fields', { method: 'PUT', body: JSON.stringify({ enabled_fields }) }),
  setIpapiIsFields: (enabled_fields: string[]) =>
    request<UserApiKey>('/user-api-keys/ipapi_is/fields', { method: 'PUT', body: JSON.stringify({ enabled_fields }) }),
  setIpapiIsFreeTier: (free_tier: boolean) =>
    request<UserApiKey>('/user-api-keys/ipapi_is/free-tier', { method: 'PUT', body: JSON.stringify({ free_tier }) }),
  setMxtoolboxFields: (enabled_fields: string[]) =>
    request<UserApiKey>('/user-api-keys/mxtoolbox/fields', { method: 'PUT', body: JSON.stringify({ enabled_fields }) }),
  getIpInfo: (ip: string) => request<IpInfoResult>(`/ip-info/${ip}`),
  mxtoolboxLookup: (command: string, argument: string, port?: number) =>
    request<Record<string, unknown>>('/mxtoolbox/lookup', { method: 'POST', body: JSON.stringify({ command, argument, port }) }),

  // ── Capture domain (feeds / captures) — Stage 4 consumes these ──────────
  getWrapperConfig: () => request<{ wireshark_capture_enabled: boolean; tshark_capture_enabled: boolean; feed_token: string }>('/capture/wrapper-config'),
  getFeeds: () => request<FeedSession[]>('/feeds'),
  deleteFeed: (name: string) => request(`/feeds/${name}`, { method: 'DELETE' }),
  // Download endpoints need the Bearer token — a plain <a href> won't send
  // it (auth here is an in-memory JWT, not a cookie) — so these fetch the
  // bytes with the header attached and hand back a Blob for the caller to
  // either parse in-browser or push through triggerBrowserDownload().
  downloadFeedBytes: (name: string) => authedBlobFetch(`/feeds/${name}/download`),
  downloadCaptureBytes: (fname: string) => authedBlobFetch(`/captures/${fname}/download`),
  getCaptures: () => request<{ storage_path_configured: boolean; captures: Capture[] }>('/captures'),
  deleteCapture: (fname: string) => request(`/captures/${fname}`, { method: 'DELETE' }),
  uploadCapture: async (file: File): Promise<{ ok: boolean; filename: string; size_bytes: number }> => {
    const formData = new FormData()
    formData.append('file', file)
    const headers: Record<string, string> = {}
    if (_accessToken) headers['Authorization'] = `Bearer ${_accessToken}`
    const res = await fetch('/api/captures/upload', { method: 'POST', headers, body: formData })
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }))
      throw new Error(err.detail || res.statusText)
    }
    return res.json()
  },
}

export interface SslStatus {
  installed: boolean
  expires?: string
  expires_iso?: string
  days_until_expiry?: number
  subject?: string
  issuer?: string
  error?: string
  status?: string
}

// -- Types -----------------------------------------------------------------------

export interface UserIn {
  username: string
  email: string
  password?: string
  role: string
}

export interface User {
  id: number
  username: string
  email: string
  role: string
  is_active: boolean
  is_default_admin: boolean
  auth_provider: string
  created_at: string
  last_login: string | null
  has_password: boolean
}

export interface LogRecord {
  id: number
  ts: string
  level: string
  level_no: number
  logger: string
  message: string
  exc_info: string | null
}

export interface LogResponse {
  total: number
  limit: number
  offset: number
  records: LogRecord[]
}

export interface LogStats {
  total: number
  by_level: Record<string, number>
  loggers: string[]
  latest_ts: string | null
  capture_level?: string
}

export type LogQueryParams = {
  level?: string
  logger?: string
  search?: string
  since?: string
  until?: string
  limit?: string
  offset?: string
}

export interface Integration {
  id: number
  name: string
  app_name: string
  base_url: string
  has_token: boolean
  enabled: boolean
  health_status: string
  last_health_check: string | null
}

export interface IntegrationInput {
  name: string
  app_name?: string
  base_url: string
  suite_token: string
  enabled?: boolean
}

export interface UserApiKey {
  provider: string
  label: string
  api_key: string
  updated_at: string | null
  enabled_fields: string[] | null // ipinfo/ipapi_is/mxtoolbox only; null = not customized (all shown)
  free_tier: boolean // ipapi_is only — use its keyless free tier instead of api_key
}

export interface IpInfoResult {
  ip: string
  ipinfo: Record<string, any> | null
  ipinfo_error: string | null
  ipinfo_enabled_fields: string[] | null
  ipinfo_enabled: boolean
  ipapi_is: Record<string, any> | null
  ipapi_is_error: string | null
  ipapi_is_enabled_fields: string[] | null
  ipapi_is_enabled: boolean
  abuseipdb: Record<string, any> | null
  abuseipdb_error: string | null
  abuseipdb_enabled: boolean
  mxtoolbox: Record<string, any> | null
  mxtoolbox_error: string | null
  mxtoolbox_enabled_fields: string[] | null
  mxtoolbox_enabled: boolean
}

// -- Capture domain types (backend built in Stage 2; UI consumes in Stage 4) ------

export interface FeedSession {
  name: string
  remote_addr: string
  connected: boolean
  created_at: number
  last_seen: number
  bytes_buffered: number
  bytes_received: number
  duration: number
  truncated: boolean
}

export interface Capture {
  id: number
  filename: string
  session_name: string | null
  source: string
  size_bytes: number | null
  status: string
  created_by: number | null
  created_at: string
}
