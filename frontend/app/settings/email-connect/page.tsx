'use client'

import { Suspense, useEffect, useState, type CSSProperties } from 'react'
import Link from 'next/link'
import { useSearchParams } from 'next/navigation'
import {
  emailConnectUrl,
  emailDisconnect,
  emailScan,
  fetchEmailStatus,
  imapConnect,
  type EmailProvider,
  updateSetting,
} from '@/lib/api'
import type { EmailConnectionStatus, EmailScanResponse } from '@/lib/types'

type ScanState = 'idle' | 'scanning' | 'done' | 'error'

interface ProviderCardProps {
  name: string
  provider: 'google' | 'microsoft'
  icon: string
  connected: boolean
  onConnect: () => void
  onDisconnect: () => void
  onScan: () => void
  scanState: ScanState
  lastScan: EmailScanResponse | null
  scanError: string | null
}

function ProviderCard({
  name, provider, icon, connected, onConnect, onDisconnect, onScan,
  scanState, lastScan, scanError,
}: ProviderCardProps) {
  return (
    <div
      style={{
        border: `1px solid ${connected ? 'var(--ok)' : 'var(--border)'}`,
        borderRadius: 'var(--radius)',
        padding: '1.5rem',
        background: 'var(--panel)',
        display: 'flex',
        flexDirection: 'column',
        gap: '1rem',
      }}
    >
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
        <span style={{ fontSize: '2rem' }}>{icon}</span>
        <div style={{ flex: 1 }}>
          <div style={{ fontWeight: 700, fontSize: '0.95rem', color: '#fff' }}>{name}</div>
          <div style={{ fontSize: '0.78rem', color: connected ? 'var(--ok)' : 'var(--muted)' }}>
            {connected ? '● Connected' : '○ Not connected'}
          </div>
        </div>
        {connected ? (
          <button className="btn btn-danger" onClick={onDisconnect} style={{ fontSize: '0.8rem', padding: '0.4rem 0.8rem' }}>
            Disconnect
          </button>
        ) : (
          <button className="btn btn-primary" onClick={onConnect} style={{ fontSize: '0.8rem', padding: '0.4rem 0.8rem' }}>
            Connect →
          </button>
        )}
      </div>

      {/* Scan controls */}
      {connected && (
        <div style={{ borderTop: '1px solid var(--border)', paddingTop: '1rem', display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
          <button
            className="btn btn-primary"
            onClick={onScan}
            disabled={scanState === 'scanning'}
            style={{ alignSelf: 'flex-start' }}
          >
            {scanState === 'scanning' ? '⏳ Scanning inbox…' : '🔍 Scan Inbox Now'}
          </button>

          {scanError && (
            <p style={{ color: 'var(--bad)', fontSize: '0.82rem', margin: 0 }}>{scanError}</p>
          )}

          {lastScan && scanState === 'done' && (
            <div
              style={{
                background: 'var(--panel-2)',
                border: '1px solid var(--border)',
                borderRadius: '6px',
                padding: '0.75rem 1rem',
                fontSize: '0.82rem',
                display: 'flex',
                gap: '2rem',
              }}
            >
              <div>
                <div style={{ color: 'var(--muted)', fontSize: '0.7rem', textTransform: 'uppercase', letterSpacing: '0.08em' }}>Emails scanned</div>
                <div style={{ fontWeight: 700, fontSize: '1.2rem', color: '#fff' }}>{lastScan.emails_fetched}</div>
              </div>
              <div>
                <div style={{ color: 'var(--muted)', fontSize: '0.7rem', textTransform: 'uppercase', letterSpacing: '0.08em' }}>Findings</div>
                <div style={{ fontWeight: 700, fontSize: '1.2rem', color: lastScan.findings_total > 0 ? 'var(--critical)' : 'var(--ok)' }}>
                  {lastScan.findings_total}
                </div>
              </div>
              {lastScan.findings_total > 0 && (
                <Link href="/findings" className="btn" style={{ alignSelf: 'center', fontSize: '0.78rem', padding: '0.35rem 0.7rem' }}>
                  View Findings →
                </Link>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

interface CredFieldProps {
  label: string
  settingKey: string
  placeholder?: string
  secret?: boolean
}

function CredField({ label, settingKey, placeholder, secret }: CredFieldProps) {
  const [val, setVal] = useState('')
  const [saved, setSaved] = useState(false)
  const [saving, setSaving] = useState(false)

  const save = async () => {
    setSaving(true)
    try {
      await updateSetting(settingKey, val)
      setSaved(true)
      setTimeout(() => setSaved(false), 2000)
    } finally {
      setSaving(false)
    }
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
      <label style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
        {label}
      </label>
      <div style={{ display: 'flex', gap: '0.5rem' }}>
        <input
          type={secret ? 'password' : 'text'}
          value={val}
          onChange={(e) => setVal(e.target.value)}
          placeholder={placeholder ?? settingKey}
          style={{ flex: 1 }}
        />
        <button
          className={`btn${saved ? ' btn-primary' : ''}`}
          onClick={save}
          disabled={saving || !val}
          style={{ flexShrink: 0, fontSize: '0.8rem', padding: '0.4rem 0.8rem' }}
        >
          {saved ? '✓ Saved' : saving ? '…' : 'Save'}
        </button>
      </div>
    </div>
  )
}

interface ImapCardProps {
  name: string
  icon: string
  connected: boolean
  account: string | null
  onDisconnect: () => void
  onScan: () => void
  scanState: ScanState
  lastScan: EmailScanResponse | null
  scanError: string | null
  connecting: boolean
  connectError: string | null
  form: { email: string; host: string; port: string; folder: string; password: string }
  onChange: (v: { email: string; host: string; port: string; folder: string; password: string }) => void
  onConnect: () => void
  suggestHost: (email: string, currentHost: string) => string
}

const INPUT_STYLE: CSSProperties = {
  background: 'var(--panel-2)',
  border: '1px solid var(--border)',
  borderRadius: '6px',
  color: '#fff',
  padding: '0.5rem 0.7rem',
  fontSize: '0.85rem',
  width: '100%',
  boxSizing: 'border-box',
}

function ImapCard({
  name, icon, connected, account, onDisconnect, onScan, scanState, lastScan, scanError,
  connecting, connectError, form, onChange, onConnect, suggestHost,
}: ImapCardProps) {
  const set = (patch: Partial<typeof form>) => onChange({ ...form, ...patch })

  const host = suggestHost(form.email, form.host)
  const hostPlaceholder = form.email.includes('@') ? host : 'imap.yourdomain.com'

  return (
    <div
      style={{
        border: `1px solid ${connected ? 'var(--ok)' : 'var(--border)'}`,
        borderRadius: 'var(--radius)',
        padding: '1.5rem',
        background: 'var(--panel)',
        display: 'flex',
        flexDirection: 'column',
        gap: '1rem',
      }}
    >
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
        <span style={{ fontSize: '2rem' }}>{icon}</span>
        <div style={{ flex: 1 }}>
          <div style={{ fontWeight: 700, fontSize: '0.95rem', color: '#fff' }}>{name}</div>
          <div style={{ fontSize: '0.78rem', color: connected ? 'var(--ok)' : 'var(--muted)' }}>
            {connected ? `● Connected · ${account}` : '○ Not connected'}
          </div>
        </div>
        {connected && (
          <button className="btn btn-danger" onClick={onDisconnect} style={{ fontSize: '0.8rem', padding: '0.4rem 0.8rem' }}>
            Disconnect
          </button>
        )}
      </div>

      {/* Connect form */}
      {!connected && (
        <div style={{ borderTop: '1px solid var(--border)', paddingTop: '1rem', display: 'flex', flexDirection: 'column', gap: '0.7rem' }}>
          <div style={{ fontSize: '0.78rem', color: 'var(--muted)' }}>
            Works with any mail server that exposes IMAP — Gmail, Outlook, Yahoo, Zoho, corporate or custom domains. Use an app password, not your normal password.
          </div>
          <input
            type="email"
            placeholder="you@yourdomain.com"
            value={form.email}
            onChange={(e) => set({ email: e.target.value })}
            style={INPUT_STYLE}
          />
          <div style={{ display: 'flex', gap: '0.5rem' }}>
            <input
              type="text"
              placeholder={hostPlaceholder}
              value={form.host}
              onChange={(e) => set({ host: e.target.value })}
              style={{ ...INPUT_STYLE, flex: 1 }}
            />
            <input
              type="number"
              placeholder="993"
              value={form.port}
              onChange={(e) => set({ port: e.target.value })}
              style={{ ...INPUT_STYLE, width: '5.5rem', flexShrink: 0 }}
            />
          </div>
          <div style={{ display: 'flex', gap: '0.5rem' }}>
            <input
              type="text"
              placeholder="Folder (INBOX)"
              value={form.folder}
              onChange={(e) => set({ folder: e.target.value })}
              style={{ ...INPUT_STYLE, flex: 1 }}
            />
            <input
              type="password"
              placeholder="App password"
              value={form.password}
              onChange={(e) => set({ password: e.target.value })}
              style={{ ...INPUT_STYLE, flex: 1 }}
            />
          </div>
          {connectError && <p style={{ color: 'var(--bad)', fontSize: '0.82rem', margin: 0 }}>{connectError}</p>}
          <button
            className="btn btn-primary"
            onClick={onConnect}
            disabled={connecting}
            style={{ alignSelf: 'flex-start' }}
          >
            {connecting ? '⏳ Connecting…' : '🔗 Connect mailbox'}
          </button>
        </div>
      )}

      {/* Scan controls */}
      {connected && (
        <div style={{ borderTop: '1px solid var(--border)', paddingTop: '1rem', display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
          <button
            className="btn btn-primary"
            onClick={onScan}
            disabled={scanState === 'scanning'}
            style={{ alignSelf: 'flex-start' }}
          >
            {scanState === 'scanning' ? '⏳ Scanning inbox…' : '🔍 Scan Inbox Now'}
          </button>

          {scanError && (
            <p style={{ color: 'var(--bad)', fontSize: '0.82rem', margin: 0 }}>{scanError}</p>
          )}

          {lastScan && scanState === 'done' && (
            <div
              style={{
                background: 'var(--panel-2)',
                border: '1px solid var(--border)',
                borderRadius: '6px',
                padding: '0.75rem 1rem',
                fontSize: '0.82rem',
                display: 'flex',
                gap: '2rem',
              }}
            >
              <div>
                <div style={{ color: 'var(--muted)', fontSize: '0.7rem', textTransform: 'uppercase', letterSpacing: '0.08em' }}>Emails scanned</div>
                <div style={{ fontWeight: 700, fontSize: '1.2rem', color: '#fff' }}>{lastScan.emails_fetched}</div>
              </div>
              <div>
                <div style={{ color: 'var(--muted)', fontSize: '0.7rem', textTransform: 'uppercase', letterSpacing: '0.08em' }}>Findings</div>
                <div style={{ fontWeight: 700, fontSize: '1.2rem', color: lastScan.findings_total > 0 ? 'var(--critical)' : 'var(--ok)' }}>
                  {lastScan.findings_total}
                </div>
              </div>
              {lastScan.findings_total > 0 && (
                <Link href="/findings" className="btn" style={{ alignSelf: 'center', fontSize: '0.78rem', padding: '0.35rem 0.7rem' }}>
                  View Findings →
                </Link>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

function EmailIntegrationPageInner() {
  const searchParams = useSearchParams()
  const [status, setStatus] = useState<EmailConnectionStatus | null>(null)
  const [googleScan, setGoogleScan] = useState<ScanState>('idle')
  const [googleResult, setGoogleResult] = useState<EmailScanResponse | null>(null)
  const [googleError, setGoogleError] = useState<string | null>(null)
  const [msScan, setMsScan] = useState<ScanState>('idle')
  const [msResult, setMsResult] = useState<EmailScanResponse | null>(null)
  const [msError, setMsError] = useState<string | null>(null)
  const [imapScan, setImapScan] = useState<ScanState>('idle')
  const [imapResult, setImapResult] = useState<EmailScanResponse | null>(null)
  const [imapError, setImapError] = useState<string | null>(null)
  const [imapConnecting, setImapConnecting] = useState(false)
  const [imapForm, setImapForm] = useState({ email: '', host: '', port: '993', folder: 'INBOX', password: '' })
  const [imapConnectError, setImapConnectError] = useState<string | null>(null)
  const [showAdvanced, setShowAdvanced] = useState(false)
  const [notification, setNotification] = useState<string | null>(null)

  const reload = () =>
    fetchEmailStatus()
      .then(setStatus)
      .catch(() =>
        setStatus({ google_connected: false, microsoft_connected: false, imap_connected: false, imap_account: null })
      )

  useEffect(() => {
    reload()

    // Handle redirect-back from OAuth
    const connected = searchParams.get('email_connected')
    const error = searchParams.get('email_error')
    if (connected) setNotification(`✅ ${connected === 'google' ? 'Gmail' : 'Microsoft 365'} connected successfully!`)
    if (error) setNotification(`❌ OAuth error: ${error}`)
  }, [searchParams])

  const handleConnect = (provider: 'google' | 'microsoft') => {
    window.location.href = emailConnectUrl(provider)
  }

  const handleDisconnect = async (provider: EmailProvider) => {
    await emailDisconnect(provider)
    reload()
  }

  const handleScan = async (provider: EmailProvider) => {
    const setS = provider === 'google' ? setGoogleScan : provider === 'microsoft' ? setMsScan : setImapScan
    const setR = provider === 'google' ? setGoogleResult : provider === 'microsoft' ? setMsResult : setImapResult
    const setE = provider === 'google' ? setGoogleError : provider === 'microsoft' ? setMsError : setImapError
    setS('scanning')
    setE(null)
    try {
      const res = await emailScan(provider, 20)
      setR(res)
      setS('done')
    } catch (err: unknown) {
      setE(err instanceof Error ? err.message : 'Scan failed')
      setS('error')
    }
  }

  const SUGGESTED_HOSTS: Record<string, string> = {
    'gmail.com': 'imap.gmail.com',
    'googlemail.com': 'imap.gmail.com',
    'outlook.com': 'outlook.office365.com',
    'hotmail.com': 'outlook.office365.com',
    'live.com': 'outlook.office365.com',
    'msn.com': 'outlook.office365.com',
    'yahoo.com': 'imap.mail.yahoo.com',
    'ymail.com': 'imap.mail.yahoo.com',
    'aol.com': 'imap.aol.com',
    'icloud.com': 'imap.mail.me.com',
    'me.com': 'imap.mail.me.com',
    'zoho.com': 'imap.zoho.com',
    'zoho.eu': 'imap.zoho.eu',
  }

  const suggestHost = (email: string, currentHost: string): string => {
    const domain = email.split('@')[1]?.toLowerCase() ?? ''
    if (!domain || currentHost.trim()) return currentHost
    return SUGGESTED_HOSTS[domain] ?? `mail.${domain}`
  }

  const handleImapConnect = async () => {
    setImapConnecting(true)
    setImapConnectError(null)
    try {
      const payload = {
        email: imapForm.email.trim(),
        host: suggestHost(imapForm.email, imapForm.host).trim(),
        port: parseInt(imapForm.port, 10) || 993,
        folder: imapForm.folder.trim() || 'INBOX',
        password: imapForm.password,
      }
      if (!payload.email || !payload.host || !payload.password) {
        setImapConnectError('Email, host and password are required.')
        return
      }
      await imapConnect(payload)
      setImapForm({ email: '', host: '', port: '993', folder: 'INBOX', password: '' })
      setNotification('✅ IMAP mailbox connected!')
      reload()
    } catch (err: unknown) {
      setImapConnectError(err instanceof Error ? err.message : 'Could not connect')
    } finally {
      setImapConnecting(false)
    }
  }

  return (
    <main>
      <div className="page-title">
        <div>
          <span className="eyebrow">Settings</span>
          <h1>Email Integration</h1>
          <p className="subtitle">
            Connect your mailbox via OAuth so the phishing agent can automatically scan your inbox.
          </p>
        </div>
        <Link href="/settings" className="btn btn-ghost">← Settings</Link>
      </div>

      {notification && (
        <div
          style={{
            padding: '0.75rem 1rem',
            borderRadius: 'var(--radius)',
            background: notification.startsWith('✅') ? 'var(--ok-bg)' : 'var(--bad-bg)',
            border: `1px solid ${notification.startsWith('✅') ? 'var(--ok)' : 'var(--bad)'}`,
            color: notification.startsWith('✅') ? 'var(--ok)' : 'var(--bad)',
            fontSize: '0.85rem',
            marginBottom: '1.5rem',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
          }}
        >
          {notification}
          <button onClick={() => setNotification(null)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'inherit', fontSize: '1rem' }}>✕</button>
        </div>
      )}

      {/* How it works */}
      <section className="panel" style={{ marginBottom: '1.5rem' }}>
        <h2>How it works</h2>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '1rem', fontSize: '0.82rem', color: 'var(--muted)' }}>
          {['1. Connect a mailbox (OAuth or any IMAP server)', '2. Click "Scan Inbox Now" to fetch recent emails', '3. The phishing agent analyses each email for SPF/DKIM failures, malicious links, and impersonation', '4. Findings appear in the Findings dashboard'].map((step) => (
            <div key={step} style={{ padding: '0.75rem', background: 'var(--panel-2)', borderRadius: '6px', border: '1px solid var(--border)' }}>
              {step}
            </div>
          ))}
        </div>
      </section>

      {/* Provider cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(340px, 1fr))', gap: '1rem', marginBottom: '2rem' }}>
        <ProviderCard
          name="Gmail / Google Workspace"
          provider="google"
          icon="📧"
          connected={status?.google_connected ?? false}
          onConnect={() => handleConnect('google')}
          onDisconnect={() => handleDisconnect('google')}
          onScan={() => handleScan('google')}
          scanState={googleScan}
          lastScan={googleResult}
          scanError={googleError}
        />
        <ProviderCard
          name="Microsoft 365 / Outlook"
          provider="microsoft"
          icon="📬"
          connected={status?.microsoft_connected ?? false}
          onConnect={() => handleConnect('microsoft')}
          onDisconnect={() => handleDisconnect('microsoft')}
          onScan={() => handleScan('microsoft')}
          scanState={msScan}
          lastScan={msResult}
          scanError={msError}
        />
        <ImapCard
          name="Any Mail Server (IMAP)"
          icon="🌐"
          connected={status?.imap_connected ?? false}
          account={status?.imap_account ?? null}
          onDisconnect={() => handleDisconnect('imap')}
          onScan={() => handleScan('imap')}
          scanState={imapScan}
          lastScan={imapResult}
          scanError={imapError}
          connecting={imapConnecting}
          connectError={imapConnectError}
          form={imapForm}
          onChange={setImapForm}
          onConnect={handleImapConnect}
          suggestHost={suggestHost}
        />
      </div>

      {/* Advanced settings (OAuth app credentials) */}
      <section className="panel">
        <div
          style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', cursor: 'pointer' }}
          onClick={() => setShowAdvanced(v => !v)}
        >
          <h2 style={{ margin: 0 }}>Advanced settings</h2>
          <span style={{ color: 'var(--accent)', fontSize: '0.85rem' }}>{showAdvanced ? '▾ Hide' : '▸ Show'}</span>
        </div>
        <p style={{ color: 'var(--muted)', fontSize: '0.82rem', marginTop: '0.5rem' }}>
          {showAdvanced
            ? 'Register an OAuth app with each provider and paste the credentials here to use the Gmail / Microsoft connectors.'
            : 'OAuth client IDs and secrets for the Gmail and Microsoft 365 connectors.'}
        </p>

        {showAdvanced && (
          <div style={{ marginTop: '1.5rem' }}>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(340px, 1fr))', gap: '2rem' }}>
          {/* Google */}
          <div>
            <h3 style={{ color: '#fff', marginBottom: '1rem', fontSize: '0.88rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              📧 Google / Gmail
            </h3>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', fontSize: '0.82rem', color: 'var(--muted)', marginBottom: '1rem', background: 'var(--panel-2)', borderRadius: '6px', padding: '0.75rem', border: '1px solid var(--border)' }}>
              <div>1. Go to <strong style={{ color: 'var(--accent)' }}>console.cloud.google.com</strong></div>
              <div>2. Create project → Enable <strong style={{ color: '#fff' }}>Gmail API</strong></div>
              <div>3. Create OAuth 2.0 credentials → Web Application</div>
              <div>4. Add redirect URI: <code style={{ fontSize: '0.75rem' }}>http://localhost:3000/email/connect/google/callback</code></div>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
              <CredField label="Client ID" settingKey="email_google_client_id" placeholder="xxxxxx.apps.googleusercontent.com" />
              <CredField label="Client Secret" settingKey="email_google_client_secret" placeholder="GOCSPX-…" secret />
            </div>
          </div>

          {/* Microsoft */}
          <div>
            <h3 style={{ color: '#fff', marginBottom: '1rem', fontSize: '0.88rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              📬 Microsoft 365 / Outlook
            </h3>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', fontSize: '0.82rem', color: 'var(--muted)', marginBottom: '1rem', background: 'var(--panel-2)', borderRadius: '6px', padding: '0.75rem', border: '1px solid var(--border)' }}>
              <div>1. Go to <strong style={{ color: 'var(--accent)' }}>portal.azure.com</strong> → App Registrations</div>
              <div>2. Register new app → Add redirect URI: <code style={{ fontSize: '0.75rem' }}>http://localhost:3000/email/connect/microsoft/callback</code></div>
              <div>3. Add permission: <strong style={{ color: '#fff' }}>Mail.Read</strong> (Microsoft Graph)</div>
              <div>4. Create a client secret under Certificates & Secrets</div>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
              <CredField label="Tenant ID" settingKey="email_microsoft_tenant_id" placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" />
              <CredField label="Client ID" settingKey="email_microsoft_client_id" placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" />
              <CredField label="Client Secret" settingKey="email_microsoft_client_secret" placeholder="…" secret />
            </div>
          </div>
        </div>
          </div>
        )}
      </section>
    </main>
  )
}

export default function EmailIntegrationPage() {
  return (
    <Suspense fallback={null}>
      <EmailIntegrationPageInner />
    </Suspense>
  )
}
