'use client'

import { useEffect, useState } from 'react'
import Link from 'next/link'
import { fetchSettings, updateSetting } from '@/lib/api'
import { AGENT_KINDS, type AgentKind, type PipelineMode } from '@/lib/types'

const AGENT_LABELS: Record<AgentKind, string> = {
  vulnerability: 'Vulnerability Assessment (nmap)',
  phishing: 'Phishing Detection (mail / URL)',
  network: 'Network Traffic Analysis (ss)',
  webapp: 'Web Application (nuclei)',
}

export default function SettingsPage() {
  const [settings, setSettings] = useState<Record<string, string>>({})
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  // Form states
  const [llmProvider, setLlmProvider] = useState('openai')
  const [llmModel, setLlmModel] = useState('')
  const [llmBaseUrl, setLlmBaseUrl] = useState('')
  const [llmApiKey, setLlmApiKey] = useState('')
  const [mcpServers, setMcpServers] = useState('')

  // Pipeline states
  const [pipelineMode, setPipelineMode] = useState<PipelineMode>('auto')
  const [pipelineAgents, setPipelineAgents] = useState<AgentKind[]>([])
  const [mailSource, setMailSource] = useState('')

  const [saving, setSaving] = useState(false)
  const [message, setMessage] = useState<string | null>(null)

  useEffect(() => {
    fetchSettings()
      .then((data) => {
        const map: Record<string, string> = {}
        data.forEach(s => map[s.key] = s.value)
        setSettings(map)
        setLlmProvider(map['llm_provider'] || 'openai')
        setLlmModel(map['llm_model'] || '')
        setLlmBaseUrl(map['llm_base_url'] || '')
        setLlmApiKey(map['llm_api_key'] || map['openai_api_key'] || '')
        setMcpServers(map['mcp_servers'] || '')
        setPipelineMode(map['pipeline_mode'] === 'manual' ? 'manual' : 'auto')
        setPipelineAgents(parsePipelineAgents(map['pipeline_agents']))
        setMailSource(map['mail_source'] || '')
      })
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false))
  }, [])

  async function handleSave(e: React.FormEvent) {
    e.preventDefault()
    setSaving(true)
    setMessage(null)
    setError(null)

    try {
      if (llmProvider !== settings['llm_provider']) await updateSetting('llm_provider', llmProvider)
      if (llmModel !== settings['llm_model']) await updateSetting('llm_model', llmModel)
      if (llmBaseUrl !== settings['llm_base_url']) await updateSetting('llm_base_url', llmBaseUrl)
      if (llmApiKey !== settings['llm_api_key']) await updateSetting('llm_api_key', llmApiKey)
      if (mcpServers !== settings['mcp_servers']) await updateSetting('mcp_servers', mcpServers)

      if (pipelineMode !== settings['pipeline_mode']) await updateSetting('pipeline_mode', pipelineMode)
      const agentsJson = JSON.stringify(pipelineAgents)
      if (agentsJson !== settings['pipeline_agents']) await updateSetting('pipeline_agents', agentsJson)
      if (mailSource !== settings['mail_source']) await updateSetting('mail_source', mailSource)

      setMessage('Settings saved successfully.')
      setSettings({
        ...settings,
        llm_provider: llmProvider,
        llm_model: llmModel,
        llm_base_url: llmBaseUrl,
        llm_api_key: llmApiKey,
        mcp_servers: mcpServers,
        pipeline_mode: pipelineMode,
        pipeline_agents: agentsJson,
        mail_source: mailSource,
      })
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Unknown error')
    } finally {
      setSaving(false)
    }
  }

  function toggleAgent(agent: AgentKind) {
    setPipelineAgents((prev) =>
      prev.includes(agent) ? prev.filter((a) => a !== agent) : [...prev, agent]
    )
  }

  return (
    <main>
      <div className="page-title">
        <div>
          <span className="eyebrow">Platform</span>
          <h1>Settings</h1>
          <p className="subtitle">Engine credentials and external service configuration.</p>
        </div>
      </div>

      <section className="panel" style={{ maxWidth: '42rem' }}>
        {loading && <span className="status pending">Loading settings…</span>}

        {error && (
          <div className="error" style={{ marginBottom: '1rem' }}>
            <span className="status bad">● Error</span>
            <p>{error}</p>
          </div>
        )}

        {message && (
          <div
            style={{
              padding: '0.75rem 1rem',
              background: 'var(--ok-bg)',
              border: '1px solid rgba(52,211,153,0.3)',
              borderRadius: '10px',
              marginBottom: '1rem',
              color: 'var(--ok)',
              fontWeight: 700,
            }}
          >
            {message}
          </div>
        )}

        {!loading && (
          <form onSubmit={handleSave} style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
              <div>
                <label className="field" htmlFor="llm-provider">LLM Provider</label>
                <select
                  id="llm-provider"
                  value={llmProvider}
                  onChange={(e) => setLlmProvider(e.target.value)}
                  style={{ width: '100%', padding: '0.5rem', borderRadius: '4px', border: '1px solid var(--border)', background: 'var(--bg)' }}
                >
                  <option value="openai">OpenAI (or Compatible)</option>
                  <option value="anthropic">Anthropic (Claude)</option>
                </select>
              </div>

              <div>
                <label className="field" htmlFor="llm-model">Model Name</label>
                <input
                  id="llm-model"
                  type="text"
                  value={llmModel}
                  onChange={(e) => setLlmModel(e.target.value)}
                  placeholder={llmProvider === 'anthropic' ? 'claude-3-5-sonnet-20241022' : 'gpt-4o-mini'}
                />
              </div>
            </div>

            <div>
              <label className="field" htmlFor="llm-base-url">Base URL (Optional)</label>
              <p style={{ fontSize: '0.85rem', color: 'var(--muted)', margin: '0 0 0.5rem' }}>
                For local proxies like LiteLLM or Ollama. Leave blank for provider defaults.
              </p>
              <input
                id="llm-base-url"
                type="text"
                value={llmBaseUrl}
                onChange={(e) => setLlmBaseUrl(e.target.value)}
                placeholder="http://localhost:8082"
              />
            </div>

            <div>
              <label className="field" htmlFor="llm-api-key">API Key</label>
              <p style={{ fontSize: '0.85rem', color: 'var(--muted)', margin: '0 0 0.5rem' }}>
                The API key used to authenticate with the configured provider.
              </p>
              <input
                id="llm-api-key"
                type="password"
                value={llmApiKey}
                onChange={(e) => setLlmApiKey(e.target.value)}
                placeholder="sk-..."
              />
            </div>

            <div>
              <label className="field" htmlFor="mcp-servers">
                External MCP Servers (JSON)
              </label>
              <p style={{ fontSize: '0.85rem', color: 'var(--muted)', margin: '0 0 0.5rem' }}>
                Configure external MCP servers for threat intel enrichment (Phase 3+).
              </p>
              <textarea
                id="mcp-servers"
                value={mcpServers}
                onChange={(e) => setMcpServers(e.target.value)}
                rows={5}
                placeholder={'{\n  "threat-intel": "http://mcp-server:8000"\n}'}
                style={{ fontFamily: 'var(--font-mono)', fontSize: '0.82rem' }}
              />
            </div>

            <div style={{ borderTop: '1px solid var(--border)', paddingTop: '1.25rem' }}>
              <h2 style={{ margin: '0 0 0.25rem' }}>Pipeline</h2>
              <p style={{ fontSize: '0.85rem', color: 'var(--muted)', margin: '0 0 1rem' }}>
                Controls what Run Agent launches. Auto runs the full pipeline and skips
                anything that is not connected — no prompts, no extra config.
              </p>

              <div>
                <label className="field" htmlFor="pipeline-mode">Pipeline Mode</label>
                <select
                  id="pipeline-mode"
                  value={pipelineMode}
                  onChange={(e) => setPipelineMode(e.target.value as PipelineMode)}
                  style={{ width: '100%', padding: '0.5rem', borderRadius: '4px', border: '1px solid var(--border)', background: 'var(--bg)' }}
                >
                  <option value="auto">Auto — full pipeline (skip what is not connected)</option>
                  <option value="manual">Manual — (choose what to run)</option>
                </select>
              </div>

              {pipelineMode === 'manual' && (
                <div style={{ marginTop: '1rem', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                  {AGENT_KINDS.map((agent) => (
                    <label key={agent} style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', fontSize: '0.9rem' }}>
                      <input
                        type="checkbox"
                        checked={pipelineAgents.includes(agent)}
                        onChange={() => toggleAgent(agent)}
                      />
                      {AGENT_LABELS[agent]}
                    </label>
                  ))}
                </div>
              )}

              <div style={{ marginTop: '1rem' }}>
                <label className="field" htmlFor="mail-source">Mail Source (Phishing)</label>
                <p style={{ fontSize: '0.85rem', color: 'var(--muted)', margin: '0 0 0.5rem' }}>
                  Where the phishing agent gets emails to scan (e.g. an IMAP endpoint or mailbox path).
                  In Auto mode phishing is skipped when this is empty.
                </p>
                <input
                  id="mail-source"
                  type="text"
                  value={mailSource}
                  onChange={(e) => setMailSource(e.target.value)}
                  placeholder="imap://user@mail.example.com"
                />
              </div>
            </div>

            <div>
              <button type="submit" className="btn btn-primary" disabled={saving}>
                {saving ? 'Saving…' : 'Save Settings'}
              </button>
            </div>
          </form>
        )}
      </section>

      {/* Email Integration card */}
      <section className="panel" style={{ maxWidth: '42rem', marginTop: '0' }}>
        <h2>Email Integration</h2>
        <p style={{ color: 'var(--muted)', fontSize: '0.85rem', margin: '0.5rem 0 1.25rem' }}>
          Connect Gmail or Microsoft 365 so the phishing agent can automatically scan your inbox for threats.
        </p>
        <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
          <Link href="/settings/email-connect" className="btn btn-primary">
            📧 Manage Email Connections →
          </Link>
        </div>
      </section>
    </main>
  )
}

function parsePipelineAgents(raw: string | undefined): AgentKind[] {
  if (!raw) return []
  try {
    const parsed = JSON.parse(raw)
    if (!Array.isArray(parsed)) return []
    return parsed.filter((a): a is AgentKind => (AGENT_KINDS as string[]).includes(a))
  } catch {
    return []
  }
}
