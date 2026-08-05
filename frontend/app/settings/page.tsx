'use client'

import { useEffect, useState } from 'react'
import { fetchSettings, updateSetting } from '@/lib/api'

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
      
      setMessage('Settings saved successfully.')
      setSettings({
        ...settings,
        llm_provider: llmProvider,
        llm_model: llmModel,
        llm_base_url: llmBaseUrl,
        llm_api_key: llmApiKey,
        mcp_servers: mcpServers
      })
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Unknown error')
    } finally {
      setSaving(false)
    }
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

            <div>
              <button type="submit" className="btn btn-primary" disabled={saving}>
                {saving ? 'Saving…' : 'Save Settings'}
              </button>
            </div>
          </form>
        )}
      </section>
    </main>
  )
}
