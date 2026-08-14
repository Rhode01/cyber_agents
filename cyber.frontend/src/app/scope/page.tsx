'use client'

import { useMemo, useState } from 'react'

import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { Card, CardBody, CardHeader } from '@/components/ui/Card'
import { Checkbox, Field, Input, Textarea } from '@/components/ui/Field'
import { Crosshair, Globe, Lock, ShieldCheck, Trash2, TriangleAlert } from '@/components/ui/icons'
import { PageHeader } from '@/components/ui/PageHeader'
import { StatCard, StatGrid } from '@/components/ui/StatCard'
import { EmptyState, ErrorState, LoadingState } from '@/components/ui/states'
import { useAddScanScope, useRevokeScanScope, useScanScope } from '@/lib/queries'
import type { ScanScopeEntry } from '@/types'

/**
 * Which hosts this platform may scan.
 *
 * Before this page, the answer was `SCAN_ALLOWED_TARGETS` in the MCP server's environment:
 * putting a client's server in scope meant editing config and redeploying, which does not
 * scale past the first client.
 *
 * Two things about this screen are deliberate rather than decorative.
 *
 * **The attestation is required, and it is a real field.** Adding an entry is a claim that
 * you own the host or hold authorisation to test it. There is no identity system yet, so
 * the name typed here is the only answer to "who said we could scan this" — which makes it
 * worth collecting properly rather than defaulting.
 *
 * **A hostname becomes an address in front of the user.** They type the name they know
 * their server by; the row that appears shows the address it resolved to, because that is
 * what actually gets scanned. Hiding that would leave someone believing they had authorised
 * a name when they had authorised whatever it pointed at this morning.
 */

function ScopeRow({
  entry,
  onRevoke,
  revoking,
}: {
  entry: ScanScopeEntry
  onRevoke: (id: string) => void
  revoking: boolean
}) {
  return (
    <li className="flex flex-wrap items-start justify-between gap-3 border-b border-border px-4 py-3 last:border-0">
      <div className="min-w-0">
        <div className="flex flex-wrap items-center gap-2">
          <span className="font-mono text-body-sm text-text-primary">{entry.network}</span>
          {entry.requested ? (
            <Badge tone="neutral">
              {/* Untrusted only in the sense that the operator typed it; rendered as text. */}
              via {entry.requested}
            </Badge>
          ) : null}
          {!entry.active ? <Badge tone="neutral">revoked</Badge> : null}
        </div>
        <p className="mt-1 text-caption text-text-tertiary">
          {entry.label ? <span className="text-text-secondary">{entry.label} · </span> : null}
          authorised by {entry.authorized_by}
          {entry.note ? ` · ${entry.note}` : ''}
        </p>
      </div>
      {entry.active ? (
        <Button
          size="sm"
          variant="secondary"
          leadingIcon={<Trash2 className="size-3.5" />}
          loading={revoking}
          onClick={() => onRevoke(entry.id)}
        >
          Revoke
        </Button>
      ) : null}
    </li>
  )
}

export default function ScopePage() {
  const [includeRevoked, setIncludeRevoked] = useState(false)
  const scope = useScanScope(includeRevoked)
  const add = useAddScanScope()
  const revoke = useRevokeScanScope()

  const [target, setTarget] = useState('')
  const [label, setLabel] = useState('')
  const [authorizedBy, setAuthorizedBy] = useState('')
  const [note, setNote] = useState('')
  const [attested, setAttested] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const entries = useMemo(() => scope.data?.items ?? [], [scope.data])
  const active = useMemo(() => entries.filter((entry) => entry.active), [entries])

  const canSubmit = target.trim().length > 0 && authorizedBy.trim().length > 0 && attested

  async function submit(event: React.FormEvent) {
    event.preventDefault()
    setError(null)
    try {
      await add.mutateAsync({
        target: target.trim(),
        label: label.trim(),
        authorized_by: authorizedBy.trim(),
        note: note.trim(),
      })
      // The attestation is cleared too: it is a claim about one host, not a mode.
      setTarget('')
      setLabel('')
      setNote('')
      setAttested(false)
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Could not add that to scope.')
    }
  }

  return (
    <>
      <PageHeader
        title="Scan scope"
        description="The hosts this platform is permitted to scan. Anything not listed here — or in the deployment's own private ranges — is refused before the scanner starts."
      />

      <StatGrid>
        <StatCard
          label="Authorised"
          value={active.length}
          hint="ranges in scope right now"
          icon={<ShieldCheck className="size-4" />}
        />
        <StatCard
          label="Named hosts"
          value={active.filter((entry) => entry.requested).length}
          hint="added by hostname, stored by address"
          icon={<Globe className="size-4" />}
        />
        <StatCard
          label="Single addresses"
          value={active.filter((entry) => entry.network.endsWith('/32')).length}
          hint="one server each"
          icon={<Crosshair className="size-4" />}
        />
      </StatGrid>

      <div className="mt-4 grid gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,420px)]">
        <Card>
          <CardHeader
            title="In scope"
            description="A revoked entry stops working immediately, and is kept so the record of who authorised it survives."
            actions={
              <Checkbox
                label="Show revoked"
                checked={includeRevoked}
                onChange={(event) => setIncludeRevoked(event.target.checked)}
              />
            }
          />
          {scope.isPending ? (
            <LoadingState message="Loading scope" />
          ) : scope.error ? (
            <ErrorState
              title="Could not load scope"
              error={scope.error}
              icon={<TriangleAlert className="size-5" />}
              onRetry={() => void scope.refetch()}
            />
          ) : entries.length === 0 ? (
            <EmptyState
              icon={<Lock className="size-5" />}
              title="Nothing authorised yet"
              description="Only this deployment's own private ranges can be scanned. Add a client host to put it in scope — no redeploy needed."
            />
          ) : (
            <ul>
              {entries.map((entry) => (
                <ScopeRow
                  key={entry.id}
                  entry={entry}
                  onRevoke={(id) => void revoke.mutateAsync(id)}
                  revoking={revoke.isPending && revoke.variables === entry.id}
                />
              ))}
            </ul>
          )}
        </Card>

        <Card>
          <CardHeader
            title="Authorise a host"
            description="A hostname is resolved and its address is what gets stored — the name itself is never what decides scope."
          />
          <CardBody>
            <form className="space-y-4" onSubmit={(event) => void submit(event)}>
              <Field
                label="Host or range"
                hint="An address, a CIDR range up to /16, or a hostname to resolve."
              >
                <Input
                  value={target}
                  onChange={(event) => setTarget(event.target.value)}
                  placeholder="server.client.com, 203.0.113.10, or 203.0.113.0/24"
                  autoComplete="off"
                />
              </Field>

              <Field label="What is it?" hint="Optional. Shown beside the entry.">
                <Input
                  value={label}
                  onChange={(event) => setLabel(event.target.value)}
                  placeholder="Client web server"
                  autoComplete="off"
                />
              </Field>

              <Field
                label="Authorised by"
                hint="Recorded against every scan of this host. Required."
              >
                <Input
                  value={authorizedBy}
                  onChange={(event) => setAuthorizedBy(event.target.value)}
                  placeholder="your name or email"
                  autoComplete="off"
                />
              </Field>

              <Field label="Note" hint="Optional. A contract reference, a ticket, an owner.">
                <Textarea
                  rows={2}
                  value={note}
                  onChange={(event) => setNote(event.target.value)}
                  placeholder="Signed engagement 2026-08; scope agreed with the client."
                />
              </Field>

              <Checkbox
                label="I own this host, or hold authorisation to test it"
                description="Scanning a host you are not authorised to test is unlawful in most jurisdictions. This attestation is recorded, not verified."
                checked={attested}
                onChange={(event) => setAttested(event.target.checked)}
              />

              {error ? (
                <p className="text-caption text-danger" role="alert">
                  {error}
                </p>
              ) : null}

              <Button type="submit" variant="primary" loading={add.isPending} disabled={!canSubmit}>
                Add to scope
              </Button>
            </form>
          </CardBody>
        </Card>
      </div>
    </>
  )
}
