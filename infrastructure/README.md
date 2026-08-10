# Infrastructure

Deployment lives here, separate from application code, so a change to how the
platform runs never touches a service's source tree.

Nothing here is wired up yet — this is the placeholder the layout reserves.
Local development uses the root `docker-compose.yml`; `make up` is the only
entrypoint you need today.

## Intended layout

```
infrastructure/
├── secrets.env.example     the variables a deployment must supply
├── helm/                   one chart per deployable service
│   ├── cyber-backend/
│   ├── cyber-ai-engine/
│   └── cyber-mcp-server/
├── k8s/                    cluster add-ons (ingress, cert-manager, dashboards)
├── terraform/              cloud resources and secret wiring
└── scripts/                deploy, rollout, secret population
```

## Secrets

No secret belongs in this repository, and none belongs in the database either.
The `settings` table that previously held the OpenAI key, OAuth client secrets,
IMAP passwords and Gmail refresh tokens was removed precisely because it was
readable over an unauthenticated endpoint and unencrypted at rest.

Every credential reaches a service through its environment. In a cluster that
means a secret manager mounted as env vars; locally it means `.env`, which is
gitignored. `secrets.env.example` documents the full set.

Before any mailbox integration returns, it needs OAuth `state` plus PKCE and
encrypted token storage — see the note in `cyber.frontend/src/lib/api.ts`.
