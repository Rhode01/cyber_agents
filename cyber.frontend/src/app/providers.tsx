'use client'

import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { NuqsAdapter } from 'nuqs/adapters/next/app'
import { useState, type ReactNode } from 'react'

/**
 * Client-side providers for the whole app.
 *
 * Split out of `layout.tsx` so the layout itself stays a server component — a `'use client'`
 * on the root layout would opt the entire tree out of server rendering.
 *
 * The `QueryClient` is created in state rather than at module scope. At module scope one
 * client would be shared across every request during SSR, so one user's cached findings
 * could be served to another.
 */
export function Providers({ children }: { children: ReactNode }) {
  const [queryClient] = useState(
    () =>
      new QueryClient({
        defaultOptions: {
          queries: {
            // Data here describes a live system, so refetching on focus is right - an
            // analyst returning to the tab should not read a five-minute-old severity count.
            refetchOnWindowFocus: true,
            // One retry, not three. A backend that is down should surface as an error state
            // quickly; three exponential retries just make the page look hung.
            retry: 1,
            staleTime: 15_000,
          },
          mutations: {
            // Never retried. Every mutation here either starts a scan, spends model budget,
            // or changes a finding's status, and a silent second attempt is worse than a
            // visible failure.
            retry: false,
          },
        },
      }),
  )

  /* Development-only handle on the cache.
     Without it, diagnosing "why is this view stuck loading" means guessing from the network
     tab: the request status is visible but the query's own status, error and retry count are
     not. Gated on NODE_ENV so it never reaches a production bundle.

     In an effect, not inline in the render body: assigning to `window` while rendering is a
     side effect, and React Compiler rejects it outright rather than letting it slide. */
  useEffect(() => {
    if (process.env.NODE_ENV !== 'development') return
    const target = window as unknown as { queryClient?: QueryClient }
    target.queryClient = queryClient
    return () => {
      delete target.queryClient
    }
  }, [queryClient])

  return (
    <QueryClientProvider client={queryClient}>
      {/* Puts filter state in the URL, so a filtered findings view is shareable. */}
      <NuqsAdapter>{children}</NuqsAdapter>
    </QueryClientProvider>
  )
}
