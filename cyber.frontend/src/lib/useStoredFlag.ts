'use client'

import { useCallback, useSyncExternalStore } from 'react'

/**
 * A boolean preference that survives a reload.
 *
 * Built on `useSyncExternalStore` rather than the more obvious `useState` + `useEffect` that
 * reads `localStorage` on mount. Three reasons, in order of how much they matter:
 *
 * 1. **No cascading render.** Setting state synchronously inside an effect renders the tree
 *    twice on every mount — once with the default, once with the stored value.
 * 2. **No hydration mismatch.** `getServerSnapshot` gives the server the default, and React
 *    knows to reconcile rather than warn. Reading `localStorage` during render would differ
 *    between server and client.
 * 3. **Cross-tab sync, free.** `storage` events fire in other tabs, so collapsing the sidebar
 *    in one tab collapses it in the rest.
 *
 * The subscriber list is module-level because `storage` does not fire in the tab that wrote
 * the value — only in the others — so a local write has to notify local subscribers itself.
 */

const listeners = new Set<() => void>()

function subscribe(onChange: () => void): () => void {
  listeners.add(onChange)
  window.addEventListener('storage', onChange)
  return () => {
    listeners.delete(onChange)
    window.removeEventListener('storage', onChange)
  }
}

function notify(): void {
  for (const listener of listeners) listener()
}

export function useStoredFlag(key: string, fallback = false): [boolean, (next: boolean) => void] {
  const value = useSyncExternalStore(
    subscribe,
    // Read on every notify. `localStorage.getItem` is synchronous and cheap, and returning a
    // cached object here would break the snapshot equality check React relies on.
    () => readFlag(key, fallback),
    () => fallback,
  )

  const set = useCallback(
    (next: boolean) => {
      try {
        window.localStorage.setItem(key, next ? '1' : '0')
      } catch {
        // A blocked or full storage should not stop the UI from responding. The preference
        // simply will not survive the reload.
      }
      notify()
    },
    [key],
  )

  return [value, set]
}

function readFlag(key: string, fallback: boolean): boolean {
  try {
    const stored = window.localStorage.getItem(key)
    return stored === null ? fallback : stored === '1'
  } catch {
    return fallback
  }
}
