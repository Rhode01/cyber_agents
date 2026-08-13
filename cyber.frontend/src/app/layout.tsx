import type { Metadata, Viewport } from 'next'
import { Inter, Outfit } from 'next/font/google'
import type { ReactNode } from 'react'

import { AppShell } from '@/components/shell/AppShell'
import { Providers } from '@/app/providers'

import './globals.css'

/**
 * Inter for text, Outfit for display.
 *
 * Both were already wired through `next/font`, which is worth keeping: it self-hosts the
 * files and inlines the `@font-face` rules, so there is no layout shift and no request to
 * Google at runtime. `display: swap` means text is readable during the swap rather than
 * invisible.
 */
const inter = Inter({
  subsets: ['latin'],
  variable: '--font-inter',
  display: 'swap',
})

const outfit = Outfit({
  subsets: ['latin'],
  variable: '--font-outfit',
  display: 'swap',
})

export const metadata: Metadata = {
  title: {
    default: 'Sentinel AI — Security Operations',
    template: '%s · Sentinel AI',
  },
  description:
    'Detection agents that interpret scanner output and suspect messages into prioritised, explained findings.',
}

export const viewport: Viewport = {
  // The palette is dark-first; telling the browser means form controls, scrollbars and the
  // address bar match rather than flashing white.
  colorScheme: 'dark',
  themeColor: '#0a0c10',
}

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en" className={`${inter.variable} ${outfit.variable}`}>
      <body className="min-h-screen antialiased">
        <Providers>
          <AppShell>{children}</AppShell>
        </Providers>
      </body>
    </html>
  )
}
