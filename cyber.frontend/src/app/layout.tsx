import type { Metadata } from 'next'
import type { ReactNode } from 'react'
import { Inter, Outfit } from 'next/font/google'
import Sidebar from '@/components/Sidebar'

import './globals.css'

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
  title: 'Sentinel AI — Security Operations',
  description: 'AI-driven cybersecurity scanning and analysis platform.',
}

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en" className={`${inter.variable} ${outfit.variable}`}>
      <body className="antialiased">
        <div className="shell">
          <Sidebar />
          <div className="content">{children}</div>
        </div>
      </body>
    </html>
  )
}
