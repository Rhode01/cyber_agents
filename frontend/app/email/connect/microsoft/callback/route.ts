import { NextRequest, NextResponse } from 'next/server'

export const dynamic = 'force-dynamic'

const BACKEND_URL = process.env.NEXT_PUBLIC_BACKEND_URL ?? 'http://localhost:8000'

export function GET(req: NextRequest) {
  const target = new URL('/email/connect/microsoft/callback', BACKEND_URL)
  for (const [key, value] of req.nextUrl.searchParams) target.searchParams.set(key, value)
  return NextResponse.redirect(target)
}
