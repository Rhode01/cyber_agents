import {
  Activity,
  FileSearch,
  FileText,
  Inbox,
  MailWarning,
  Play,
  Server,
  Shield,
  ShieldCheck,
  type LucideIcon,
} from '@/components/ui/icons'

/**
 * The navigation model.
 *
 * Data rather than markup, so the sidebar, the mobile drawer and the breadcrumb trail all
 * read from one definition and cannot disagree about what a route is called.
 *
 * The grouping is the actual navigation fix. There were eight flat peer links, which gave
 * no clue that Scans, Phishing and Run Agent are three ways to start work while Findings and
 * Services are two ways to look at results. The groups follow the analyst's loop: see the
 * posture, submit something, investigate what came back, report on it.
 */

export interface NavRoute {
  href: string
  label: string
  icon: LucideIcon
  /** Shown in breadcrumbs and page headers; may differ from the nav label. */
  title: string
  description: string
}

export interface NavGroup {
  id: string
  label: string
  routes: readonly NavRoute[]
}

export const NAV_GROUPS: readonly NavGroup[] = [
  {
    id: 'overview',
    label: 'Overview',
    routes: [
      {
        href: '/',
        label: 'Dashboard',
        icon: Shield,
        title: 'Security posture',
        description: 'What needs attention right now, and what has changed.',
      },
    ],
  },
  {
    id: 'analyse',
    label: 'Analyse',
    routes: [
      {
        href: '/scans',
        label: 'Scan intake',
        icon: Inbox,
        title: 'Scan intake',
        description:
          'Upload a scanner report and have it interpreted into prioritised findings.',
      },
      {
        href: '/phishing',
        label: 'Phishing',
        icon: MailWarning,
        title: 'Phishing detection',
        description:
          'Submit a suspect email or link. Deterministic rules decide what is wrong; the model explains it and ranks what matters.',
      },
      {
        href: '/run',
        label: 'Run agent',
        icon: Play,
        title: 'Run agent',
        description: 'Point the detection agents at a target and watch them work.',
      },
    ],
  },
  {
    id: 'investigate',
    label: 'Investigate',
    routes: [
      {
        href: '/findings',
        label: 'Findings',
        icon: FileSearch,
        title: 'Findings',
        description: 'Every detection, filterable and sortable.',
      },
      {
        href: '/services',
        label: 'Services',
        icon: Server,
        title: 'Services',
        description: 'What is exposed on the hosts this platform has seen.',
      },
    ],
  },
  {
    id: 'configure',
    label: 'Configure',
    routes: [
      {
        href: '/scope',
        label: 'Scan scope',
        icon: ShieldCheck,
        title: 'Scan scope',
        description:
          'The hosts this platform is permitted to scan. Anything not listed is refused before the scanner starts.',
      },
    ],
  },
  {
    id: 'report',
    label: 'Report',
    routes: [
      {
        href: '/reports',
        label: 'Reports',
        icon: FileText,
        title: 'Reports',
        description: 'A summary to hand to someone who was not watching the queue.',
      },
    ],
  },
]

export const ALL_ROUTES: readonly NavRoute[] = NAV_GROUPS.flatMap((group) => group.routes)

/** The route whose page is currently showing, for titles and breadcrumbs. */
export function routeForPath(pathname: string): NavRoute | undefined {
  // Exact match first: "/" would otherwise prefix-match everything.
  const exact = ALL_ROUTES.find((route) => route.href === pathname)
  if (exact) return exact
  return ALL_ROUTES.filter((route) => route.href !== '/').find((route) =>
    pathname.startsWith(route.href),
  )
}

/** True when a nav item should render as current. */
export function isActive(href: string, pathname: string): boolean {
  if (href === '/') return pathname === '/'
  return pathname === href || pathname.startsWith(`${href}/`)
}

export { Activity }
