import {
  AlertOctagon,
  AlertTriangle,
  Activity,
  ArrowRight,
  ArrowUpRight,
  Ban,
  Boxes,
  Bug,
  Check,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  CircleCheck,
  CircleDashed,
  CircleHelp,
  CircleSlash,
  CircleX,
  Clock,
  Copy,
  Crosshair,
  Download,
  ExternalLink,
  Eye,
  FileSearch,
  FileText,
  FileUp,
  Filter,
  Fingerprint,
  Gauge,
  Globe,
  Info,
  Inbox,
  KeyRound,
  Layers,
  Link2,
  Loader2,
  Lock,
  Mail,
  MailWarning,
  MinusCircle,
  MoreHorizontal,
  Network,
  Paperclip,
  Play,
  Printer,
  Radar,
  RefreshCw,
  ScanLine,
  Search,
  Send,
  Server,
  Shield,
  ShieldAlert,
  ShieldCheck,
  SlidersHorizontal,
  Timer,
  Trash2,
  TrendingUp,
  TriangleAlert,
  Upload,
  Waypoints,
  X,
  type LucideIcon,
} from 'lucide-react'

import type { IndicatorCategory, Severity } from '@/types'

/**
 * The application's icon vocabulary.
 *
 * Every icon is re-exported through this one module rather than imported from
 * `lucide-react` at each use site. That is what stops the set from drifting: adding a new
 * concept means adding a line here and noticing whether something similar already exists,
 * instead of three pages independently picking three different glyphs for "scan".
 *
 * Sizing is by Tailwind class at the use site (`size-4` for inline, `size-5` for controls,
 * `size-6` for empty states). Lucide's stroke width is 2 by default, which is heavy next to
 * 14px text, so `Icon` sets 1.75 as the house weight.
 */

export {
  Activity,
  AlertOctagon,
  AlertTriangle,
  ArrowRight,
  ArrowUpRight,
  Ban,
  Boxes,
  Bug,
  Check,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  CircleCheck,
  CircleDashed,
  CircleHelp,
  CircleSlash,
  CircleX,
  Clock,
  Copy,
  Crosshair,
  Download,
  ExternalLink,
  Eye,
  FileSearch,
  FileText,
  FileUp,
  Filter,
  Fingerprint,
  Gauge,
  Globe,
  Inbox,
  Info,
  KeyRound,
  Layers,
  Link2,
  Loader2,
  Lock,
  Mail,
  MailWarning,
  MinusCircle,
  MoreHorizontal,
  Network,
  Paperclip,
  Play,
  Printer,
  Radar,
  RefreshCw,
  ScanLine,
  Search,
  Send,
  Server,
  Shield,
  ShieldAlert,
  ShieldCheck,
  SlidersHorizontal,
  Timer,
  Trash2,
  TrendingUp,
  TriangleAlert,
  Upload,
  Waypoints,
  X,
}

export type { LucideIcon }

/**
 * Severity icons.
 *
 * The reason severity carries an icon at all: colour alone fails for the ~8% of men with a
 * red/green deficiency, fails in greyscale print, and fails anyone who has not learnt that
 * orange means high. The shapes are deliberately distinct rather than five circles in
 * different colours - an octagon, a triangle, a warning triangle, a dash and an "i" are
 * distinguishable with no colour at all.
 */
export const SEVERITY_ICON: Record<Severity, LucideIcon> = {
  critical: AlertOctagon,
  high: TriangleAlert,
  medium: AlertTriangle,
  low: MinusCircle,
  info: Info,
}

/** Icons for the six phishing indicator families. */
export const CATEGORY_ICON: Record<IndicatorCategory, LucideIcon> = {
  authentication: KeyRound,
  identity: Fingerprint,
  url: Link2,
  content: FileText,
  attachment: Paperclip,
  injection: Crosshair,
}

/** Icons for the agents, used in nav and finding rows. */
export const AGENT_ICON = {
  vulnerability: Bug,
  phishing: MailWarning,
  network: Network,
  webapp: Globe,
} as const
