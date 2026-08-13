'use client'

import { Dialog, DropdownMenu, Tabs, Tooltip } from 'radix-ui'
import type { ReactNode } from 'react'

import { IconButton } from '@/components/ui/Button'
import { X } from '@/components/ui/icons'
import { cn } from '@/lib/utils'

/**
 * Floating surfaces, on Radix primitives.
 *
 * Radix rather than hand-rolled because focus trapping, restore-on-close, Escape handling,
 * portalling out of overflow contexts, `aria-modal` wiring, and typeahead in a menu are
 * precisely the things that get skipped when an overlay is written in a hurry — and the
 * brief is explicit that accessibility is not traded for polish. Radix is headless, so
 * every visual decision below is still ours.
 *
 * Overlays are the only place elevation is used. Cards get borders. That is what makes a
 * floating thing read as temporary.
 */

const OVERLAY_BACKDROP =
  'fixed inset-0 z-40 bg-black/60 backdrop-blur-[2px] ' +
  'data-[state=open]:animate-in data-[state=closed]:animate-out'

const PANEL_BASE =
  'z-50 border border-border-strong bg-surface-overlay shadow-elevation-3 ' +
  'focus:outline-none'

/* ---------------------------------------------------------------- dialog */

export function Modal({
  open,
  onOpenChange,
  title,
  description,
  children,
  footer,
  size = 'md',
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  title: string
  /** Rendered as the accessible description. Omit only if the body is self-explanatory. */
  description?: string
  children: ReactNode
  footer?: ReactNode
  size?: 'sm' | 'md' | 'lg'
}) {
  const WIDTH = { sm: 'max-w-sm', md: 'max-w-lg', lg: 'max-w-2xl' } as const

  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className={OVERLAY_BACKDROP} />
        <Dialog.Content
          className={cn(
            PANEL_BASE,
            // Bottom sheet on a phone, centred dialog from sm up. A centred modal on a
            // 390px screen leaves no room for its own content.
            'fixed inset-x-0 bottom-0 max-h-[90vh] overflow-y-auto rounded-t-lg',
            'sm:inset-x-auto sm:bottom-auto sm:left-1/2 sm:top-1/2 sm:w-full',
            'sm:-translate-x-1/2 sm:-translate-y-1/2 sm:rounded-lg',
            WIDTH[size],
          )}
        >
          <div className="flex items-start justify-between gap-4 border-b border-border-subtle px-5 py-3.5">
            <div className="min-w-0">
              <Dialog.Title className="text-heading font-semibold text-text-primary">
                {title}
              </Dialog.Title>
              {description ? (
                <Dialog.Description className="mt-1 text-body-sm text-text-secondary">
                  {description}
                </Dialog.Description>
              ) : null}
            </div>
            <Dialog.Close asChild>
              <IconButton label="Close" icon={<X className="size-4" />} size="sm" />
            </Dialog.Close>
          </div>

          <div className="px-5 py-4">{children}</div>

          {footer ? (
            <div className="flex flex-wrap items-center justify-end gap-2 border-t border-border-subtle px-5 py-3.5">
              {footer}
            </div>
          ) : null}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  )
}

/* ----------------------------------------------------------------- drawer */

/**
 * Side panel, for detail beside a list.
 *
 * The findings table opens one of these rather than navigating: triaging twenty findings
 * should not mean twenty round trips back to a re-filtered, re-scrolled list.
 */
export function Drawer({
  open,
  onOpenChange,
  title,
  description,
  children,
  footer,
  header,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  title: string
  description?: string
  children: ReactNode
  footer?: ReactNode
  /** Extra content under the title — badges, actions. */
  header?: ReactNode
}) {
  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className={OVERLAY_BACKDROP} />
        <Dialog.Content
          className={cn(
            PANEL_BASE,
            'fixed inset-y-0 right-0 flex w-full flex-col border-l sm:max-w-xl lg:max-w-2xl',
          )}
        >
          <div className="flex items-start justify-between gap-4 border-b border-border-subtle px-5 py-3.5">
            <div className="min-w-0">
              <Dialog.Title className="truncate text-heading font-semibold text-text-primary">
                {title}
              </Dialog.Title>
              {description ? (
                <Dialog.Description className="mt-1 text-body-sm text-text-secondary">
                  {description}
                </Dialog.Description>
              ) : null}
              {header ? <div className="mt-2.5">{header}</div> : null}
            </div>
            <Dialog.Close asChild>
              <IconButton label="Close" icon={<X className="size-4" />} size="sm" />
            </Dialog.Close>
          </div>

          <div className="min-h-0 flex-1 overflow-y-auto px-5 py-4">{children}</div>

          {footer ? (
            <div className="flex flex-wrap items-center justify-end gap-2 border-t border-border-subtle px-5 py-3.5">
              {footer}
            </div>
          ) : null}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  )
}

/* --------------------------------------------------------------- dropdown */

export interface MenuAction {
  label: string
  onSelect: () => void
  icon?: ReactNode
  /** Renders in the critical colour and sits below a separator. */
  destructive?: boolean
  disabled?: boolean
}

export function ActionMenu({
  trigger,
  actions,
  label = 'Actions',
  align = 'end',
}: {
  trigger: ReactNode
  actions: readonly MenuAction[]
  label?: string
  align?: 'start' | 'end'
}) {
  const safe = actions.filter((action) => !action.destructive)
  const destructive = actions.filter((action) => action.destructive)

  return (
    <DropdownMenu.Root>
      <DropdownMenu.Trigger asChild aria-label={label}>
        {trigger}
      </DropdownMenu.Trigger>
      <DropdownMenu.Portal>
        <DropdownMenu.Content
          align={align}
          sideOffset={6}
          className={cn(PANEL_BASE, 'min-w-44 rounded-md p-1')}
        >
          {safe.map((action) => (
            <MenuItem key={action.label} action={action} />
          ))}
          {destructive.length > 0 && safe.length > 0 ? (
            <DropdownMenu.Separator className="my-1 h-px bg-border-subtle" />
          ) : null}
          {destructive.map((action) => (
            <MenuItem key={action.label} action={action} />
          ))}
        </DropdownMenu.Content>
      </DropdownMenu.Portal>
    </DropdownMenu.Root>
  )
}

function MenuItem({ action }: { action: MenuAction }) {
  return (
    <DropdownMenu.Item
      disabled={action.disabled}
      onSelect={action.onSelect}
      className={cn(
        'flex cursor-pointer items-center gap-2 rounded-sm px-2 py-1.5 text-body-sm',
        'outline-none select-none',
        action.destructive
          ? 'text-severity-critical data-highlighted:bg-severity-critical-bg'
          : 'text-text-secondary data-highlighted:bg-surface-raised-hover data-highlighted:text-text-primary',
        'data-disabled:pointer-events-none data-disabled:opacity-50',
      )}
    >
      {action.icon ? (
        <span className="shrink-0" aria-hidden>
          {action.icon}
        </span>
      ) : null}
      {action.label}
    </DropdownMenu.Item>
  )
}

/* ---------------------------------------------------------------- tooltip */

/** Wrap the app once, near the root. Radix shares delay state through it. */
export function TooltipProvider({ children }: { children: ReactNode }) {
  return (
    <Tooltip.Provider delayDuration={350} skipDelayDuration={200}>
      {children}
    </Tooltip.Provider>
  )
}

/**
 * A hint on hover and on keyboard focus.
 *
 * For explaining security terminology and for naming icon-only controls. Never the only
 * place information exists — a tooltip is invisible on a touch screen.
 */
export function Hint({
  content,
  children,
  side = 'top',
}: {
  content: ReactNode
  children: ReactNode
  side?: 'top' | 'right' | 'bottom' | 'left'
}) {
  return (
    <Tooltip.Root>
      <Tooltip.Trigger asChild>{children}</Tooltip.Trigger>
      <Tooltip.Portal>
        <Tooltip.Content
          side={side}
          sideOffset={6}
          className={cn(
            PANEL_BASE,
            'max-w-xs rounded-md px-2.5 py-1.5 text-caption leading-4 text-text-secondary',
          )}
        >
          {content}
          <Tooltip.Arrow className="fill-border-strong" />
        </Tooltip.Content>
      </Tooltip.Portal>
    </Tooltip.Root>
  )
}

/* ------------------------------------------------------------------- tabs */

export interface TabDefinition {
  value: string
  label: string
  /** Shown as a count beside the label. Omitted when zero. */
  count?: number
  content: ReactNode
}

export function TabPanel({
  tabs,
  defaultValue,
  className,
}: {
  tabs: readonly TabDefinition[]
  defaultValue?: string
  className?: string
}) {
  return (
    <Tabs.Root defaultValue={defaultValue ?? tabs[0]?.value} className={className}>
      <Tabs.List
        className="flex gap-1 overflow-x-auto border-b border-border-subtle scrollbar-none"
        aria-label="Sections"
      >
        {tabs.map((tab) => (
          <Tabs.Trigger
            key={tab.value}
            value={tab.value}
            className={cn(
              'relative shrink-0 px-3 py-2 text-body-sm font-medium whitespace-nowrap',
              'text-text-tertiary transition-colors duration-(--duration-fast)',
              'hover:text-text-secondary',
              'data-[state=active]:text-text-primary',
              // The active marker is a bottom border drawn by an after pseudo-element, so
              // it sits over the list's own border rather than shifting the layout by 1px.
              'after:absolute after:inset-x-2 after:-bottom-px after:h-0.5 after:rounded-full',
              'data-[state=active]:after:bg-accent',
            )}
          >
            {tab.label}
            {tab.count !== undefined && tab.count > 0 ? (
              <span
                className="ml-1.5 rounded-full bg-surface-sunken px-1.5 py-0.5 text-caption text-text-tertiary"
                data-numeric
              >
                {tab.count}
              </span>
            ) : null}
          </Tabs.Trigger>
        ))}
      </Tabs.List>

      {tabs.map((tab) => (
        <Tabs.Content key={tab.value} value={tab.value} className="pt-4 focus:outline-none">
          {tab.content}
        </Tabs.Content>
      ))}
    </Tabs.Root>
  )
}
