'use client'

import {
  flexRender,
  getCoreRowModel,
  getPaginationRowModel,
  getSortedRowModel,
  useReactTable,
  type ColumnDef,
  type Row,
  type SortingState,
} from '@tanstack/react-table'
import { useState, type ReactNode } from 'react'

import { Button } from '@/components/ui/Button'
import { ErrorState, TableSkeleton } from '@/components/ui/states'
import { cn } from '@/lib/utils'

/**
 * The one table.
 *
 * Built on @tanstack/react-table, which was already a dependency and entirely unused —
 * every previous list was a hand-rolled `.map()` with its own sorting, its own row
 * hover, and no pagination, so a findings page with a thousand rows rendered a thousand
 * rows.
 *
 * Three things this owns so no page has to:
 *
 * **States.** Loading, error and empty are props, not something each caller remembers to
 * handle. A table that silently renders zero rows when a request failed is how a broken
 * page looks identical to a quiet one.
 *
 * **Responsive.** Below `lg` the table becomes a list of cards built from the same column
 * definitions, rather than a horizontally scrolling grid. Horizontal scroll on a table of
 * findings means the severity column is off-screen exactly when it matters.
 *
 * **Row activation.** `onRowClick` renders each row as a real `<button>`-like element with
 * keyboard support, so a triage drawer opens from the keyboard as well as the mouse.
 */

export interface DataTableProps<TData> {
  data: readonly TData[]
  columns: ColumnDef<TData, unknown>[]
  /** Stable identity. Without it, sorting re-keys every row and loses focus. */
  getRowId?: (row: TData, index: number) => string
  isLoading?: boolean
  error?: unknown
  onRetry?: () => void
  /** Shown when there is no data and no error. Give it a reason and a next action. */
  empty?: ReactNode
  onRowClick?: (row: TData) => void
  initialSorting?: SortingState
  /** 0 disables pagination — correct for short, bounded lists. */
  pageSize?: number
  /** Filters and search, rendered above the table inside the same frame. */
  toolbar?: ReactNode
  /** Caption for screen readers describing what the table contains. */
  label: string
  /** Column count used by the loading skeleton before columns are measurable. */
  skeletonRows?: number
  className?: string
  /** Renders a compact card for narrow viewports. Falls back to label/value pairs. */
  renderMobileRow?: (row: TData) => ReactNode
}

export function DataTable<TData>({
  data,
  columns,
  getRowId,
  isLoading = false,
  error,
  onRetry,
  empty,
  onRowClick,
  initialSorting = [],
  pageSize = 25,
  toolbar,
  label,
  skeletonRows = 8,
  className,
  renderMobileRow,
}: DataTableProps<TData>) {
  const [sorting, setSorting] = useState<SortingState>(initialSorting)

  const table = useReactTable({
    data: data as TData[],
    columns,
    state: { sorting },
    onSortingChange: setSorting,
    getRowId,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    ...(pageSize > 0
      ? {
          getPaginationRowModel: getPaginationRowModel(),
          initialState: { pagination: { pageSize } },
        }
      : {}),
  })

  const rows = table.getRowModel().rows

  const frame = cn(
    'overflow-hidden rounded-lg border border-border-default bg-surface-raised',
    className,
  )

  if (error) {
    return (
      <div className={frame}>
        {toolbar ? <TableToolbar>{toolbar}</TableToolbar> : null}
        <ErrorState error={error} onRetry={onRetry} />
      </div>
    )
  }

  if (isLoading) {
    return (
      <div className={frame}>
        {toolbar ? <TableToolbar>{toolbar}</TableToolbar> : null}
        <TableSkeleton rows={skeletonRows} columns={Math.min(columns.length, 6)} />
      </div>
    )
  }

  if (rows.length === 0) {
    return (
      <div className={frame}>
        {toolbar ? <TableToolbar>{toolbar}</TableToolbar> : null}
        {empty}
      </div>
    )
  }

  return (
    <div className={frame}>
      {toolbar ? <TableToolbar>{toolbar}</TableToolbar> : null}

      {/* Table, lg and up.
          `lg`, not `md`. The sidebar becomes a fixed 240px rail at `lg`, so the content well
          is only ~720px at that breakpoint — and a six-column findings table needs about that
          much to stay readable. Switching at `md` (768px) put a table wider than the viewport
          on every tablet, which is the horizontal scrolling the card view exists to avoid. */}
      <div className="hidden overflow-x-auto lg:block">
        {/* `table-fixed` is load-bearing, not cosmetic. With auto layout a long finding
            title expands its column past the container, so the last column falls off the
            right edge and `truncate` never engages - truncation needs a bounded width to
            truncate to. Fixed layout honours the column sizes below and lets the flexible
            column absorb the remainder. `min-w` is set to fit that ~720px well, so the table
            only scrolls sideways when a caller declares columns wider than that. */}
        <table className="w-full min-w-[44rem] table-fixed border-collapse text-body-sm">
          <caption className="sr-only">{label}</caption>
          <thead>
            {table.getHeaderGroups().map((headerGroup) => (
              <tr key={headerGroup.id} className="border-b border-border-subtle">
                {headerGroup.headers.map((header) => {
                  const sortable = header.column.getCanSort()
                  const direction = header.column.getIsSorted()
                  return (
                    <th
                      key={header.id}
                      scope="col"
                      aria-sort={
                        direction === 'asc'
                          ? 'ascending'
                          : direction === 'desc'
                            ? 'descending'
                            : sortable
                              ? 'none'
                              : undefined
                      }
                      className="px-4 py-2.5 text-left align-middle font-medium"
                      style={{ width: header.getSize() === 150 ? undefined : header.getSize() }}
                    >
                      {sortable ? (
                        <button
                          type="button"
                          onClick={header.column.getToggleSortingHandler()}
                          className={cn(
                            'inline-flex items-center gap-1.5 text-caption font-medium uppercase',
                            'tracking-wide transition-colors',
                            direction ? 'text-text-primary' : 'text-text-tertiary',
                            'hover:text-text-secondary',
                          )}
                        >
                          {flexRender(header.column.columnDef.header, header.getContext())}
                          <SortCaret direction={direction === false ? null : direction} />
                        </button>
                      ) : (
                        <span className="text-caption font-medium uppercase tracking-wide text-text-tertiary">
                          {flexRender(header.column.columnDef.header, header.getContext())}
                        </span>
                      )}
                    </th>
                  )
                })}
              </tr>
            ))}
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr
                key={row.id}
                {...(onRowClick
                  ? {
                      onClick: () => onRowClick(row.original),
                      onKeyDown: (event) => {
                        if (event.key === 'Enter' || event.key === ' ') {
                          event.preventDefault()
                          onRowClick(row.original)
                        }
                      },
                      tabIndex: 0,
                      role: 'button',
                      'aria-label': 'Open details',
                    }
                  : {})}
                className={cn(
                  'border-b border-border-subtle last:border-0',
                  onRowClick &&
                    'cursor-pointer transition-colors duration-(--duration-fast) ' +
                      'hover:bg-surface-raised-hover focus-visible:bg-surface-raised-hover',
                )}
              >
                {row.getVisibleCells().map((cell) => (
                  <td key={cell.id} className="px-4 py-2.5 align-middle text-text-secondary">
                    {flexRender(cell.column.columnDef.cell, cell.getContext())}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Cards, below lg. Same data, no horizontal scroll. */}
      <ul className="divide-y divide-border-subtle lg:hidden">
        {rows.map((row) => (
          <li key={row.id}>
            {onRowClick ? (
              <button
                type="button"
                onClick={() => onRowClick(row.original)}
                className="w-full px-4 py-3 text-left transition-colors hover:bg-surface-raised-hover"
              >
                <MobileRow row={row} render={renderMobileRow} />
              </button>
            ) : (
              <div className="px-4 py-3">
                <MobileRow row={row} render={renderMobileRow} />
              </div>
            )}
          </li>
        ))}
      </ul>

      {pageSize > 0 && table.getPageCount() > 1 ? (
        <Pagination
          page={table.getState().pagination.pageIndex + 1}
          pageCount={table.getPageCount()}
          total={table.getFilteredRowModel().rows.length}
          onPrevious={() => table.previousPage()}
          onNext={() => table.nextPage()}
          canPrevious={table.getCanPreviousPage()}
          canNext={table.getCanNextPage()}
        />
      ) : null}
    </div>
  )
}

function TableToolbar({ children }: { children: ReactNode }) {
  return (
    <div className="flex flex-wrap items-center gap-2 border-b border-border-subtle px-4 py-2.5">
      {children}
    </div>
  )
}

/**
 * Sort direction.
 *
 * A CSS triangle rather than an icon import, keeping this primitive dependency-free — and
 * `aria-sort` on the `<th>` is what actually communicates the state, so the caret is
 * decoration and correctly hidden.
 */
function SortCaret({ direction }: { direction: 'asc' | 'desc' | null }) {
  if (direction === null) {
    return (
      <span
        aria-hidden
        className="size-0 border-x-[3px] border-t-[4px] border-x-transparent border-t-current opacity-30"
      />
    )
  }
  return (
    <span
      aria-hidden
      className={cn(
        'size-0 border-x-[3px] border-x-transparent',
        direction === 'asc'
          ? 'border-b-[4px] border-b-current'
          : 'border-t-[4px] border-t-current',
      )}
    />
  )
}

/** Fallback narrow-viewport row: every visible cell as a label/value pair. */
function MobileRow<TData>({
  row,
  render,
}: {
  row: Row<TData>
  render?: (row: TData) => ReactNode
}) {
  if (render) return <>{render(row.original)}</>

  return (
    <dl className="grid grid-cols-[minmax(0,7rem)_1fr] gap-x-3 gap-y-1">
      {row.getVisibleCells().map((cell) => (
        <div key={cell.id} className="contents">
          <dt className="truncate text-caption uppercase tracking-wide text-text-tertiary">
            {typeof cell.column.columnDef.header === 'string'
              ? cell.column.columnDef.header
              : cell.column.id}
          </dt>
          <dd className="min-w-0 text-body-sm text-text-secondary">
            {flexRender(cell.column.columnDef.cell, cell.getContext())}
          </dd>
        </div>
      ))}
    </dl>
  )
}

export function Pagination({
  page,
  pageCount,
  total,
  onPrevious,
  onNext,
  canPrevious,
  canNext,
}: {
  page: number
  pageCount: number
  total: number
  onPrevious: () => void
  onNext: () => void
  canPrevious: boolean
  canNext: boolean
}) {
  return (
    <nav
      aria-label="Pagination"
      className="flex flex-wrap items-center justify-between gap-3 border-t border-border-subtle px-4 py-2.5"
    >
      <p className="text-caption text-text-tertiary">
        Page <span data-numeric>{page}</span> of <span data-numeric>{pageCount}</span>
        <span aria-hidden className="mx-1.5 opacity-40">
          ·
        </span>
        <span data-numeric>{total}</span> total
      </p>
      <div className="flex items-center gap-2">
        <Button size="sm" variant="secondary" onClick={onPrevious} disabled={!canPrevious}>
          Previous
        </Button>
        <Button size="sm" variant="secondary" onClick={onNext} disabled={!canNext}>
          Next
        </Button>
      </div>
    </nav>
  )
}
