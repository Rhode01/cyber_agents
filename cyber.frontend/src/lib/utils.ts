import { type ClassValue, clsx } from 'clsx'
import { twMerge } from 'tailwind-merge'

/**
 * Merge class names, letting later Tailwind utilities win over earlier ones.
 *
 * `clsx` handles conditionals and arrays; `twMerge` resolves genuine conflicts
 * (`px-2 px-4` collapses to `px-4`) which plain string concatenation cannot.
 * This is the `cn()` helper shadcn/ui and Tremor components both expect, and
 * `components.json` points its `utils` alias here.
 */
export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs))
}
