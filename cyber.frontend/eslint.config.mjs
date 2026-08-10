// eslint-config-next 16 ships native flat configs, so they are spread directly.
// No @eslint/eslintrc FlatCompat shim is needed (and using one breaks: the
// config object is circular and the legacy validator cannot serialise it).
import coreWebVitals from 'eslint-config-next/core-web-vitals'
import nextTypescript from 'eslint-config-next/typescript'

const config = [
  { ignores: ['.next/**', 'node_modules/**', 'next-env.d.ts'] },
  ...coreWebVitals,
  ...nextTypescript,
]

export default config
