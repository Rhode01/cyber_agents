/**
 * Tailwind v4 uses a single PostCSS plugin. `autoprefixer` is not needed - v4
 * handles vendor prefixing itself - and the plugin is `@tailwindcss/postcss`,
 * not `tailwindcss`.
 */
const config = {
  plugins: {
    '@tailwindcss/postcss': {},
  },
}

export default config
