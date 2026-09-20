/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        dark: {
          bg: '#0a0e17',
          card: '#111827',
          border: '#1f2937',
          hover: '#1e293b'
        }
      }
    },
  },
  plugins: [],
}
