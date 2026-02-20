/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        brand: {
          50: '#eff6ff',
          100: '#dbeafe',
          200: '#bfdbfe',
          300: '#93c5fd',
          400: '#60a5fa',
          500: '#3b82f6',
          600: '#2563eb',
          700: '#1d4ed8',
          800: '#1e40af',
          900: '#1e3a8a',
          950: '#172554',
        },
        severity: {
          critical: '#dc2626',
          high: '#ea580c',
          medium: '#d97706',
          low: '#2563eb',
          info: '#6b7280',
        },
        risk: {
          critical: '#dc2626',
          high: '#ea580c',
          medium: '#d97706',
          low: '#16a34a',
        },
      },
    },
  },
  plugins: [require('@tailwindcss/typography')],
}
