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
        surface: {
          0: 'var(--surface-0)',
          1: 'var(--surface-1)',
          2: 'var(--surface-2)',
          3: 'var(--surface-3)',
          4: 'var(--surface-4)',
        },
        accent: {
          DEFAULT: '#7c6ff0',
          light: '#9b90f0',
          dim: '#5a4fd4',
          glow: 'rgba(124,111,240,0.15)',
        },
        nhi: {
          text: 'var(--text-primary)',
          muted: 'var(--text-secondary)',
          dim: 'var(--text-tertiary)',
          faint: 'var(--text-faint)',
          ghost: 'var(--text-ghost)',
        },
        risk: {
          critical: '#ef4444',
          high: '#f97316',
          medium: '#f59e0b',
          low: '#34d399',
        },
        brd: {
          DEFAULT: 'var(--border)',
          hover: 'var(--border-hover)',
        },
      },
      fontFamily: {
        sans: ['DM Sans', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'sans-serif'],
        mono: ['JetBrains Mono', 'SF Mono', 'Fira Code', 'monospace'],
      },
      fontSize: {
        '2xs': '0.625rem',
      },
      boxShadow: {
        'glow-sm': '0 0 8px rgba(124,111,240,0.15)',
        'glow': '0 0 16px rgba(124,111,240,0.2)',
        'glow-lg': '0 0 32px rgba(124,111,240,0.25)',
        'card': 'var(--shadow-card)',
      },
      animation: {
        'pulse-glow': 'pulseGlow 3s ease-in-out infinite',
      }
    },
  },
  plugins: [],
}