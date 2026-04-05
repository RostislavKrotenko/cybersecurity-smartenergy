/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // Policy colors
        'policy-minimal': '#ef4444',
        'policy-baseline': '#f59e0b',
        'policy-standard': '#22c55e',
        // Status colors
        'status-healthy': '#22c55e',
        'status-degraded': '#eab308',
        'status-isolated': '#ef4444',
        'status-restoring': '#8b5cf6',
        // Background
        'bg-primary': '#0d1117',
        'bg-secondary': '#161b22',
        'bg-card': '#21262d',
        // Text
        'text-primary': '#e6edf3',
        'text-secondary': '#8b949e',
      },
    },
  },
  plugins: [],
}
