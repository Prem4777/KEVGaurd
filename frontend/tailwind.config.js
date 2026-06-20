/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx,ts,tsx}'],
  theme: {
    extend: {
      colors: {
        brand: {
          bg:      '#060e18',
          card:    '#0b1929',
          sidebar: '#07111c',
          green:   '#45dfa4',
          red:     '#e13052',
        },
      },
    },
  },
  plugins: [],
}
