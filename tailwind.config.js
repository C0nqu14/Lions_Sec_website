/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./templates/**/*.{html,js}",
  ],
  theme: {
    extend: {
      colors: {
        'dark-hacker': '#1A1A1A', // A cor principal que você quer
        'cyber-purple': '#6C2BD9', // Um toque de cor
      },
      fontFamily: {
        'sans': ['Inter', 'sans-serif'],
      },
    },
  },
  plugins: [],
}