import sharedPreset from '@cagent/shared-ui/tailwind.preset.js';

/** @type {import('tailwindcss').Config} */
export default {
  presets: [sharedPreset],
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
    "../../../packages/shared-ui/src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        dark: {
          50: '#f7f7f8',
          100: '#ececf1',
          200: '#d9d9e3',
          300: '#c5c5d2',
          400: '#acacbe',
          500: '#8e8ea0',
          600: '#565869',
          700: '#40414f',
          800: '#343541',
          900: '#202123',
          950: '#111112',
        },
        surface: {
          50: '#f7f7f8',
          100: '#ececf1',
          200: '#d9d9e3',
          300: '#c5c5d2',
          400: '#acacbe',
          500: '#8e8ea0',
          600: '#565869',
          700: '#40414f',
          800: '#343541',
          900: '#202123',
          950: '#111112',
        },
      },
    },
  },
  plugins: [],
};
