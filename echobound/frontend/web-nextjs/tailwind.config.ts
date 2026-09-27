import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./src/**/*.{ts,tsx}"],
  darkMode: ["class", '[data-theme="win11-dark"], [data-theme="amoled"], [data-theme="crimson"], [data-theme="azure"]'],
  theme: {
    extend: {
      colors: {
        bg: "var(--bg)",
        card: "var(--bg-card)",
        accent: "var(--accent)",
        border: "var(--border)",
      },
      borderRadius: { lg: "16px", md: "10px", sm: "6px" },
    },
  },
  plugins: [],
};
export default config;
