import type { Config } from "tailwindcss";

// Dark, terminal-flavoured theme reusing the orange Zanoza accent.
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        border: "hsl(240 6% 20%)",
        background: "hsl(240 8% 6%)",
        foreground: "hsl(0 0% 96%)",
        card: "hsl(240 7% 10%)",
        muted: "hsl(240 6% 16%)",
        "muted-foreground": "hsl(240 5% 65%)",
        primary: "hsl(22 95% 55%)",
        "primary-foreground": "hsl(0 0% 0%)",
        secondary: "hsl(240 7% 12%)",
        destructive: "hsl(0 72% 55%)",
      },
    },
  },
  plugins: [],
} satisfies Config;
