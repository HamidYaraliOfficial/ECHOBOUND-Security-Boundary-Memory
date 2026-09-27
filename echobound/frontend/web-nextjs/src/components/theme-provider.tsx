"use client";

import { createContext, useContext, useEffect, useState, ReactNode } from "react";

export type Theme = "win11-light" | "win11-dark" | "amoled" | "crimson" | "azure";

interface ThemeContextValue {
  theme: Theme;
  setTheme: (t: Theme) => void;
}

const ThemeContext = createContext<ThemeContextValue>({
  theme: "win11-light",
  setTheme: () => {},
});

export function useTheme() {
  return useContext(ThemeContext);
}

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [theme, setThemeState] = useState<Theme>("win11-light");

  useEffect(() => {
    const stored = window.localStorage.getItem("echobound_theme") as Theme | null;
    if (stored) setThemeState(stored);
  }, []);

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    window.localStorage.setItem("echobound_theme", theme);
  }, [theme]);

  const setTheme = (t: Theme) => setThemeState(t);

  return <ThemeContext.Provider value={{ theme, setTheme }}>{children}</ThemeContext.Provider>;
}

export const THEME_OPTIONS: { id: Theme; label: string }[] = [
  { id: "win11-light", label: "Windows 11 Light" },
  { id: "win11-dark", label: "Windows 11 Dark" },
  { id: "amoled", label: "AMOLED Black" },
  { id: "crimson", label: "Crimson Red" },
  { id: "azure", label: "Azure Blue" },
];
