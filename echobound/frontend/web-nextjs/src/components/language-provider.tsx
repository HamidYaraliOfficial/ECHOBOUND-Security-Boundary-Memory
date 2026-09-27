"use client";

import { createContext, useContext, useEffect, useState, ReactNode } from "react";
import { Locale, getDictionary } from "@/lib/i18n";

interface LanguageContextValue {
  locale: Locale;
  setLocale: (l: Locale) => void;
  dict: ReturnType<typeof getDictionary>;
}

const LanguageContext = createContext<LanguageContextValue>({
  locale: "en",
  setLocale: () => {},
  dict: getDictionary("en"),
});

export function useLanguage() {
  return useContext(LanguageContext);
}

export function LanguageProvider({ children }: { children: ReactNode }) {
  const [locale, setLocaleState] = useState<Locale>("en");

  useEffect(() => {
    const stored = window.localStorage.getItem("echobound_lang") as Locale | null;
    if (stored) setLocaleState(stored);
  }, []);

  useEffect(() => {
    const dict = getDictionary(locale);
    document.documentElement.setAttribute("lang", locale);
    document.documentElement.setAttribute("dir", dict.dir);
    window.localStorage.setItem("echobound_lang", locale);
  }, [locale]);

  const setLocale = (l: Locale) => setLocaleState(l);
  const dict = getDictionary(locale);

  return (
    <LanguageContext.Provider value={{ locale, setLocale, dict }}>
      {children}
    </LanguageContext.Provider>
  );
}

export const LANGUAGE_OPTIONS: { id: Locale; label: string }[] = [
  { id: "en", label: "English" },
  { id: "fa", label: "فارسی" },
  { id: "zh", label: "中文" },
];
