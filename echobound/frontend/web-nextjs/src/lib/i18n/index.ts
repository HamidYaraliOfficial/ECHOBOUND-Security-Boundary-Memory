import en from "./en.json";
import fa from "./fa.json";
import zh from "./zh.json";

export type Locale = "en" | "fa" | "zh";
export const dictionaries: Record<Locale, typeof en> = { en, fa, zh };

export function getDictionary(locale: Locale) {
  return dictionaries[locale] || dictionaries.en;
}
