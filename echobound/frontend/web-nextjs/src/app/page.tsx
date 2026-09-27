"use client";

import { useLanguage, LANGUAGE_OPTIONS } from "@/components/language-provider";
import { useTheme, THEME_OPTIONS } from "@/components/theme-provider";
import OperatingHoursPanel from "@/components/operating-hours-panel";

export default function HomePage() {
  const { dict, locale, setLocale } = useLanguage();
  const { theme, setTheme } = useTheme();

  return (
    <main className="min-h-screen p-8" style={{ background: "var(--bg)", color: "var(--text)" }}>
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-2xl font-bold">{dict.productName}</h1>
          <p className="text-sm opacity-70">{dict.tagline}</p>
        </div>
        <div className="flex gap-2">
          {LANGUAGE_OPTIONS.map((l) => (
            <button
              key={l.id}
              onClick={() => setLocale(l.id)}
              className="px-3 py-1 rounded-full text-xs border"
              style={{
                borderColor: "var(--border)",
                background: locale === l.id ? "var(--accent)" : "transparent",
                color: locale === l.id ? "#fff" : "inherit",
              }}
            >
              {l.label}
            </button>
          ))}
        </div>
      </div>

      <div className="flex gap-2 mb-8 flex-wrap">
        {THEME_OPTIONS.map((th) => (
          <button
            key={th.id}
            onClick={() => setTheme(th.id)}
            className="px-3 py-1 rounded-full text-xs border"
            style={{
              borderColor: "var(--border)",
              background: theme === th.id ? "var(--accent)" : "transparent",
              color: theme === th.id ? "#fff" : "inherit",
            }}
          >
            {th.label}
          </button>
        ))}
      </div>

      <OperatingHoursPanel />

      <p className="mt-10 text-xs opacity-50">
        This is the reference React / Next.js / TypeScript surface for ECHOBOUND. The fully-featured
        Security Command Center (Overview, Drift Center, Incident Center, Investigation Workspace, Policy
        Studio, and more) ships as a ready-to-run static SPA in <code>frontend/dashboard</code>, which talks
        to the same backend API. Extend this Next.js app with React Flow / Three.js graph views as needed —
        see <code>package.json</code> for the pinned dependencies.
      </p>
    </main>
  );
}
