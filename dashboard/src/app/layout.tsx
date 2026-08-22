import type { Metadata } from "next";
import Link from "next/link";
import type { ReactNode } from "react";

import "./globals.css";

export const metadata: Metadata = {
  title: "Aegis Audit Dashboard",
  description: "Read-only operational view of Aegis evidence and telemetry",
};

export default function RootLayout({children}: Readonly<{children: ReactNode}>) {
  return <html lang="en"><body>
    <a className="skip-link" href="#main-content">Skip to content</a>
    <header className="topbar"><div><strong>Aegis</strong><span> Audit Dashboard</span></div>
      <nav aria-label="Primary navigation">
        <Link href="/">Overview</Link><Link href="/ledger">Ledger</Link>
        <Link href="/mmr">MMR Proof</Link><Link href="/metrics">Metrics</Link>
        <Link href="/forensics">Forensics</Link>
      </nav>
    </header>
    <main id="main-content" tabIndex={-1}>{children}</main>
    <footer>Read-only interface. No sample or synthetic runtime data.</footer>
  </body></html>;
}
