import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "CIPHER WATCH — Threat Intelligence Hub",
  description: "Live SOC dashboard — OSINT aggregator pulling from URLhaus, CISA KEV, and ThreatFox",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="h-full">
      <body className="h-full">{children}</body>
    </html>
  );
}
