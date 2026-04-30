import type { Metadata } from "next";
import { IBM_Plex_Sans, JetBrains_Mono, Space_Mono } from "next/font/google";
import { Toaster } from "sonner";

import "./globals.css";

const spaceMono = Space_Mono({
  weight: ["400", "700"],
  subsets: ["latin"],
  variable: "--font-space",
});

const ibmPlex = IBM_Plex_Sans({
  weight: ["400", "500", "600"],
  subsets: ["latin"],
  variable: "--font-ibm",
});

const jetbrains = JetBrains_Mono({
  subsets: ["latin"],
  variable: "--font-jetbrains",
});

export const metadata: Metadata = {
  title: "DSTFA",
  description: "Digital Signature & Trust Forensic Agent",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html
      lang="en"
      className={`${spaceMono.variable} ${ibmPlex.variable} ${jetbrains.variable} h-full antialiased`}
    >
      <body className="min-h-full bg-[var(--bg-primary)] font-[family-name:var(--font-ibm)] text-[var(--text-primary)]">
        {children}
        <Toaster richColors theme="dark" position="top-right" />
      </body>
    </html>
  );
}
