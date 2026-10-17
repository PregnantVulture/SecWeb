import type { Metadata } from "next";
import localFont from "next/font/local";
import "./globals.css";

const geistSans = localFont({
  src: "./fonts/GeistVF.woff",
  variable: "--font-geist-sans",
  weight: "100 900",
});
const geistMono = localFont({
  src: "./fonts/GeistMonoVF.woff",
  variable: "--font-geist-mono",
  weight: "100 900",
});

export const metadata: Metadata = {
  title: "SecWeb - Website Intelligence & Vulnerability Scanner",
  description: "Automated vulnerability assessment, discovery, and site verification dashboard.",
  other: {
    "secweb-verify": "PASTE_YOUR_EXACT_GENERATED_TOKEN_HERE",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark h-full">
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased h-full bg-[#1b1a24] text-zinc-100`}
      >
        {children}
      </body>
    </html>
  );
}
