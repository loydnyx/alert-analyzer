import type { ReactNode } from "react";

export const metadata = {
  title: "Alert Analyzer",
  icons: {
    icon: [
      { url: "/favicon.ico" },
      { url: "/favicon.png" },
    ],
    apple: "/favicon.png",
  },
}

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}