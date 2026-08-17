import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "GateZero — Zero-Trust Access Gateway & Identity Mesh (gatezero.io)",
  description: "High-security identity gateway and zero-trust authorization portal for authorized enterprise access.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark">
      <head>
        <link
          href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap"
          rel="stylesheet"
        />
      </head>
      <body className="bg-background text-on-surface font-body-main selection:bg-primary-container selection:text-background antialiased">
        {children}
      </body>
    </html>
  );
}
