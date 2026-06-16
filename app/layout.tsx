import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Login with X — OAuth 2.0 Sample",
  description:
    "Sample app demonstrating the X API OAuth 2.0 PKCE flow and GET /2/users/me",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
