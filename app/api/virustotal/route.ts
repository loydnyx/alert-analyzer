// File location: app/api/virustotal/route.ts

import { NextRequest, NextResponse } from "next/server";

export async function GET(req: NextRequest) {
  const ip = req.nextUrl.searchParams.get("ip");

  if (!ip) {
    return NextResponse.json({ error: "IP is required" }, { status: 400 });
  }

  const apiKey = process.env.VIRUSTOTAL_API_KEY;
  if (!apiKey) {
    return NextResponse.json({ error: "VT API key not configured" }, { status: 500 });
  }

  try {
    const res = await fetch(`https://www.virustotal.com/api/v3/ip_addresses/${ip}`, {
      headers: { "x-apikey": apiKey },
    });

    if (!res.ok) {
    const err = await res.json();
    const message = err?.error?.message ?? err?.error ?? `VT API error (${res.status})`;
    return NextResponse.json({ error: String(message) }, { status: res.status });
    }

    const data = await res.json();
    const stats = data?.data?.attributes?.last_analysis_stats ?? {};

    return NextResponse.json({
      malicious:  stats.malicious  ?? 0,
      suspicious: stats.suspicious ?? 0,
      harmless:   stats.harmless   ?? 0,
      undetected: stats.undetected ?? 0,
      reputation: data?.data?.attributes?.reputation ?? 0,
      country:    data?.data?.attributes?.country ?? "Unknown",
      owner:      data?.data?.attributes?.as_owner ?? "Unknown",
    });
  } catch (err) {
    return NextResponse.json({ error: String(err) }, { status: 500 });
  }
}