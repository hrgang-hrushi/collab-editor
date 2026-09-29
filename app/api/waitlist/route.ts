import { NextRequest, NextResponse } from "next/server";
import { addToWaitlist, getWaitlistStats } from "@/lib/db/waitlistDb";

export const dynamic = "force-dynamic";

export async function GET() {
  try {
    const stats = getWaitlistStats();
    return NextResponse.json({
      status: "live",
      ...stats,
    });
  } catch (err: any) {
    return NextResponse.json({ error: err.message || "Failed to fetch waitlist" }, { status: 500 });
  }
}

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const { email, role, arch, referral } = body || {};

    if (!email || typeof email !== "string" || !email.includes("@")) {
      return NextResponse.json(
        { error: "A valid developer email address is required" },
        { status: 400 }
      );
    }

    const { entry, isNew, totalCount } = addToWaitlist({
      email,
      role,
      arch,
      referredBy: referral,
    });

    return NextResponse.json({
      success: true,
      isNew,
      queuePosition: entry.queuePosition,
      referralCode: entry.referralCode,
      referralUrl: `https://codecrux.us?ref=${entry.referralCode}`,
      totalCount,
      message: isNew
        ? `[CONFIRMED] Priority seat secured. You are #${entry.queuePosition} in queue.`
        : `[RE-VERIFIED] Welcome back. You are already registered at #${entry.queuePosition} in queue.`,
    });
  } catch (err: any) {
    return NextResponse.json(
      { error: err.message || "Failed to join waitlist" },
      { status: 500 }
    );
  }
}
