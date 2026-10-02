import { NextRequest, NextResponse } from "next/server";

export function middleware(request: NextRequest) {
  if (request.nextUrl.hostname === "www.codecrux.us") {
    const destination = request.nextUrl.clone();
    destination.hostname = "codecrux.us";
    destination.protocol = "https:";
    return NextResponse.redirect(destination, 301);
  }

  return NextResponse.next();
}

export const config = {
  matcher: ["/((?!_next/static|_next/image).*)"],
};
