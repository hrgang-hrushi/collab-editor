// Cloudflare Pages host canonicalization. Every client receives the same page.
export async function onRequest(context: { request: Request; next: () => Promise<Response> }) {
  const url = new URL(context.request.url);

  if (url.hostname === "www.codecrux.us") {
    url.hostname = "codecrux.us";
    url.protocol = "https:";
    return Response.redirect(url.toString(), 301);
  }

  return context.next();
}
