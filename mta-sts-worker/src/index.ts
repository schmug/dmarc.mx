export default {
  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === "/.well-known/mta-sts.txt") {
      const policy = [
        "version: STSv1",
        "mode: enforce",
        "mx: route1.mx.cloudflare.net",
        "mx: route2.mx.cloudflare.net",
        "mx: route3.mx.cloudflare.net",
        "max_age: 604800",
      ].join("\r\n");

      return new Response(policy, {
        headers: {
          "Content-Type": "text/plain",
          "Cache-Control": "public, max-age=86400",
        },
      });
    }

    return Response.redirect("https://dmarc.mx/", 301);
  },
};
