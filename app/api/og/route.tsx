import { ImageResponse } from "next/og";
import { NextRequest } from "next/server";

export const runtime = "edge";

export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url);

    const title = searchParams.get("title") || "Code Crux (Crux IDE)";
    const subtitle =
      searchParams.get("subtitle") ||
      "Bare-Metal Collaborative Code Editor · Rust & WebGPU Engine";
    const tag = searchParams.get("tag") || "SYSTEMS BENCHMARK";
    const metric1 = searchParams.get("m1") || "4.2ms // 48.6ms";
    const metric1Label = searchParams.get("l1") || "INPUT-TO-PHOTON";
    const metric2 = searchParams.get("m2") || "38MB // 680MB";
    const metric2Label = searchParams.get("l2") || "IDLE MEMORY";
    const metric3 = searchParams.get("m3") || "120 FPS";
    const metric3Label = searchParams.get("l3") || "WEBGPU REFRESH";

    return new ImageResponse(
      (
        <div
          style={{
            height: "100%",
            width: "100%",
            display: "flex",
            flexDirection: "column",
            justifyContent: "space-between",
            backgroundColor: "#000000",
            padding: "50px 60px",
            border: "1px solid #222222",
            fontFamily: "sans-serif",
            color: "#ffffff",
          }}
        >
          {/* Top Bar: Brand & Tag */}
          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              borderBottom: "1px solid #222222",
              paddingBottom: "24px",
            }}
          >
            <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
              <div
                style={{
                  fontSize: 34,
                  fontWeight: 900,
                  letterSpacing: "0px",
                  color: "#ffffff",
                }}
              >
                Crux
              </div>
              <div
                style={{
                  fontSize: 14,
                  color: "#0055ff",
                  fontFamily: "monospace",
                  fontWeight: "bold",
                }}
              >
                // BARE-METAL IDE
              </div>
            </div>

            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: "8px",
                border: "1px solid #222222",
                backgroundColor: "#111111",
                padding: "6px 14px",
                fontFamily: "monospace",
                fontSize: 12,
                color: "#888888",
              }}
            >
              <div
                style={{
                  width: 6,
                  height: 6,
                  backgroundColor: "#ffffff",
                }}
              />
              <span>[{tag.toUpperCase()}]</span>
            </div>
          </div>

          {/* Main Content: Title & Subtitle */}
          <div
            style={{
              display: "flex",
              flexDirection: "column",
              gap: "16px",
              margin: "30px 0",
            }}
          >
            <div
              style={{
                fontSize: 56,
                fontWeight: 800,
                color: "#ffffff",
                lineHeight: 1.1,
                letterSpacing: "-0.03em",
                maxWidth: "1000px",
              }}
            >
              {title}
            </div>
            <div
              style={{
                fontSize: 22,
                color: "#888888",
                lineHeight: 1.4,
                maxWidth: "920px",
              }}
            >
              {subtitle}
            </div>
          </div>

          {/* Bottom Bar: Brutalist Contrast Metrics */}
          <div
            style={{
              display: "flex",
              borderTop: "1px solid #222222",
              paddingTop: "24px",
              justifyContent: "space-between",
            }}
          >
            <div
              style={{
                display: "flex",
                flexDirection: "column",
                borderRight: "1px solid #222222",
                paddingRight: "40px",
              }}
            >
              <div
                style={{
                  fontSize: 12,
                  fontFamily: "monospace",
                  color: "#666666",
                  marginBottom: "6px",
                }}
              >
                {metric1Label}
              </div>
              <div
                style={{
                  fontSize: 28,
                  fontFamily: "monospace",
                  fontWeight: "bold",
                  color: "#0055ff",
                }}
              >
                {metric1}
              </div>
            </div>

            <div
              style={{
                display: "flex",
                flexDirection: "column",
                borderRight: "1px solid #222222",
                paddingRight: "40px",
              }}
            >
              <div
                style={{
                  fontSize: 12,
                  fontFamily: "monospace",
                  color: "#666666",
                  marginBottom: "6px",
                }}
              >
                {metric2Label}
              </div>
              <div
                style={{
                  fontSize: 28,
                  fontFamily: "monospace",
                  fontWeight: "bold",
                  color: "#ffffff",
                }}
              >
                {metric2}
              </div>
            </div>

            <div
              style={{
                display: "flex",
                flexDirection: "column",
                borderRight: "1px solid #222222",
                paddingRight: "40px",
              }}
            >
              <div
                style={{
                  fontSize: 12,
                  fontFamily: "monospace",
                  color: "#666666",
                  marginBottom: "6px",
                }}
              >
                {metric3Label}
              </div>
              <div
                style={{
                  fontSize: 28,
                  fontFamily: "monospace",
                  fontWeight: "bold",
                  color: "#22c55e",
                }}
              >
                {metric3}
              </div>
            </div>

            <div
              style={{
                display: "flex",
                flexDirection: "column",
                alignItems: "flex-end",
                justifyContent: "center",
              }}
            >
              <div
                style={{
                  fontSize: 14,
                  fontFamily: "monospace",
                  color: "#ffffff",
                  fontWeight: "bold",
                }}
              >
                codecrux.us
              </div>
              <div
                style={{
                  fontSize: 11,
                  fontFamily: "monospace",
                  color: "#444444",
                  marginTop: "4px",
                }}
              >
                RUST + WEBGPU ENGINE
              </div>
            </div>
          </div>
        </div>
      ),
      {
        width: 1200,
        height: 630,
      }
    );
  } catch (error: any) {
    return new Response(`Failed to generate the image: ${error.message}`, {
      status: 500,
    });
  }
}
