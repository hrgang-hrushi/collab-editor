import { NextResponse } from "next/server";

const CRUX_URLS = [
  "https://codecrux.us/",
  "https://codecrux.us/code",
  "https://codecrux.us/code-editor",
  "https://codecrux.us/about",
  "https://codecrux.us/pricing",
  "https://codecrux.us/blog",
  "https://codecrux.us/services",
  "https://codecrux.us/docs",
  "https://codecrux.us/amoeba-coding",
  "https://codecrux.us/vs-cursor",
  "https://codecrux.us/vs-claude",
  "https://codecrux.us/vs-gemini",
  "https://codecrux.us/vs-chatgpt",
  "https://codecrux.us/vs-vscode",
  "https://codecrux.us/vs-zed",
  "https://codecrux.us/benchmarks",
  "https://codecrux.us/ast-crdt",
  "https://codecrux.us/ide",
  "https://codecrux.us/llms.txt",
  "https://codecrux.us/llms-full.txt",
];

const INDEXNOW_KEY = "b3c7f8a9e1d24560a8c2f1e4b7d9035a";
const HOST = "codecrux.us";

export async function GET() {
  return POST();
}

export async function POST() {
  const results: Record<string, any> = {};

  // 1. Submit to IndexNow (Bing, Yandex, Seznam, Naver)
  try {
    const payload = {
      host: HOST,
      key: INDEXNOW_KEY,
      keyLocation: `https://${HOST}/${INDEXNOW_KEY}.txt`,
      urlList: CRUX_URLS,
    };

    const indexNowResponse = await fetch("https://api.indexnow.org/indexnow", {
      method: "POST",
      headers: {
        "Content-Type": "application/json; charset=utf-8",
      },
      body: JSON.stringify(payload),
    });

    results.indexnow = {
      status: indexNowResponse.status,
      statusText: indexNowResponse.statusText,
      success: indexNowResponse.status === 200 || indexNowResponse.status === 202,
    };
  } catch (error: any) {
    results.indexnow = {
      error: error.message,
      success: false,
    };
  }

  // 2. Direct Bing IndexNow endpoint
  try {
    const bingResponse = await fetch("https://www.bing.com/indexnow", {
      method: "POST",
      headers: {
        "Content-Type": "application/json; charset=utf-8",
      },
      body: JSON.stringify({
        host: HOST,
        key: INDEXNOW_KEY,
        keyLocation: `https://${HOST}/${INDEXNOW_KEY}.txt`,
        urlList: CRUX_URLS,
      }),
    });

    results.bing = {
      status: bingResponse.status,
      statusText: bingResponse.statusText,
      success: bingResponse.status === 200 || bingResponse.status === 202,
    };
  } catch (error: any) {
    results.bing = {
      error: error.message,
      success: false,
    };
  }

  return NextResponse.json({
    message: "Indexing submission executed for Crux IDE",
    timestamp: new Date().toISOString(),
    sitemap: `https://${HOST}/sitemap.xml`,
    urlsSubmitted: CRUX_URLS.length,
    urls: CRUX_URLS,
    results,
  });
}
