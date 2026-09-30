#!/usr/bin/env node

/**
 * Crux IDE — Search Engine Indexing & Google Search Console Submission Script
 * Usage: node scripts/submit-indexing.mjs
 */

import fs from "fs";
import path from "path";
import crypto from "crypto";

const HOST = "codecrux.us";
const INDEXNOW_KEY = "b3c7f8a9e1d24560a8c2f1e4b7d9035a";

const URLS = [
  `https://${HOST}/`,
  `https://${HOST}/amoeba-coding`,
  `https://${HOST}/vs-cursor`,
  `https://${HOST}/vs-claude`,
  `https://${HOST}/vs-gemini`,
  `https://${HOST}/vs-chatgpt`,
  `https://${HOST}/vs-vscode`,
  `https://${HOST}/vs-zed`,
  `https://${HOST}/benchmarks`,
  `https://${HOST}/ast-crdt`,
  `https://${HOST}/pricing`,
  `https://${HOST}/ide`,
  `https://${HOST}/llms.txt`,
  `https://${HOST}/llms-full.txt`,
];

console.log("==================================================================");
console.log("   CRUX IDE (https://codecrux.us) — SEARCH ENGINE INDEXING SUITE   ");
console.log("==================================================================\n");

async function submitIndexNow() {
  console.log("📡 [1/3] Submitting URLs to IndexNow Protocol (Bing, Yandex, Seznam, Naver)...");
  const payload = {
    host: HOST,
    key: INDEXNOW_KEY,
    keyLocation: `https://${HOST}/${INDEXNOW_KEY}.txt`,
    urlList: URLS,
  };

  const endpoints = [
    { name: "IndexNow Universal Relay", url: "https://api.indexnow.org/indexnow" },
    { name: "Bing Direct IndexNow", url: "https://www.bing.com/indexnow" },
  ];

  for (const endpoint of endpoints) {
    try {
      const response = await fetch(endpoint.url, {
        method: "POST",
        headers: { "Content-Type": "application/json; charset=utf-8" },
        body: JSON.stringify(payload),
      });

      console.log(`   ✓ ${endpoint.name}: HTTP ${response.status} ${response.statusText}`);
      if (response.status === 200 || response.status === 202) {
        console.log(`     → Successfully queued ${URLS.length} URLs for immediate crawl.`);
      } else {
        const text = await response.text();
        console.log(`     → Note: Response body: ${text || "empty"}`);
      }
    } catch (err) {
      console.error(`   ✗ ${endpoint.name} failed:`, err.message);
    }
  }
  console.log("");
}

// Google Indexing API submission using Service Account JWT
async function submitGoogleIndexingAPI() {
  console.log("🔍 [2/3] Checking Google Indexing API / Google Search Console credentials...");

  const possibleKeyPaths = [
    process.env.GOOGLE_APPLICATION_CREDENTIALS,
    path.resolve(process.cwd(), "google-credentials.json"),
    path.resolve(process.cwd(), "service_account.json"),
    path.resolve(process.cwd(), "google-service-account.json"),
  ].filter(Boolean);

  let keyFile = possibleKeyPaths.find((p) => fs.existsSync(p));

  if (!keyFile) {
    console.log("   ℹ No Google Cloud service account JSON key found in local environment.");
    console.log("   ℹ Supported auto-discovery paths: google-credentials.json, service_account.json");
    console.log("   ------------------------------------------------------------------");
    console.log("   📌 HOW TO SUBMIT DIRECTLY TO GOOGLE SEARCH CONSOLE:");
    console.log("   1. Open: https://search.google.com/search-console");
    console.log("   2. Add Property -> Select 'URL prefix' -> Enter: https://codecrux.us");
    console.log("   3. Verification:");
    console.log("      • HTML Tag: We've enabled automatic verification meta tags in app/layout.tsx.");
    console.log("      • HTML File: Any google<hash>.html file is automatically verified by Crux middleware.");
    console.log("   4. Once verified, go to 'Sitemaps' tab in the left sidebar:");
    console.log("      • Enter: sitemap.xml");
    console.log("      • Click 'Submit'");
    console.log("   5. For Instant URL Indexing:");
    console.log("      • Use the 'URL Inspection' search bar at the very top.");
    console.log("      • Type: https://codecrux.us/");
    console.log("      • Click 'Test Live URL', then click 'Request Indexing'.");
    console.log("   ------------------------------------------------------------------\n");
    return;
  }

  try {
    console.log(`   Found Google credentials file: ${keyFile}`);
    const keyData = JSON.parse(fs.readFileSync(keyFile, "utf8"));
    const clientEmail = keyData.client_email;
    const privateKey = keyData.private_key;

    if (!clientEmail || !privateKey) {
      console.log("   ✗ Invalid Google service account JSON structure.");
      return;
    }

    console.log(`   Authorizing as: ${clientEmail}...`);

    // Build JWT
    const now = Math.floor(Date.now() / 1000);
    const header = { alg: "RS256", typ: "JWT" };
    const claimSet = {
      iss: clientEmail,
      scope: "https://www.googleapis.com/auth/indexing",
      aud: "https://oauth2.googleapis.com/token",
      exp: now + 3600,
      iat: now,
    };

    const b64Header = Buffer.from(JSON.stringify(header)).toString("base64url");
    const b64Claim = Buffer.from(JSON.stringify(claimSet)).toString("base64url");
    const signInput = `${b64Header}.${b64Claim}`;

    const signer = crypto.createSign("RSA-SHA256");
    signer.update(signInput);
    const signature = signer.sign(privateKey, "base64url");
    const jwt = `${signInput}.${signature}`;

    const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
        assertion: jwt,
      }),
    });

    const tokenData = await tokenRes.json();
    if (!tokenData.access_token) {
      console.log("   ✗ Failed to obtain Google OAuth access token:", tokenData);
      return;
    }

    const accessToken = tokenData.access_token;
    console.log("   ✓ Google OAuth token acquired successfully.");
    console.log("   Publishing URL notifications to Google Indexing API...");

    for (const url of URLS) {
      const publishRes = await fetch("https://indexing.googleapis.com/v3/urlNotifications:publish", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${accessToken}`,
        },
        body: JSON.stringify({
          url: url,
          type: "URL_UPDATED",
        }),
      });

      const resJson = await publishRes.json();
      if (publishRes.ok) {
        console.log(`   ✓ [Google Indexing API] ${url} -> Notified successfully!`);
      } else {
        console.log(`   ⚠ [Google Indexing API] ${url} -> HTTP ${publishRes.status}: ${resJson.error?.message || "Error"}`);
      }
    }
  } catch (err) {
    console.error("   ✗ Google Indexing API submission error:", err.message);
  }
  console.log("");
}

async function verifySeoArtifacts() {
  console.log("📋 [3/3] Verifying Crux Production SEO Artifacts...");
  const checks = [
    { label: "Sitemap XML", file: "public/sitemap.xml", url: `https://${HOST}/sitemap.xml` },
    { label: "Robots TXT", file: "public/robots.txt", url: `https://${HOST}/robots.txt` },
    { label: "Web App Manifest", file: "public/manifest.json", url: `https://${HOST}/manifest.json` },
    { label: "OpenGraph 1200x630 Image", file: "public/og-image.png", url: `https://${HOST}/og-image.png` },
    { label: "Apple Touch Icon", file: "public/apple-touch-icon.png", url: `https://${HOST}/apple-touch-icon.png` },
    { label: "IndexNow Key File", file: `public/${INDEXNOW_KEY}.txt`, url: `https://${HOST}/${INDEXNOW_KEY}.txt` },
    { label: "LLMs Machine Spec", file: "public/llms.txt", url: `https://${HOST}/llms.txt` },
  ];

  for (const check of checks) {
    const exists = fs.existsSync(path.resolve(process.cwd(), check.file));
    console.log(`   ${exists ? "✓" : "✗"} [${check.label}] -> ${check.file} (${exists ? "EXISTS" : "MISSING"})`);
  }

  console.log("\n==================================================================");
  console.log("   INDEXING & SEO INITIALIZATION COMPLETE                         ");
  console.log("==================================================================\n");
}

async function main() {
  await submitIndexNow();
  await submitGoogleIndexingAPI();
  await verifySeoArtifacts();
}

main().catch(console.error);
