"use client";

import { useEffect, useRef, useState } from "react";

type CaptureState = "idle" | "starting" | "preview" | "recording" | "saving" | "saved" | "error";

/** Local development capture of the actual tab, enabled with ?demo=1. */
export default function DemoRecorder() {
  const [enabled, setEnabled] = useState(false);
  const [shot, setShot] = useState("landing");
  const [surface, setSurface] = useState<"browser" | "window">("browser");
  const [state, setState] = useState<CaptureState>("idle");
  const [message, setMessage] = useState("");
  const recorderRef = useRef<MediaRecorder | null>(null);
  const streamRef = useRef<MediaStream | null>(null);
  const chunksRef = useRef<Blob[]>([]);
  const previewRef = useRef<HTMLVideoElement | null>(null);
  const shotRef = useRef(shot);
  const captureRequestRef = useRef(0);

  useEffect(() => {
    setEnabled(new URLSearchParams(window.location.search).get("demo") === "1");
  }, []);

  useEffect(() => {
    shotRef.current = shot;
  }, [shot]);

  const stop = () => {
    if (state === "starting") {
      captureRequestRef.current += 1;
      setState("idle");
      setMessage("Source selection canceled. Choose a source to try again.");
      return;
    }
    const recorder = recorderRef.current;
    if (recorder?.state === "recording") recorder.stop();
    streamRef.current?.getTracks().forEach((track) => track.stop());
    if (recorder?.state !== "recording" && state === "preview") setState("idle");
  };

  useEffect(() => {
    if (state === "preview" && previewRef.current && streamRef.current) {
      previewRef.current.srcObject = streamRef.current;
      void previewRef.current.play();
    }
  }, [state]);

  useEffect(() => {
    if (!enabled) return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.altKey && event.shiftKey && event.key.toLowerCase() === "r") {
        event.preventDefault();
        stop();
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [enabled, state]);

  const chooseTab = async () => {
    if (!navigator.mediaDevices?.getDisplayMedia || !window.MediaRecorder) {
      setState("error");
      setMessage("This browser cannot record a display. Use a browser with screen capture support.");
      return;
    }
    setState("starting");
    setMessage(surface === "browser" ? "Choose this browser tab in the share picker." : "Choose the Crux app window in the share picker.");
    const requestId = ++captureRequestRef.current;
    try {
      const captureOptions = {
        video: { frameRate: 30, displaySurface: surface },
        audio: false,
        preferCurrentTab: surface === "browser",
        selfBrowserSurface: "include",
      } as DisplayMediaStreamOptions & { preferCurrentTab: boolean; selfBrowserSurface: "include" };
      const stream = await navigator.mediaDevices.getDisplayMedia(captureOptions);
      if (requestId !== captureRequestRef.current) {
        stream.getTracks().forEach((track) => track.stop());
        return;
      }
      streamRef.current = stream;
      const track = stream.getVideoTracks()[0];
      const settings = track.getSettings();
      setState("preview");
      setMessage(`${track.label || "Captured surface"} · ${settings.width || "?"}×${settings.height || "?"}. Confirm the preview shows this demo tab.`);
      track.onended = () => {
        if (recorderRef.current?.state === "recording") recorderRef.current.stop();
        else setState("idle");
      };
    } catch (error) {
      if (requestId !== captureRequestRef.current) return;
      streamRef.current?.getTracks().forEach((track) => track.stop());
      setState("error");
      setMessage(String(error));
    }
  };

  const beginRecording = () => {
    const stream = streamRef.current;
    if (!stream?.active) {
      setState("error");
      setMessage("Capture ended. Choose the tab again.");
      return;
    }
    try {
      const mimeType = ["video/webm;codecs=vp9", "video/webm;codecs=vp8", "video/webm", "video/mp4"].find((type) => MediaRecorder.isTypeSupported(type));
      if (!mimeType) throw new Error("Video recording is unavailable in this browser");
      const contentType = mimeType.startsWith("video/mp4") ? "video/mp4" : "video/webm";
      const recorder = new MediaRecorder(stream, { mimeType, videoBitsPerSecond: 5_000_000 });
      recorderRef.current = recorder;
      chunksRef.current = [];
      recorder.ondataavailable = (event) => {
        if (event.data.size) chunksRef.current.push(event.data);
      };
      recorder.onstop = async () => {
        stream.getTracks().forEach((track) => track.stop());
        setState("saving");
        try {
          const blob = new Blob(chunksRef.current, { type: mimeType });
          if (blob.size < 1024) throw new Error("Recording was empty");
          const response = await fetch(`/api/demo-recordings?shot=${encodeURIComponent(shotRef.current)}`, {
            method: "POST",
            headers: { "Content-Type": contentType },
            body: blob,
          });
          const result = await response.json();
          if (!response.ok) throw new Error(result.error || "Could not save recording");
          setMessage(`${result.path} (${Math.round(blob.size / 1024)} KB)`);
          setState("saved");
        } catch (error) {
          setMessage(String(error));
          setState("error");
        }
      };
      recorder.start(1000);
      setState("recording");
      setMessage("");
    } catch (error) {
      streamRef.current?.getTracks().forEach((track) => track.stop());
      setState("error");
      setMessage(String(error));
    }
  };

  if (!enabled) return null;
  if (state === "recording" || state === "saving") {
    return (
      <div className="fixed bottom-2 right-2 z-[100] border border-[#444444] bg-black px-2 py-1 text-[11px] font-mono text-white" aria-live="polite">
        {state === "recording" ? (
          <button onClick={stop} className="text-white hover:underline" aria-label="Stop demo recording">
            REC ●  STOP RECORDING
          </button>
        ) : "SAVING CAPTURE..."}
      </div>
    );
  }

  return (
    <div className="fixed bottom-2 right-2 z-[100] flex max-w-[340px] flex-col gap-2 border border-[#444444] bg-black p-2 text-[11px] font-mono text-white" aria-label="Demo recording controls">
      <div>LOCAL DEMO CAPTURE / ACTUAL SOURCE</div>
      <label className="flex items-center gap-2">
        SHOT
        <input aria-label="Demo shot name" value={shot} onChange={(event) => setShot(event.target.value)} className="min-w-0 flex-1 border border-[#444444] bg-black px-1 py-0.5 text-white outline-none focus:border-white" />
      </label>
      <label className="flex items-center gap-2">
        SOURCE
        <select aria-label="Demo capture source" value={surface} onChange={(event) => setSurface(event.target.value as "browser" | "window")} className="flex-1 border border-[#444444] bg-black px-1 py-0.5 text-white">
          <option value="browser">THIS TAB</option>
          <option value="window">APP WINDOW</option>
        </select>
      </label>
      {state === "preview" && <video ref={previewRef} muted playsInline className="max-h-40 w-full border border-[#444444] object-contain" aria-label="Capture preview" />}
      <button onClick={state === "preview" ? beginRecording : chooseTab} disabled={state === "starting"} className="border border-[#444444] bg-[#111111] px-2 py-1 text-left hover:border-white hover:bg-white hover:text-black disabled:opacity-50">
        {state === "starting" ? "SELECT SOURCE..." : state === "preview" ? "CONFIRM AND RECORD" : "CHOOSE SOURCE TO RECORD"}
      </button>
      {(state === "preview" || state === "starting") && <button onClick={stop} className="border border-[#444444] px-2 py-1 text-left hover:border-white">CANCEL CAPTURE</button>}
      {message && <div role="status" className="break-all text-[#aaaaaa]">{message}</div>}
    </div>
  );
}
