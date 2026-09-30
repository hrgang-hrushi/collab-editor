"use client";

type Shot = "editor" | "canvas" | "collaboration" | "ai";

const descriptions: Record<Shot, string> = {
  editor: "Recorded Crux editor and terminal",
  canvas: "Recorded Crux spatial canvas",
  collaboration: "Recorded Crux multiplayer editing",
  ai: "Recorded Crux AI Assistant panel",
};

export default function RecordedIdePreview({ shot }: { shot: Shot }) {
  return (
    <div className="flex h-full w-full items-center justify-center overflow-hidden bg-black">
      <video
        key={shot}
        src={`/landing-demo/${shot}.mp4?v=20260930-current`}
        poster={`/landing-demo/${shot}.jpg?v=20260930-current`}
        aria-label={descriptions[shot]}
        autoPlay
        muted
        loop
        playsInline
        preload="auto"
        className="pointer-events-none h-full w-full object-cover"
      />
    </div>
  );
}
