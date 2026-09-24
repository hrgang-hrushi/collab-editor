"use client";

import React, { useState, useEffect, useMemo } from "react";

interface PixelGridTransitionProps {
  color?: string;
  columns?: number;
  rowMultiplier?: number;
  squareDuration?: number;
  maxDelay?: number;
  zIndex?: number;
}

export default function PixelGridTransition({
  color = "#0055FF",
  columns = 12,
  rowMultiplier = 3,
  squareDuration = 0.5,
  maxDelay = 0.6,
  zIndex = 9999,
}: PixelGridTransitionProps) {
  const [mounted, setMounted] = useState(false);
  const [revealed, setRevealed] = useState(false);
  const [squareSize, setSquareSize] = useState(100);
  const totalRows = Math.ceil(columns * rowMultiplier);

  useEffect(() => {
    const updateSize = () => {
      setSquareSize(window.innerWidth / columns);
      setMounted(true);
    };

    updateSize();
    window.addEventListener("resize", updateSize);

    // Trigger reveal transition on next frame
    const timer = requestAnimationFrame(() => {
      setRevealed(true);
    });

    return () => {
      window.removeEventListener("resize", updateSize);
      cancelAnimationFrame(timer);
    };
  }, [columns]);

  const delays = useMemo(() => {
    const count = columns * totalRows;
    return Array.from({ length: count }, () => Math.random() * maxDelay);
  }, [columns, totalRows, maxDelay]);

  // Clean up completely after transition completes
  const [isVisible, setIsVisible] = useState(true);
  useEffect(() => {
    const totalTime = (squareDuration + maxDelay) * 1000 + 400;
    const hideTimer = setTimeout(() => {
      setIsVisible(false);
    }, totalTime);
    return () => clearTimeout(hideTimer);
  }, [squareDuration, maxDelay]);

  if (!mounted || !isVisible) return null;

  return (
    <div
      style={{
        position: "fixed",
        inset: 0,
        width: "100vw",
        height: "100vh",
        overflow: "hidden",
        display: "grid",
        gridTemplateColumns: mounted
          ? `repeat(${columns}, ${squareSize}px)`
          : `repeat(${columns}, 1fr)`,
        gridTemplateRows: mounted
          ? `repeat(${totalRows}, ${squareSize}px)`
          : `repeat(${totalRows}, 1fr)`,
        pointerEvents: "none",
        zIndex,
      }}
    >
      {delays.map((delay, index) => (
        <div
          key={index}
          style={{
            backgroundColor: color,
            opacity: revealed ? 0 : 1,
            transition: `opacity ${squareDuration}s ease`,
            transitionDelay: `${delay}s`,
          }}
        />
      ))}
    </div>
  );
}
