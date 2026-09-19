/**
 * Crex Remote Cursor Interpolator (Framer Motion + Spring Physics)
 * 
 * Provides 60fps linear interpolation (lerping) and spatial awareness tracking
 * for remote peers gliding across editor coordinates even over stuttering networks.
 */

"use client";

import React, { useEffect, useState, useRef } from "react";
import { motion, useSpring, useMotionValue } from "framer-motion";
import { Awareness } from "y-protocols/awareness";
import { EditorView } from "@codemirror/view";
import * as Y from "yjs";
import { ySyncFacet } from "y-codemirror.next";

interface RemoteCursorInterpolationProps {
  view: EditorView | null;
  awareness: Awareness | null;
}

interface PeerInterpolationState {
  clientID: number;
  name: string;
  color: string;
  uid: string;
  isIdle: boolean;
  isTyping: boolean;
  x: number;
  y: number;
  visible: boolean;
}

/**
 * Single Smoothly Lerped Peer Cursor Element using Framer Motion Spring
 */
const SmoothPeerCursor: React.FC<{ peer: PeerInterpolationState }> = ({ peer }) => {
  // Motion values with high-speed, critically damped springs (sub-10ms feel)
  const springX = useSpring(peer.x, { stiffness: 450, damping: 35 });
  const springY = useSpring(peer.y, { stiffness: 450, damping: 35 });

  useEffect(() => {
    springX.set(peer.x);
    springY.set(peer.y);
  }, [peer.x, peer.y, springX, springY]);

  if (!peer.visible) return null;

  const isLight = peer.color.toLowerCase() === "#ffffff" || peer.color.toLowerCase() === "#fff";

  return (
    <motion.div
      className="absolute top-0 left-0 pointer-events-none select-none z-50"
      style={{
        x: springX,
        y: springY,
        willChange: "transform",
      }}
    >
      {/* 2px Solid or Dashed Vertical Line */}
      <div
        className="w-[2px] h-[1.25em]"
        style={{
          backgroundColor: peer.isIdle ? "transparent" : peer.color,
          borderLeft: peer.isIdle ? "2px dashed #444444" : "none",
          borderRadius: "0px",
        }}
      />

      {/* Sharp 0px-radius rectangular name tag pinned above cursor */}
      <div
        className="absolute bottom-full left-0 mb-[2px] px-1 py-[1px] font-sans text-[10px] font-semibold uppercase leading-none tracking-[0px] whitespace-nowrap border border-[#222222]"
        style={{
          backgroundColor: peer.color,
          color: isLight ? "#000000" : "#FFFFFF",
          borderRadius: "0px",
          opacity: peer.isIdle ? 0.5 : 1.0,
          borderColor: peer.isIdle ? "#444444" : "#222222",
        }}
      >
        <span>{peer.name}</span>
        {peer.isTyping && <span className="ml-1 text-[8px] animate-pulse">●</span>}
      </div>
    </motion.div>
  );
};

export default function RemoteCursorInterpolator({ view, awareness }: RemoteCursorInterpolationProps) {
  const [peers, setPeers] = useState<PeerInterpolationState[]>([]);
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!view || !awareness) return;

    const updatePeers = () => {
      const conf = view.state.facet(ySyncFacet);
      if (!conf) return;

      const ytext = conf.ytext;
      const ydoc = ytext.doc;
      if (!ydoc) return;

      const updatedPeers: PeerInterpolationState[] = [];
      const now = Date.now();
      const containerRect = containerRef.current
        ? containerRef.current.getBoundingClientRect()
        : view.dom.getBoundingClientRect();

      awareness.getStates().forEach((state: any, clientID: number) => {
        if (clientID === ydoc.clientID) return;
        if (!state || !state.cursor) return;

        const headPos = Y.createAbsolutePositionFromRelativePosition(state.cursor.head, ydoc);
        if (!headPos || headPos.type !== ytext) return;

        const coords = view.coordsAtPos(headPos.index);
        if (!coords) return;

        // Verify if cursor is within visible vertical range
        const isVisible =
          coords.top >= containerRect.top - 20 &&
          coords.top <= containerRect.bottom + 20;

        const user = state.user || {};
        const name = user.name || `Peer-${clientID.toString().slice(-4)}`;
        const color = user.color || "#FFFFFF";
        const uid = user.uid || "CRX-PEER";
        const lastActive = state.lastActive || 0;
        const isIdle = now - lastActive > 3000;
        const isTyping = !isIdle && !!state.isTyping;

        // Relative coordinates inside the interpolator container DOM
        const relX = coords.left - containerRect.left;
        const relY = coords.top - containerRect.top;

        updatedPeers.push({
          clientID,
          name,
          color,
          uid,
          isIdle,
          isTyping,
          x: relX,
          y: relY,
          visible: isVisible,
        });
      });

      setPeers(updatedPeers);
    };

    awareness.on("change", updatePeers);
    const scrollEl = view.scrollDOM;
    if (scrollEl) {
      scrollEl.addEventListener("scroll", updatePeers, { passive: true });
    }
    window.addEventListener("resize", updatePeers);
    const interval = setInterval(updatePeers, 100);

    return () => {
      awareness.off("change", updatePeers);
      if (scrollEl) {
        scrollEl.removeEventListener("scroll", updatePeers);
      }
      window.removeEventListener("resize", updatePeers);
      clearInterval(interval);
    };
  }, [view, awareness]);

  return (
    <div ref={containerRef} className="absolute inset-0 pointer-events-none overflow-hidden z-40">
      {peers.map((peer) => (
        <SmoothPeerCursor key={peer.clientID} peer={peer} />
      ))}
    </div>
  );
}
