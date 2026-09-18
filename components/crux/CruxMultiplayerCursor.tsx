"use client";

import React from "react";
import CruxPointerCursor from "./CruxPointerCursor";

interface CruxMultiplayerCursorProps {
  name?: string;
  uid?: string;
  status?: string;
  color?: string;
  x?: number;
  y?: number;
}

export default function CruxMultiplayerCursor({
  name = "Sarah Lin",
  uid = "CRX-9941-SL",
  status,
  color = "#007AFF",
  x,
  y,
}: CruxMultiplayerCursorProps) {
  return (
    <CruxPointerCursor
      name={name}
      uid={uid}
      status={status}
      color={color}
      x={x}
      y={y}
    />
  );
}
