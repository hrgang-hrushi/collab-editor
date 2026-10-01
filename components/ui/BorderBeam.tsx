"use client";

import React, { useState, useEffect } from "react";
import {
  BorderBeam as RawBorderBeam,
  type BorderBeamProps,
  type BorderBeamSize,
  type BorderBeamColorVariant,
} from "border-beam";

export type { BorderBeamProps, BorderBeamSize, BorderBeamColorVariant };

/**
 * SSR-safe BorderBeam wrapper for Next.js
 * Prevents hydration mismatch caused by raw unescaped CSS @property text in SSR <style> tags.
 */
export function BorderBeam({
  children,
  className,
  style,
  ...props
}: BorderBeamProps) {
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
  }, []);

  if (!mounted) {
    return (
      <div className={className} style={style}>
        {children}
      </div>
    );
  }

  return (
    <RawBorderBeam className={className} style={style} {...props}>
      {children}
    </RawBorderBeam>
  );
}

export default BorderBeam;
