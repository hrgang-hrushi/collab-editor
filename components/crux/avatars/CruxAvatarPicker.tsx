"use client";

import React from "react";
import { BotAvatar, botAvatarTypes, type BotAvatarType } from "bot-avatars";
import { avatarMotionSeed } from "./avatarMotion";

interface CruxAvatarPickerProps {
  value: BotAvatarType;
  onChange: (type: BotAvatarType) => void;
  compact?: boolean;
  identity?: string;
}

export default function CruxAvatarPicker({ value, onChange, compact = false, identity = "local" }: CruxAvatarPickerProps) {
  const seed = avatarMotionSeed(identity);
  return (
    <fieldset className="space-y-2">
      <legend className="text-[9px] uppercase tracking-widest text-[#888888] font-mono">
        Choose your avatar
      </legend>
      <div className={`grid gap-1.5 ${compact ? "grid-cols-6 sm:grid-cols-9" : "grid-cols-6"}`}>
        {botAvatarTypes.map((type) => (
          <button
            key={type}
            type="button"
            onClick={() => onChange(type)}
            aria-label={`${type} avatar`}
            aria-pressed={value === type}
            title={type}
            className={`min-w-0 border p-1.5 flex items-center justify-center transition-none ${
              value === type
                ? "border-white bg-[#222222]"
                : "border-[#222222] bg-[#111111] hover:border-white"
            }`}
          >
            <BotAvatar type={type} size={compact ? 32 : 40} state="default" seed={seed} interactive={false} theme="dark" />
          </button>
        ))}
      </div>
      <div className="text-[10px] font-mono uppercase text-white">Selected: {value}</div>
    </fieldset>
  );
}
