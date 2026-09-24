"use client";

import React, { isValidElement, useLayoutEffect, useEffect, useRef, useState } from "react";
import { HugeiconsIcon } from "@hugeicons/react";
import "./BranchedMenu.css";

const useIsomorphicLayoutEffect = typeof window !== "undefined" ? useLayoutEffect : useEffect;

export interface BranchedMenuChildItem {
  value: string;
  label: string;
  icon?: any;
  actions?: React.ReactNode;
  renderLabel?: () => React.ReactNode;
  draggable?: boolean;
  onDragStart?: (e: React.DragEvent) => void;
  onDragOver?: (e: React.DragEvent) => void;
  onDragLeave?: (e: React.DragEvent) => void;
  onDrop?: (e: React.DragEvent) => void;
  onDoubleClick?: (e: React.MouseEvent) => void;
  [key: string]: any;
}

export interface BranchedMenuItem {
  label: string;
  value?: string;
  icon?: any;
  children?: BranchedMenuChildItem[];
  actions?: React.ReactNode;
  renderLabel?: () => React.ReactNode;
  draggable?: boolean;
  onDragStart?: (e: React.DragEvent) => void;
  onDragOver?: (e: React.DragEvent) => void;
  onDragLeave?: (e: React.DragEvent) => void;
  onDrop?: (e: React.DragEvent) => void;
  [key: string]: any;
}

export interface BranchedMenuProps {
  items: BranchedMenuItem[];
  defaultOpen?: number | number[];
  defaultActive?: string;
  active?: string;
  onSelect?: (value: string, item: BranchedMenuItem | BranchedMenuChildItem) => void;
  onToggle?: (index: number, open: boolean) => void;
  color?: string;
  accentColor?: string;
  lineColor?: string;
  width?: number | string;
  rowHeight?: number;
  indent?: number;
  trunk?: number;
  radius?: number;
  lineWidth?: number;
  fontSize?: number;
  drawDuration?: number;
  foldDuration?: number;
  className?: string;
}

const PAD = 6;
const MARK = 16;

const renderIcon = (icon: any) => {
  if (!icon) return null;
  if (isValidElement(icon)) return icon;
  return <HugeiconsIcon icon={icon} size={15} strokeWidth={1.8} />;
};

const toSet = (open: number | number[] | undefined): Set<number> => {
  if (Array.isArray(open)) return new Set(open);
  if (typeof open === "number" && open >= 0) return new Set([open]);
  return new Set();
};

export default function BranchedMenu({
  items = [],
  defaultOpen = [0],
  defaultActive = "",
  active: controlledActive,
  onSelect,
  onToggle,
  color = "#888888",
  accentColor = "#ffffff",
  lineColor = "#222222",
  width = 240,
  rowHeight = 32,
  indent = 36,
  trunk = 12,
  radius = 8,
  lineWidth = 1.5,
  fontSize = 12,
  drawDuration = 350,
  foldDuration = 250,
  className = "",
}: BranchedMenuProps) {
  const [open, setOpen] = useState<Set<number>>(() => toSet(defaultOpen));
  const [internalActive, setInternalActive] = useState<string>(() => {
    if (controlledActive !== undefined) return controlledActive;
    if (defaultActive) return defaultActive;
    const first = items.find((it, i) => it.children && toSet(defaultOpen).has(i));
    return first?.children?.[0]?.value ?? "";
  });

  const active = controlledActive !== undefined ? controlledActive : internalActive;

  const navRef = useRef<HTMLElement>(null);
  const heads = useRef<(HTMLElement | null)[]>([]);
  const markerRef = useRef<HTMLSpanElement>(null);
  const latest = useRef<{
    onSelect?: (value: string, item: BranchedMenuItem | BranchedMenuChildItem) => void;
    onToggle?: (index: number, open: boolean) => void;
  }>({});
  latest.current = { onSelect, onToggle };

  const activeSection = items.findIndex(
    (it) => it.children?.some((kid) => kid.value === active) || (!it.children && (it.value ?? it.label) === active)
  );
  const markerShown = activeSection >= 0 && (open.has(activeSection) || !items[activeSection]?.children);

  useEffect(() => {
    if (activeSection >= 0 && !open.has(activeSection)) {
      setOpen((prev) => new Set([...prev, activeSection]));
    }
  }, [activeSection]);

  useIsomorphicLayoutEffect(() => {
    const place = (glide: boolean) => {
      const m = markerRef.current;
      const el = heads.current[activeSection];
      if (!m) return;
      const on = markerShown && el;
      if (!glide) m.style.transition = "none";
      if (on && el) {
        m.style.top = `${el.offsetTop + (el.offsetHeight - MARK) / 2}px`;
      }
      m.toggleAttribute("data-on", Boolean(on));
      if (!glide) {
        void m.offsetHeight;
        m.style.transition = "";
      }
    };
    place(true);
    let first = true;
    const ro = new ResizeObserver(() => {
      if (first) {
        first = false;
        return;
      }
      place(false);
    });
    if (navRef.current) ro.observe(navRef.current);
    return () => ro.disconnect();
  }, [activeSection, markerShown, items, fontSize, rowHeight, open]);

  const select = (value: string, item: BranchedMenuItem | BranchedMenuChildItem) => {
    if (controlledActive === undefined) {
      setInternalActive(value);
    }
    latest.current.onSelect?.(value, item);
  };

  const toggle = (i: number) => {
    setOpen((prev) => {
      const next = new Set(prev);
      const isOpen = !next.has(i);
      if (isOpen) next.add(i);
      else next.delete(i);
      latest.current.onToggle?.(i, isOpen);
      return next;
    });
  };

  const r = Math.min(radius, rowHeight / 2 - 2);
  const endX = indent - 8;
  const rowY = (k: number) => PAD + k * rowHeight + rowHeight / 2;
  const branch = (k: number) => `M ${trunk} ${rowY(k) - r} A ${r} ${r} 0 0 0 ${trunk + r} ${rowY(k)} H ${endX}`;
  const reach = (k: number) => `M ${trunk} 0 V ${rowY(k) - r} A ${r} ${r} 0 0 0 ${trunk + r} ${rowY(k)} H ${endX}`;
  const length = (k: number) => rowY(k) - r + (Math.PI * r) / 2 + (endX - trunk - r);

  return (
    <nav
      ref={navRef}
      className={`branched-menu${className ? ` ${className}` : ""}`}
      style={
        {
          "--bm-w": typeof width === "number" ? `${width}px` : width,
          "--bm-ink": color,
          "--bm-accent": accentColor,
          "--bm-line": lineColor,
          "--bm-font": `${fontSize}px`,
          "--bm-row": `${rowHeight}px`,
          "--bm-indent": `${indent}px`,
          "--bm-line-w": lineWidth,
          "--bm-draw": `${drawDuration}ms`,
          "--bm-fold": `${foldDuration}ms`,
        } as React.CSSProperties
      }
    >
      <span ref={markerRef} className="branched-menu__marker" aria-hidden="true" />
      {items.map((item, i) => {
        const kids = item.children;
        const isOpen = kids ? open.has(i) : false;
        const leafValue = item.value ?? item.label;
        const leafActive = !kids && leafValue === active;
        const bodyH = kids ? PAD * 2 + kids.length * rowHeight : 0;

        return (
          <div
            key={item.value ?? item.label ?? i}
            className="branched-menu__section"
            data-open={isOpen ? "" : undefined}
          >
            <button
              ref={(el) => {
                heads.current[i] = el;
              }}
              type="button"
              className="branched-menu__head"
              aria-expanded={kids ? isOpen : undefined}
              aria-current={leafActive ? "true" : undefined}
              data-active={leafActive ? "" : undefined}
              draggable={item.draggable}
              onDragStart={item.onDragStart}
              onDragOver={item.onDragOver}
              onDragLeave={item.onDragLeave}
              onDrop={item.onDrop}
              onClick={() => (kids ? toggle(i) : select(leafValue, item))}
            >
              <div className="branched-menu__head-left">
                {item.icon && <span className="branched-menu__icon">{renderIcon(item.icon)}</span>}
                <span className="branched-menu__label">
                  {item.renderLabel ? item.renderLabel() : item.label}
                </span>
              </div>
              {item.actions && <div className="branched-menu__actions">{item.actions}</div>}
            </button>

            {kids && kids.length > 0 ? (
              <div className="branched-menu__body">
                <div className="branched-menu__fold">
                  <div className="branched-menu__tree" style={{ height: bodyH }}>
                    <svg className="branched-menu__lines" width={indent} height={bodyH} aria-hidden="true">
                      {/* Vertical Trunk */}
                      <path
                        className="branched-menu__base"
                        d={`M ${trunk} 0 V ${rowY(kids.length - 1) - r}`}
                      />
                      {/* Base Branch Arcs */}
                      {kids.map((kid, k) => (
                        <path key={kid.value} className="branched-menu__base" d={branch(k)} />
                      ))}
                      {/* Animated Reach Arcs to Active Child */}
                      {kids.map((kid, k) => (
                        <path
                          key={kid.value}
                          className="branched-menu__reach"
                          d={reach(k)}
                          style={{
                            strokeDasharray: length(k),
                            strokeDashoffset: kid.value === active ? 0 : length(k),
                          }}
                        />
                      ))}
                    </svg>

                    {/* Child Item Buttons */}
                    {kids.map((kid) => (
                      <div
                        key={kid.value}
                        className="branched-menu__item"
                        aria-current={kid.value === active ? "true" : undefined}
                        data-active={kid.value === active ? "" : undefined}
                        tabIndex={isOpen ? 0 : -1}
                        draggable={kid.draggable}
                        onDragStart={kid.onDragStart}
                        onDragOver={kid.onDragOver}
                        onDragLeave={kid.onDragLeave}
                        onDrop={kid.onDrop}
                        onClick={() => select(kid.value, kid)}
                        onDoubleClick={kid.onDoubleClick}
                      >
                        <div className="branched-menu__item-left">
                          {kid.icon ? (
                            <span className="branched-menu__icon" aria-hidden="true">
                              {renderIcon(kid.icon)}
                            </span>
                          ) : null}
                          <span className="branched-menu__label" title={kid.value}>
                            {kid.renderLabel ? kid.renderLabel() : kid.label}
                          </span>
                        </div>
                        {kid.actions ? (
                          <div className="branched-menu__actions">{kid.actions}</div>
                        ) : null}
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            ) : null}
          </div>
        );
      })}
    </nav>
  );
}
