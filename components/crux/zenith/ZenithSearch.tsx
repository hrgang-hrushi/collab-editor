"use client";

import React, { useState, useMemo, useCallback } from "react";
import { useWorkspaceStore } from "@/lib/store";

interface SearchResult {
  fileId: string;
  fileName: string;
  lineNum: number;
  lineText: string;
  matchStart: number;
  matchEnd: number;
}

interface ResultGroup {
  fileId: string;
  fileName: string;
  hits: SearchResult[];
}

export default function ZenithSearch() {
  const files = useWorkspaceStore((state) => state.files);
  const setActiveFile = useWorkspaceStore((state) => state.setActiveFile);
  const openTab = useWorkspaceStore((state) => state.openTab);
  const setCursorPos = useWorkspaceStore((state) => state.setCursorPos);

  const [query, setQuery] = useState("");
  const [caseSensitive, setCaseSensitive] = useState(false);
  const [regexMode, setRegexMode] = useState(false);
  const [regexError, setRegexError] = useState<string | null>(null);

  const results = useMemo<SearchResult[]>(() => {
    if (!query.trim()) return [];

    const out: SearchResult[] = [];

    let pattern: RegExp | null = null;
    if (regexMode) {
      try {
        pattern = new RegExp(query, caseSensitive ? "g" : "gi");
        setRegexError(null);
      } catch (e: unknown) {
        const msg = e instanceof Error ? e.message : "Invalid regex";
        setRegexError(msg);
        return [];
      }
    } else {
      setRegexError(null);
    }

    for (const file of files) {
      if (out.length >= 200) break;
      const lines = (file.content || "").split("\n");
      for (let idx = 0; idx < lines.length; idx++) {
        if (out.length >= 200) break;
        const lineText = lines[idx];

        if (regexMode && pattern) {
          // Reset lastIndex for each line
          pattern.lastIndex = 0;
          const m = pattern.exec(lineText);
          if (m) {
            out.push({
              fileId: file.id,
              fileName: file.name,
              lineNum: idx + 1,
              lineText,
              matchStart: m.index,
              matchEnd: m.index + m[0].length,
            });
          }
        } else {
          const searchIn = caseSensitive ? lineText : lineText.toLowerCase();
          const searchFor = caseSensitive ? query : query.toLowerCase();
          const matchStart = searchIn.indexOf(searchFor);
          if (matchStart !== -1) {
            out.push({
              fileId: file.id,
              fileName: file.name,
              lineNum: idx + 1,
              lineText,
              matchStart,
              matchEnd: matchStart + searchFor.length,
            });
          }
        }
      }
    }

    return out;
  }, [query, caseSensitive, regexMode, files]);

  // Group results by file
  const groups = useMemo<ResultGroup[]>(() => {
    const map = new Map<string, ResultGroup>();
    for (const r of results) {
      if (!map.has(r.fileId)) {
        map.set(r.fileId, { fileId: r.fileId, fileName: r.fileName, hits: [] });
      }
      map.get(r.fileId)!.hits.push(r);
    }
    return Array.from(map.values());
  }, [results]);

  const handleResultClick = useCallback(
    (result: SearchResult) => {
      setActiveFile(result.fileId);
      openTab(result.fileId);
      setCursorPos({ line: result.lineNum, col: 1 });
    },
    [setActiveFile, openTab, setCursorPos]
  );

  return (
    <div className="flex flex-col h-full overflow-hidden bg-[#000000]">
      {/* Search Input */}
      <div className="px-3 py-2 border-b border-[#222222] space-y-2">
        <input
          type="text"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search in files…"
          className="w-full bg-[#0A0A0A] border border-[#222222] text-white text-xs font-mono px-2 py-1.5 outline-none placeholder-[#555555] focus:border-[#444444] transition-colors"
          autoFocus
        />
        {/* Options row */}
        <div className="flex items-center gap-3 text-[10px] font-mono text-[#888888]">
          <label className="flex items-center gap-1 cursor-pointer select-none hover:text-white transition-colors">
            <input
              type="checkbox"
              checked={caseSensitive}
              onChange={(e) => setCaseSensitive(e.target.checked)}
              className="accent-[#00E5FF] w-2.5 h-2.5"
            />
            <span>Aa</span>
          </label>
          <label className="flex items-center gap-1 cursor-pointer select-none hover:text-white transition-colors">
            <input
              type="checkbox"
              checked={regexMode}
              onChange={(e) => setRegexMode(e.target.checked)}
              className="accent-[#00E5FF] w-2.5 h-2.5"
            />
            <span>.*</span>
          </label>
          {/* Result count */}
          {query.trim() && !regexError && (
            <span className="ml-auto px-1.5 py-0.5 bg-[#0A0A0A] border border-[#222222] text-[#888888] text-[9px]">
              {results.length >= 200 ? "200+" : results.length} result
              {results.length !== 1 ? "s" : ""}
            </span>
          )}
        </div>
        {regexError && (
          <p className="text-[10px] font-mono text-[#FF453A] truncate">{regexError}</p>
        )}
      </div>

      {/* Results */}
      <div className="flex-1 overflow-y-auto font-mono text-xs">
        {!query.trim() && (
          <p className="px-3 py-4 text-[#555555] text-[11px]">
            Type to search across all files.
          </p>
        )}

        {query.trim() && groups.length === 0 && !regexError && (
          <p className="px-3 py-4 text-[#555555] text-[11px]">No results found.</p>
        )}

        {groups.map((group) => (
          <div key={group.fileId}>
            {/* File header */}
            <div className="sticky top-0 px-3 py-1 bg-[#0A0A0A] border-b border-[#222222] text-[#888888] text-[10px] tracking-wide flex items-center justify-between z-10">
              <span className="truncate text-white">{group.fileName}</span>
              <span className="ml-2 shrink-0 text-[#555555]">{group.hits.length}</span>
            </div>

            {/* Hits */}
            {group.hits.map((hit, i) => (
              <div
                key={`${hit.fileId}-${hit.lineNum}-${i}`}
                onClick={() => handleResultClick(hit)}
                className="flex items-start gap-2 px-3 py-1 cursor-pointer hover:bg-[#0A0A0A] border-b border-[#111111] group transition-colors"
              >
                {/* Line number */}
                <span className="shrink-0 text-[#444444] w-8 text-right pt-px select-none">
                  {hit.lineNum}
                </span>
                {/* Line text with highlight */}
                <span className="text-[#888888] group-hover:text-white truncate transition-colors">
                  {hit.lineText.slice(0, hit.matchStart)}
                  <mark className="bg-[#00E5FF22] text-[#00E5FF] not-italic">
                    {hit.lineText.slice(hit.matchStart, hit.matchEnd)}
                  </mark>
                  {hit.lineText.slice(hit.matchEnd)}
                </span>
              </div>
            ))}
          </div>
        ))}

        {results.length >= 200 && (
          <p className="px-3 py-2 text-[#555555] text-[10px] border-t border-[#222222]">
            Showing first 200 results. Narrow your search.
          </p>
        )}
      </div>
    </div>
  );
}
