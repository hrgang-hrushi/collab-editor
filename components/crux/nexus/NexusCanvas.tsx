"use client";

import React, { useRef, useState, useEffect } from "react";
import { useWorkspaceStore } from "@/lib/store";
import EditorNode from "@/components/canvas/EditorNode";
import ConnectorLayer from "@/components/canvas/ConnectorLayer";
import CursorLayer from "@/components/multiplayer/CursorLayer";
import PipelineTracker from "@/components/canvas/PipelineTracker";
import { initCrexCanvasSession, CrexCRDTSession } from "@/lib/crdt/yjsProvider";
import { isTauriDesktop, readDroppedItems, readFileList, readNativeDirectory } from "@/lib/fileUtils";
import {
  Layers,
  ZoomIn,
  ZoomOut,
  RotateCcw,
  X,
  Plus,
  Activity,
  Pause,
  Play,
  FolderPlus,
  Upload,
  Zap,
} from "lucide-react";

interface NexusCanvasProps {
  onSwitchToZenith: (fileId?: string) => void;
}

export default function NexusCanvas({ onSwitchToZenith }: NexusCanvasProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const folderInputRef = useRef<HTMLInputElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const files = useWorkspaceStore((state) => state.files);
  const edges = useWorkspaceStore((state) => state.edges);
  const canvasTransform = useWorkspaceStore((state) => state.canvasTransform);
  const setCanvasTransform = useWorkspaceStore((state) => state.setCanvasTransform);
  const zoomBy = useWorkspaceStore((state) => state.zoomBy);
  const resetView = useWorkspaceStore((state) => state.resetView);
  const isConnecting = useWorkspaceStore((state) => state.isConnectingNodes);
  const cancelConnection = useWorkspaceStore((state) => state.cancelConnection);
  const createFile = useWorkspaceStore((state) => state.createFile);
  const importFiles = useWorkspaceStore((state) => state.importFiles);
  const importFolders = useWorkspaceStore((state) => state.importFolders);
  const setLastImportStatus = useWorkspaceStore((state) => state.setLastImportStatus);
  const flowSpeedFactor = useWorkspaceStore((state) => state.flowSpeedFactor);
  const setFlowSpeedFactor = useWorkspaceStore((state) => state.setFlowSpeedFactor);
  const isFlowPaused = useWorkspaceStore((state) => state.isFlowPaused);
  const toggleFlowPause = useWorkspaceStore((state) => state.toggleFlowPause);
  const isPipelineTrackerOpen = useWorkspaceStore((state) => state.isPipelineTrackerOpen);
  const togglePipelineTracker = useWorkspaceStore((state) => state.togglePipelineTracker);

  const [isPanning, setIsPanning] = useState(false);
  const [spacePressed, setSpacePressed] = useState(false);
  const [isNewNodeModalOpen, setIsNewNodeModalOpen] = useState(false);
  const [newNodeName, setNewNodeName] = useState("");
  const [isDragOver, setIsDragOver] = useState(false);
  const panStartRef = useRef<{ x: number; y: number; panX: number; panY: number } | null>(null);

  const panX = Number.isFinite(canvasTransform?.panX) ? canvasTransform.panX : 80;
  const panY = Number.isFinite(canvasTransform?.panY) ? canvasTransform.panY : 60;
  const zoom = Number.isFinite(canvasTransform?.zoom) && canvasTransform.zoom > 0 ? canvasTransform.zoom : 0.52;

  const currentUser = useWorkspaceStore((state) => state.currentUser);
  const canvasSessionRef = useRef<CrexCRDTSession | null>(null);

  useEffect(() => {
    if (!files || files.length === 0) {
      useWorkspaceStore.getState().loadStarterWorkspace();
    }
  }, [files?.length]);

  // Real-time WebRTC Multiplayer Synchronization on Spatial Canvas
  useEffect(() => {
    const session = initCrexCanvasSession({
      name: currentUser.name || "Collaborator",
      color: currentUser.color || "#38b6ff",
      uid: currentUser.uid || "CRX-PEER",
    });
    canvasSessionRef.current = session;

    const handleCanvasAwareness = () => {
      try {
        const states = session.awareness.getStates();
        const activePeerIds = new Set<string>();

        states.forEach((state: any, clientID: number) => {
          if (clientID === session.ydoc.clientID) return;
          const peerKey = `canvas-client-${clientID}`;
          activePeerIds.add(peerKey);

          if (state && state.canvasMouse && state.user) {
            const u = state.user;
            useWorkspaceStore.getState().updateRemoteCursor(peerKey, {
              userId: peerKey,
              userName: u.name || `Peer-${clientID.toString().slice(-4)}`,
              userColor: u.color || "#38b6ff",
              userUid: u.uid || `CRX-${clientID.toString().slice(-4)}`,
              activeFileId: state.canvasMouse.activeFileId,
              x: state.canvasMouse.x,
              y: state.canvasMouse.y,
              targetX: state.canvasMouse.x,
              targetY: state.canvasMouse.y,
              status: state.canvasMouse.status || (state.isTyping ? "typing" : undefined),
              isTyping: !!(state.canvasMouse.status === "typing" || state.isTyping),
              lastUpdated: Date.now(),
            });
          }
        });

        useWorkspaceStore.getState().pruneRemoteCursors(activePeerIds);
      } catch {
        // ignore
      }
    };

    session.awareness.on("change", handleCanvasAwareness);
    return () => {
      session.awareness.off("change", handleCanvasAwareness);
    };
  }, [currentUser]);

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const uploadedFiles = e.target.files;
    if (!uploadedFiles || uploadedFiles.length === 0) return;
    const imported = await readFileList(uploadedFiles);
    if (imported.length) importFiles(imported);
    setLastImportStatus(`Imported ${imported.length} files${uploadedFiles.length > imported.length ? ` · ${uploadedFiles.length - imported.length} skipped (large, unreadable, or ignored)` : ""}`);
    e.target.value = "";
  };

  const handleFolderUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const uploadedFiles = e.target.files;
    if (!uploadedFiles || uploadedFiles.length === 0) return;

    const imported = await readFileList(uploadedFiles);
    const rootFolder = uploadedFiles[0]?.webkitRelativePath?.split("/")[0];
    if (rootFolder) importFolders([rootFolder]);
    if (imported.length) importFiles(imported);
    setLastImportStatus(`Imported ${imported.length} files and ${rootFolder ? 1 : 0} folders${uploadedFiles.length > imported.length ? ` · ${uploadedFiles.length - imported.length} skipped (large, unreadable, or ignored)` : ""}`);
    e.target.value = "";
  };

  const openFolderPicker = async () => {
    if (!isTauriDesktop()) {
      folderInputRef.current?.click();
      return;
    }
    try {
      const imported = await readNativeDirectory();
      if (imported) {
        if (imported.folders.length) importFolders(imported.folders);
        if (imported.files.length) importFiles(imported.files);
        setLastImportStatus(`Imported ${imported.files.length} files and ${imported.folders.length} folders${imported.skipped ? ` · ${imported.skipped} skipped (large, unreadable, or ignored)` : ""}`);
      }
    } catch (error) {
      console.error("Failed to import folder", error);
      window.alert(`Could not import folder: ${String(error)}`);
    }
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragOver(true);
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragOver(false);
  };

  const handleDrop = async (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragOver(false);

    const imported = await readDroppedItems(e.dataTransfer.items);
    if (imported.folders.length) importFolders(imported.folders);
    if (imported.files.length) importFiles(imported.files);
    setLastImportStatus(`Imported ${imported.files.length} files and ${imported.folders.length} folders${imported.skipped ? ` · ${imported.skipped} skipped (large, unreadable, or ignored)` : ""}`);
  };

  // Spacebar pan listener
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (
        e.code === "Space" &&
        !spacePressed &&
        (e.target as HTMLElement).tagName !== "INPUT" &&
        (e.target as HTMLElement).tagName !== "TEXTAREA"
      ) {
        setSpacePressed(true);
      }
    };
    const handleKeyUp = (e: KeyboardEvent) => {
      if (e.code === "Space") {
        setSpacePressed(false);
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    window.addEventListener("keyup", handleKeyUp);
    return () => {
      window.removeEventListener("keydown", handleKeyDown);
      window.removeEventListener("keyup", handleKeyUp);
    };
  }, [spacePressed]);

  // Trackpad / Wheel zoom & pan
  const handleWheel = (e: React.WheelEvent) => {
    if (e.ctrlKey || e.metaKey) {
      e.preventDefault();
      const zoomFactor = e.deltaY < 0 ? 1.08 : 0.92;
      const newZoom = Math.min(Math.max(canvasTransform.zoom * zoomFactor, 0.2), 1.75);

      const rect = containerRef.current?.getBoundingClientRect();
      if (!rect) return;

      const mouseX = e.clientX - rect.left;
      const mouseY = e.clientY - rect.top;

      const newPanX = mouseX - (mouseX - canvasTransform.panX) * (newZoom / canvasTransform.zoom);
      const newPanY = mouseY - (mouseY - canvasTransform.panY) * (newZoom / canvasTransform.zoom);

      setCanvasTransform({
        panX: Math.round(newPanX),
        panY: Math.round(newPanY),
        zoom: Number(newZoom.toFixed(2)),
      });
    } else {
      setCanvasTransform({
        panX: canvasTransform.panX - e.deltaX,
        panY: canvasTransform.panY - e.deltaY,
        zoom: canvasTransform.zoom,
      });
    }
  };

  const handleMouseDown = (e: React.MouseEvent) => {
    if (
      e.button === 1 ||
      spacePressed ||
      e.target === containerRef.current ||
      (e.target as HTMLElement).id === "nexus-canvas-plane"
    ) {
      setIsPanning(true);
      panStartRef.current = {
        x: e.clientX,
        y: e.clientY,
        panX: canvasTransform.panX,
        panY: canvasTransform.panY,
      };
    }
  };

  const handleMouseMove = (e: React.MouseEvent) => {
    if (isPanning && panStartRef.current) {
      const dx = e.clientX - panStartRef.current.x;
      const dy = e.clientY - panStartRef.current.y;
      setCanvasTransform({
        panX: Math.round(panStartRef.current.panX + dx),
        panY: Math.round(panStartRef.current.panY + dy),
        zoom: canvasTransform.zoom,
      });
    }

    // Broadcast real-time canvas mouse coordinates to peers over WebRTC
    if (containerRef.current && canvasSessionRef.current) {
      const rect = containerRef.current.getBoundingClientRect();
      const screenX = e.clientX - rect.left;
      const screenY = e.clientY - rect.top;
      const worldX = Math.round((screenX - panX) / zoom);
      const worldY = Math.round((screenY - panY) / zoom);

      canvasSessionRef.current.awareness.setLocalStateField("canvasMouse", {
        x: worldX,
        y: worldY,
        status: isNewNodeModalOpen ? "typing" : undefined,
      });
    }
  };

  const handleMouseLeave = () => {
    if (canvasSessionRef.current) {
      canvasSessionRef.current.awareness.setLocalStateField("canvasMouse", null);
    }
  };

  const handleMouseUp = () => {
    setIsPanning(false);
    panStartRef.current = null;
  };

  const handleCreateNode = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newNodeName.trim()) return;
    createFile(newNodeName.trim());
    setNewNodeName("");
    setIsNewNodeModalOpen(false);
  };

  return (
    <div
      ref={containerRef}
      onWheel={handleWheel}
      onMouseDown={handleMouseDown}
      onMouseMove={handleMouseMove}
      onMouseLeave={handleMouseLeave}
      onMouseUp={handleMouseUp}
      onDragOver={handleDragOver}
      onDragLeave={handleDragLeave}
      onDrop={handleDrop}
      className={`relative w-full h-full overflow-hidden bg-black canvas-dot-grid select-none ${
        spacePressed || isPanning ? "cursor-grab active:cursor-grabbing" : "cursor-default"
      }`}
    >
      <input
        type="file"
        ref={folderInputRef}
        {...({ webkitdirectory: "", directory: "", multiple: true } as any)}
        className="hidden"
        onChange={handleFolderUpload}
      />
      <input
        type="file"
        ref={fileInputRef}
        multiple
        className="hidden"
        onChange={handleFileUpload}
      />

      {/* Drag & Drop Visual Overlay on Canvas */}
      {isDragOver && (
        <div className="absolute inset-0 z-50 bg-black/95 flex flex-col items-center justify-center p-8 text-center border-2 border-dashed border-[#007AFF] rounded-none">
          <FolderPlus className="w-12 h-12 text-[#007AFF] mb-3" />
          <span className="text-base font-semibold text-white font-sans">
            Drop Folder or Code Files
          </span>
          <span className="text-xs text-[#888888] font-sans mt-1.5 max-w-md">
            Files will be parsed into reactive architectural nodes and auto-wired into the spatial canvas.
          </span>
        </div>
      )}

      {/* Top Canvas HUD Toolbar */}
      <div className="absolute top-3 left-1/2 -translate-x-1/2 z-40 flex items-center gap-3 px-3 py-1 bg-[#0A0A0A] border border-[#222222] rounded-none text-xs text-[#888888] font-sans select-none">
        <div className="flex items-center gap-2">
          <div className="w-4 h-4 rounded-none bg-black border border-[#222222] flex items-center justify-center">
            <Layers className="w-3 h-3 text-white" />
          </div>
          <span className="font-semibold text-white uppercase text-[10px] tracking-wider">Canvas</span>
          <span className="text-[#222222]">·</span>
          <span className="text-[#888888] text-xs hidden sm:inline font-mono">
            {files.length} files · {edges.length} connections
          </span>
          <span className="text-[#222222] hidden sm:inline">·</span>
          <div className="hidden sm:flex items-center gap-1.5 px-1.5 py-0.5 rounded-none bg-black border border-[#222222]">
            <span
              className={`w-1.5 h-1.5 rounded-none ${
                isFlowPaused ? "bg-[#888888]" : "bg-[#007AFF]"
              }`}
            />
            <span className="text-[10px] font-mono text-[#888888]">
              {isFlowPaused ? "Paused" : "Live"}
            </span>
          </div>
        </div>

        <div className="h-3 w-[1px] bg-[#222222]" />

        {/* Speed Controller & Pause Scrubber */}
        <div className="flex items-center rounded-none border border-[#222222] bg-black p-0.5 text-[10px]">
          <button
            onClick={toggleFlowPause}
            title={isFlowPaused ? "Resume Flow" : "Pause Flow"}
            className={`px-1.5 py-0.5 rounded-none flex items-center gap-1 transition-colors ${
              isFlowPaused
                ? "bg-[#222222] text-white font-medium"
                : "text-[#888888] hover:text-white"
            }`}
          >
            {isFlowPaused ? (
              <>
                <Play className="w-2.5 h-2.5 fill-current" />
                <span>Play</span>
              </>
            ) : (
              <>
                <Pause className="w-2.5 h-2.5" />
                <span>Pause</span>
              </>
            )}
          </button>
          <div className="w-[1px] h-2.5 bg-[#222222] mx-0.5" />
          <button
            onClick={() => setFlowSpeedFactor(0.5)}
            title="0.5x Slow Pace"
            className={`px-1.5 py-0.5 rounded-none transition-colors ${
              flowSpeedFactor === 0.5
                ? "bg-[#222222] text-white font-medium"
                : "text-[#888888] hover:text-white"
            }`}
          >
            0.5x
          </button>
          <button
            onClick={() => setFlowSpeedFactor(1)}
            title="1x Normal Pace"
            className={`px-1.5 py-0.5 rounded-none transition-colors ${
              flowSpeedFactor === 1
                ? "bg-[#222222] text-white font-medium"
                : "text-[#888888] hover:text-white"
            }`}
          >
            1x
          </button>
        </div>

        {/* Connection Tracker Toggle Button */}
        <button
          onClick={togglePipelineTracker}
          className={`flex items-center gap-1.5 h-6 px-2.5 rounded-none border text-xs font-sans transition-colors ${
            isPipelineTrackerOpen
              ? "bg-[#222222] border-[#222222] text-white font-medium"
              : "bg-black hover:bg-[#222222] border-[#222222] text-[#888888] hover:text-white"
          }`}
          title="Toggle Connections Panel"
        >
          <Activity className="w-3.5 h-3.5" />
          <span>Connections</span>
          <span className="text-[10px] font-mono px-1 py-0.2 rounded-none bg-[#0A0A0A] border border-[#222222] text-[#888888]">
            {edges.length}
          </span>
        </button>

        <div className="h-3 w-[1px] bg-[#222222]" />

        <button
          onClick={() => onSwitchToZenith()}
          className="flex items-center gap-1.5 h-6 px-2.5 rounded-none bg-black hover:bg-[#222222] border border-[#222222] text-[#888888] hover:text-white text-xs font-sans font-medium transition-colors"
        >
          <span>Editor</span>
          <kbd className="text-[9px] text-[#888888] bg-[#0A0A0A] px-1 rounded-none border border-[#222222]">⌘ Space</kbd>
        </button>
      </div>

      {/* Transformed Spatial World Plane */}
      <div
        id="nexus-canvas-plane"
        className={`absolute top-0 left-0 w-full h-full origin-top-left ${
          isPanning
            ? "transition-none"
            : "transition-transform duration-200 ease-[cubic-bezier(0.16,1,0.3,1)]"
        }`}
        style={{
          transform: `translate3d(${panX}px, ${panY}px, 0) scale(${zoom})`,
          willChange: "transform",
        }}
      >
        <ConnectorLayer />

        {files.length === 0 ? (
          <div className="absolute top-1/3 left-1/2 -translate-x-1/2 -translate-y-1/2 p-6 border border-[#222222] bg-[#0A0A0A] text-white flex flex-col items-center max-w-sm text-center space-y-3">
            <div className="w-8 h-8 bg-black border border-[#222222] flex items-center justify-center">
              <Layers className="w-4 h-4 text-white" />
            </div>
            <h3 className="text-sm font-semibold uppercase tracking-wider">Starter Workspace</h3>
            <p className="text-xs text-[#888888] leading-relaxed">
              No files are loaded on the canvas. Click below to load the starter workspace.
            </p>
            <button
              onClick={() => useWorkspaceStore.getState().loadStarterWorkspace()}
              className="px-4 py-2 bg-white text-black hover:bg-[#CCCCCC] text-xs font-semibold uppercase tracking-wider transition-none"
            >
              Load Starter Workspace
            </button>
          </div>
        ) : (
          files.map((file) => (
            <EditorNode
              key={file.id}
              file={file}
              onOpenInIde={() => onSwitchToZenith(file.id)}
            />
          ))
        )}

        <CursorLayer />
      </div>

      {/* Connection Tracker Dock */}
      {isPipelineTrackerOpen && <PipelineTracker />}

      {/* Connecting Mode Helper Banner */}
      {isConnecting && (
        <div className="fixed bottom-8 left-1/2 -translate-x-1/2 z-40 flex items-center gap-3 px-3 py-1.5 bg-[#0A0A0A] border border-white rounded-none text-xs text-white font-sans">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-none bg-white" />
            <span className="font-semibold text-white">Connection Mode:</span>
            <span className="text-[#888888]">Click another file to connect</span>
          </div>
          <button
            onClick={cancelConnection}
            className="flex items-center gap-1 h-5 px-2 rounded-none bg-black hover:bg-[#222222] text-[#888888] hover:text-white border border-[#222222] text-xs transition-colors"
          >
            <X className="w-3 h-3" />
            <span>Cancel</span>
          </button>
        </div>
      )}

      {/* Bottom Controls: Import + File + Zoom Dock */}
      <div className="absolute bottom-4 right-4 z-40 flex items-center gap-1.5 p-1 bg-[#0A0A0A] border border-[#222222] rounded-none text-xs font-sans text-[#888888] select-none">
        {/* Import Folder Button */}
        <button
          onClick={openFolderPicker}
          className="flex items-center gap-1 h-6 px-2 rounded-none bg-black hover:bg-[#222222] text-[#888888] hover:text-white border border-[#222222] text-xs transition-colors"
          title="Import Folder to Canvas"
        >
          <FolderPlus className="w-3.5 h-3.5 text-[#888888]" />
          <span>Folder</span>
        </button>

        {/* Import Files Button */}
        <button
          onClick={() => fileInputRef.current?.click()}
          className="flex items-center gap-1 h-6 px-2 rounded-none bg-black hover:bg-[#222222] text-[#888888] hover:text-white border border-[#222222] text-xs transition-colors"
          title="Import Files to Canvas"
        >
          <Upload className="w-3.5 h-3.5 text-[#888888]" />
          <span>Files</span>
        </button>

        <div className="w-[1px] h-3 bg-[#222222]" />

        <button
          onClick={() => setIsNewNodeModalOpen(true)}
          className="flex items-center gap-1 h-6 px-2 rounded-none bg-black hover:bg-[#222222] border border-[#222222] text-[#888888] hover:text-white text-xs font-medium transition-colors"
          title="Add new file"
        >
          <Plus className="w-3.5 h-3.5" />
          <span>File</span>
        </button>

        <div className="w-[1px] h-3 bg-[#222222]" />

        <button
          onClick={() => zoomBy(-0.1)}
          title="Zoom Out"
          className="p-1 rounded-none text-[#888888] hover:text-white hover:bg-[#222222] transition-colors"
        >
          <ZoomOut className="w-3.5 h-3.5" />
        </button>

        <span className="px-1 text-white min-w-[38px] text-center font-medium text-xs font-mono">
          {Math.round(canvasTransform.zoom * 100)}%
        </span>

        <button
          onClick={() => zoomBy(0.1)}
          title="Zoom In"
          className="p-1 rounded-none text-[#888888] hover:text-white hover:bg-[#222222] transition-colors"
        >
          <ZoomIn className="w-3.5 h-3.5" />
        </button>

        <div className="w-[1px] h-3 bg-[#222222]" />

        <button
          onClick={resetView}
          title="Reset View"
          className="p-1 rounded-none text-[#888888] hover:text-white hover:bg-[#222222] transition-colors"
        >
          <RotateCcw className="w-3 h-3" />
        </button>
      </div>

      {/* New File Modal */}
      {isNewNodeModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80">
          <div className="w-full max-w-sm p-5 bg-[#0A0A0A] border border-[#222222] rounded-none text-white space-y-4 font-sans">
            <div className="flex items-center justify-between pb-3 border-b border-[#222222]">
              <h3 className="font-semibold text-xs text-white uppercase tracking-widest">Add New File</h3>
              <button
                onClick={() => setIsNewNodeModalOpen(false)}
                className="text-[#888888] hover:text-white p-1 rounded-none hover:bg-[#222222]"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleCreateNode} className="space-y-4">
              <div>
                <label className="text-[10px] text-[#888888] uppercase tracking-widest block mb-1.5 font-medium font-sans">
                  File Name
                </label>
                <input
                  type="text"
                  autoFocus
                  value={newNodeName}
                  onChange={(e) => setNewNodeName(e.target.value)}
                  placeholder="e.g. app.ts, utils.ts"
                  className="w-full px-2.5 py-1.5 bg-black border border-[#222222] focus:border-[#007AFF] rounded-none text-xs text-white font-mono focus:outline-none placeholder-[#888888]"
                />
              </div>

              <div className="flex items-center justify-end gap-2 pt-2 border-t border-[#222222]">
                <button
                  type="button"
                  onClick={() => setIsNewNodeModalOpen(false)}
                  className="px-2.5 py-1 rounded-none text-xs text-[#888888] hover:text-white hover:bg-[#222222] border border-[#222222] transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={!newNodeName.trim()}
                  className="px-3 py-1 rounded-none bg-white text-black hover:bg-[#cccccc] text-xs font-medium disabled:opacity-40 transition-colors"
                >
                  Create File
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
