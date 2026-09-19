"use client";

import React, { Component, ErrorInfo, ReactNode } from "react";
import { useWorkspaceStore } from "@/lib/store";
import { RotateCcw, AlertTriangle, Play } from "lucide-react";

interface Props {
  children: ReactNode;
  fallbackTitle?: string;
  fallbackDescription?: string;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export default class CruxErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false,
    error: null,
  };

  public static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error("[CruxErrorBoundary] Caught error:", error, errorInfo);
  }

  private handleLoadStarter = () => {
    try {
      useWorkspaceStore.getState().loadStarterWorkspace();
    } catch (e) {
      console.error("[CruxErrorBoundary] Failed to load starter:", e);
    }
    this.setState({ hasError: false, error: null });
  };

  private handleRetry = () => {
    this.setState({ hasError: false, error: null });
  };

  public render() {
    if (this.state.hasError) {
      return (
        <div className="w-full h-full min-h-[300px] flex flex-col items-center justify-center p-8 bg-[#000000] text-[#FFFFFF] font-sans select-none border border-[#222222]">
          <div className="max-w-md w-full border border-[#222222] bg-[#0A0A0A] p-6 space-y-4">
            <div className="flex items-center gap-2 text-white border-b border-[#222222] pb-3">
              <AlertTriangle className="w-4 h-4 text-white" />
              <h2 className="text-sm font-semibold uppercase tracking-wider">
                {this.props.fallbackTitle || "Starter Workspace"}
              </h2>
            </div>

            <p className="text-xs text-[#888888] leading-relaxed font-sans">
              {this.props.fallbackDescription ||
                "A view error occurred. Instead of crashing the application, you can load the starter workspace with all default files and connections."}
            </p>

            {this.state.error && (
              <div className="p-2 bg-[#000000] border border-[#222222] text-[10px] font-mono text-[#888888] overflow-x-auto max-h-24">
                {this.state.error.message}
              </div>
            )}

            <div className="flex items-center gap-2 pt-2">
              <button
                onClick={this.handleLoadStarter}
                className="flex-1 px-3 py-2 bg-white text-black hover:bg-[#CCCCCC] text-xs font-semibold uppercase tracking-wider transition-none flex items-center justify-center gap-2"
              >
                <Play className="w-3.5 h-3.5 fill-current" />
                <span>Load Starter Workspace</span>
              </button>

              <button
                onClick={this.handleRetry}
                className="px-3 py-2 bg-transparent border border-[#222222] hover:border-white text-white text-xs font-semibold uppercase tracking-wider transition-none flex items-center gap-1.5"
              >
                <RotateCcw className="w-3.5 h-3.5" />
                <span>Try Again</span>
              </button>
            </div>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
