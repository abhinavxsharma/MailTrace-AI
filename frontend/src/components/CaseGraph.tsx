import React, { useEffect, useRef, useState } from "react";
import cytoscape, { Core } from "cytoscape";
import { GraphData, GraphNodeData } from "../types";
import { ZoomIn, ZoomOut, Maximize2, RefreshCw, Network, Info } from "lucide-react";

interface CaseGraphProps {
  graphData?: GraphData | null;
  isLoading?: boolean;
}

export const CaseGraph: React.FC<CaseGraphProps> = ({ graphData, isLoading }) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<Core | null>(null);
  const [selectedNode, setSelectedNode] = useState<GraphNodeData | null>(null);

  useEffect(() => {
    if (!containerRef.current || !graphData || graphData.nodes.length === 0) {
      return;
    }

    // Destroy any existing instance
    if (cyRef.current) {
      cyRef.current.destroy();
    }

    try {
      const cy = cytoscape({
        container: containerRef.current,
        elements: {
          nodes: graphData.nodes.map((n) => ({
            data: {
              ...n.data,
              displayLabel: n.data.label.length > 24 ? n.data.label.substring(0, 22) + "..." : n.data.label,
            },
          })),
          edges: graphData.edges.map((e) => ({
            data: {
              ...e.data,
            },
          })),
        },
        style: [
          {
            selector: "node",
            style: {
              "label": "data(displayLabel)",
              "text-valign": "bottom",
              "text-halign": "center",
              "font-size": "10px",
              "font-family": "Inter, Arial, sans-serif",
              "color": "#334155",
              "text-margin-y": 4,
              "background-color": "#64748b",
              "border-width": 2,
              "border-color": "#ffffff",
              "width": 32,
              "height": 32,
            },
          },
          {
            selector: "node[type = 'email']",
            style: {
              "background-color": "#0f172a",
              "shape": "round-rectangle",
              "width": 42,
              "height": 42,
              "border-width": 3,
              "border-color": "#38bdf8",
            },
          },
          {
            selector: "node[type = 'sender']",
            style: {
              "background-color": "#2563eb",
              "shape": "ellipse",
            },
          },
          {
            selector: "node[type = 'reply_to']",
            style: {
              "background-color": "#dc2626",
              "shape": "diamond",
              "width": 36,
              "height": 36,
              "border-width": 2,
              "border-color": "#fecaca",
            },
          },
          {
            selector: "node[type = 'return_path']",
            style: {
              "background-color": "#d97706",
              "shape": "ellipse",
            },
          },
          {
            selector: "node[type = 'domain']",
            style: {
              "background-color": "#4f46e5",
              "shape": "hexagon",
            },
          },
          {
            selector: "node[type = 'url']",
            style: {
              "background-color": "#9333ea",
              "shape": "round-rectangle",
            },
          },
          {
            selector: "node[type = 'ip']",
            style: {
              "background-color": "#0284c7",
              "shape": "ellipse",
            },
          },
          {
            selector: "node[type = 'infrastructure']",
            style: {
              "background-color": "#059669",
              "shape": "pentagon",
              "width": 36,
              "height": 36,
            },
          },
          {
            selector: "node:selected",
            style: {
              "border-width": 4,
              "border-color": "#1d4ed8",
            },
          },
          {
            selector: "edge",
            style: {
              "width": 2,
              "line-color": "#cbd5e1",
              "target-arrow-color": "#94a3b8",
              "target-arrow-shape": "triangle",
              "curve-style": "bezier",
              "arrow-scale": 0.8,
            },
          },
          {
            selector: "edge:selected",
            style: {
              "width": 3,
              "line-color": "#2563eb",
              "target-arrow-color": "#2563eb",
            },
          },
        ],
        layout: {
          name: "cose",
          idealEdgeLength: () => 80,
          nodeOverlap: 20,
          refresh: 20,
          fit: true,
          padding: 30,
          randomize: false,
          componentSpacing: 100,
          nodeRepulsion: () => 400000,
          edgeElasticity: () => 100,
          nestingFactor: 5,
          gravity: 80,
          numIter: 1000,
          initialTemp: 200,
          coolingFactor: 0.95,
          minTemp: 1.0,
        },
      });

      cy.on("tap", "node", (evt) => {
        const node = evt.target;
        setSelectedNode(node.data() as GraphNodeData);
      });

      cy.on("tap", (evt) => {
        if (evt.target === cy) {
          setSelectedNode(null);
        }
      });

      cyRef.current = cy;
    } catch (e) {
      console.error("Cytoscape initialization error:", e);
    }

    return () => {
      if (cyRef.current) {
        cyRef.current.destroy();
        cyRef.current = null;
      }
    };
  }, [graphData]);

  const handleZoomIn = () => {
    cyRef.current?.zoom(cyRef.current.zoom() * 1.25);
  };

  const handleZoomOut = () => {
    cyRef.current?.zoom(cyRef.current.zoom() * 0.8);
  };

  const handleFit = () => {
    cyRef.current?.fit(undefined, 30);
  };

  const handleReset = () => {
    cyRef.current?.reset();
    cyRef.current?.fit(undefined, 30);
  };

  return (
    <div className="card p-6 bg-white border border-slate-200 rounded-xl shadow-sm">
      {/* Header & Controls */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-base font-semibold text-slate-900">Forensic Relationship Graph</h2>
            {graphData && (
              <span className="text-xs text-slate-500 font-mono bg-slate-100 px-2 py-0.5 rounded border border-slate-200">
                {graphData.node_count} nodes • {graphData.edge_count} edges
              </span>
            )}
          </div>
          <p className="text-xs text-slate-500 mt-0.5">Interactive entity graph connecting emails, domains, URLs, IPs, and infrastructure</p>
        </div>

        {/* Action Toolbar */}
        <div className="flex items-center gap-1.5 self-end sm:self-auto">
          <button
            onClick={handleZoomIn}
            title="Zoom In"
            className="p-1.5 rounded-lg border border-slate-200 bg-slate-50 hover:bg-slate-100 text-slate-700 transition-all"
          >
            <ZoomIn className="w-4 h-4" />
          </button>
          <button
            onClick={handleZoomOut}
            title="Zoom Out"
            className="p-1.5 rounded-lg border border-slate-200 bg-slate-50 hover:bg-slate-100 text-slate-700 transition-all"
          >
            <ZoomOut className="w-4 h-4" />
          </button>
          <button
            onClick={handleFit}
            title="Fit View"
            className="p-1.5 rounded-lg border border-slate-200 bg-slate-50 hover:bg-slate-100 text-slate-700 transition-all"
          >
            <Maximize2 className="w-4 h-4" />
          </button>
          <button
            onClick={handleReset}
            title="Reset Layout"
            className="p-1.5 rounded-lg border border-slate-200 bg-slate-50 hover:bg-slate-100 text-slate-700 transition-all"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Main Canvas Area */}
      <div className="relative h-96 w-full rounded-xl border border-slate-200 bg-slate-50/50 overflow-hidden">
        {isLoading && (
          <div className="absolute inset-0 z-10 flex items-center justify-center bg-white/70 backdrop-blur-sm">
            <div className="flex items-center gap-2 text-xs font-semibold text-slate-600 font-mono">
              <Network className="w-4 h-4 animate-spin text-blue-600" />
              <span>Building relationship topology...</span>
            </div>
          </div>
        )}

        {(!graphData || graphData.nodes.length === 0) && !isLoading ? (
          <div className="h-full flex flex-col items-center justify-center text-slate-400 text-xs">
            <Network className="w-10 h-10 text-slate-300 mb-2 stroke-[1.5]" />
            <span>No forensic graph nodes generated yet.</span>
            <span className="text-[11px] text-slate-400 mt-0.5">Analyze case to construct relationship graph.</span>
          </div>
        ) : (
          <div ref={containerRef} className="h-full w-full" />
        )}

        {/* Selected Node Details Floating Overlay */}
        {selectedNode && (
          <div className="absolute bottom-3 left-3 max-w-sm p-3 bg-white/95 backdrop-blur border border-slate-200 rounded-xl shadow-lg text-xs z-20 transition-all fade">
            <div className="flex items-center justify-between font-bold text-slate-900 border-b pb-1.5 mb-1.5">
              <span className="flex items-center gap-1.5">
                <Info className="w-3.5 h-3.5 text-blue-600" />
                <span className="uppercase text-[10px] text-slate-500 font-sans">{selectedNode.type} Node</span>
              </span>
              <button
                onClick={() => setSelectedNode(null)}
                className="text-slate-400 hover:text-slate-700 text-sm leading-none"
              >
                ×
              </button>
            </div>
            <div className="font-semibold text-slate-800 break-all font-mono">
              {selectedNode.label}
            </div>
            {selectedNode.value && selectedNode.value !== selectedNode.label && (
              <div className="text-slate-500 text-[11px] mt-1 break-all">
                Value: {selectedNode.value}
              </div>
            )}
          </div>
        )}
      </div>

      {/* Legend */}
      <div className="mt-3 flex flex-wrap items-center gap-3 text-[11px] text-slate-500 pt-2 border-t border-slate-100">
        <div className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded-sm bg-[#0f172a]" /> Email</div>
        <div className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded-full bg-[#2563eb]" /> Sender</div>
        <div className="flex items-center gap-1"><span className="w-2.5 h-2.5 rotate-45 bg-[#dc2626]" /> Reply-To</div>
        <div className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded-full bg-[#d97706]" /> Return-Path</div>
        <div className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded-sm bg-[#4f46e5]" /> Domain</div>
        <div className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded-sm bg-[#9333ea]" /> URL</div>
        <div className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded-full bg-[#0284c7]" /> IP</div>
        <div className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded-sm bg-[#059669]" /> Infrastructure</div>
      </div>
    </div>
  );
};
