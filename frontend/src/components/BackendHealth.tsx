import React, { useEffect, useState } from "react";
import { getHealth } from "../api/client";
import { Activity } from "lucide-react";

interface BackendHealthProps {
  onStatusChange?: (online: boolean) => void;
}

export const BackendHealth: React.FC<BackendHealthProps> = ({ onStatusChange }) => {
  const [online, setOnline] = useState<boolean | null>(null);
  const [version, setVersion] = useState<string>("");

  useEffect(() => {
    let mounted = true;

    const check = async () => {
      try {
        const data = await getHealth();
        if (mounted) {
          setOnline(true);
          setVersion(data.version || "0.1.0");
          onStatusChange?.(true);
        }
      } catch {
        if (mounted) {
          setOnline(false);
          onStatusChange?.(false);
        }
      }
    };

    check();
    const interval = setInterval(check, 10000);
    return () => {
      mounted = false;
      clearInterval(interval);
    };
  }, [onStatusChange]);

  if (online === null) {
    return (
      <div className="flex items-center gap-1.5 px-2.5 py-1 text-[11px] text-slate-500 rounded bg-slate-100 border border-slate-200">
        <Activity className="w-3 h-3 animate-spin text-slate-400" />
        <span>Connecting</span>
      </div>
    );
  }

  if (!online) {
    return (
      <div className="flex items-center gap-1.5 px-2.5 py-1 text-[11px] text-red-700 bg-red-50 border border-red-200 rounded font-medium">
        <span className="w-2 h-2 rounded-full bg-red-500 animate-pulse" />
        <span>Backend Offline</span>
      </div>
    );
  }

  return (
    <div className="flex items-center gap-1.5 px-2.5 py-1 text-[11px] text-slate-700 bg-slate-50 border border-slate-200 rounded font-medium">
      <span className="w-2 h-2 rounded-full bg-emerald-500" />
      <span>Backend Online</span>
      <span className="text-[10px] text-slate-400 font-mono">v{version}</span>
    </div>
  );
};
