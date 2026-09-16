import React from "react";
import { InfrastructureData, DNSRecord, RDAPRecord, GeoIPRecord } from "../types";
import { Server, Network, MapPin, Activity } from "lucide-react";

interface InfrastructurePanelProps {
  infrastructure?: InfrastructureData | null;
  dns?: Record<string, DNSRecord>;
  rdap?: Record<string, RDAPRecord>;
  geoip?: Record<string, GeoIPRecord>;
}

export const InfrastructurePanel: React.FC<InfrastructurePanelProps> = ({
  infrastructure,
  dns,
  rdap,
  geoip,
}) => {
  const sourceIp = infrastructure?.source_ip || "Unavailable";
  const sourceRdap = rdap && sourceIp !== "Unavailable" ? rdap[sourceIp] : undefined;
  const sourceGeo = geoip && sourceIp !== "Unavailable" ? geoip[sourceIp] : undefined;

  const getStatusBadge = (status?: string) => {
    if (status === "available" || status === "AVAILABLE") {
      return <span className="text-[9px] px-1.5 py-0.2 rounded bg-emerald-50 text-emerald-700 border border-emerald-200 font-mono font-bold">OK</span>;
    }
    return <span className="text-[9px] px-1.5 py-0.2 rounded bg-slate-100 text-slate-500 border border-slate-200 font-mono font-medium">N/A</span>;
  };

  const geoCityStr = sourceGeo?.city && sourceGeo.city !== "Unavailable" ? ` (${sourceGeo.city})` : "";
  const geoDisplay = sourceGeo?.country
    ? `${sourceGeo.country}${geoCityStr}`
    : infrastructure?.country || "Unavailable";

  if (!infrastructure && (!dns || Object.keys(dns).length === 0)) {
    return (
      <div className="card bg-white border border-slate-200 rounded-lg p-3.5 shadow-xs text-xs">
        <div className="flex items-center justify-between pb-2 mb-2.5 border-b border-slate-100">
          <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500 flex items-center gap-1.5">
            <Server className="w-3.5 h-3.5 text-blue-600" />
            <span>Observed Source Infrastructure</span>
          </span>
          <span className="text-[10px] text-slate-400 font-mono">PASSIVE INTEL</span>
        </div>
        <div className="p-4 bg-slate-50 rounded border border-slate-200 text-center text-slate-500">
          <div className="font-semibold text-slate-700">Infrastructure intelligence unavailable.</div>
          <p className="text-slate-400 text-[11px] mt-0.5">Run threat analysis to enrich source IP and domain routing telemetry.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="card bg-white border border-slate-200 rounded-lg p-3.5 shadow-xs text-xs">
      <div className="flex items-center justify-between pb-2 mb-2.5 border-b border-slate-100">
        <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500 flex items-center gap-1.5">
          <Server className="w-3.5 h-3.5 text-blue-600" />
          <span>Observed Source Infrastructure</span>
        </span>
        <span className="text-[10px] text-slate-400 font-mono">
          PASSIVE INTEL
        </span>
      </div>

      {/* Primary Observables Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 mb-2.5">
        {/* Source IP */}
        <div className="p-2 rounded border border-slate-200 bg-slate-50">
          <div className="flex items-center gap-1 text-[9px] uppercase font-sans text-slate-400">
            <Server className="w-3 h-3 text-slate-500" />
            <span>Source IP</span>
          </div>
          <div className="font-mono font-bold text-slate-900 mt-0.5 truncate" title={sourceIp}>
            {sourceIp}
          </div>
          <div className="text-[10px] text-slate-500 font-mono truncate mt-0.5" title={infrastructure?.reverse_dns || "No PTR record"}>
            {infrastructure?.reverse_dns || "No PTR record"}
          </div>
        </div>

        {/* Network / RDAP */}
        <div className="p-2 rounded border border-slate-200 bg-slate-50">
          <div className="flex items-center gap-1 text-[9px] uppercase font-sans text-slate-400">
            <Network className="w-3 h-3 text-slate-500" />
            <span>Network / RDAP</span>
          </div>
          <div className="font-semibold text-slate-800 mt-0.5 truncate" title={sourceRdap?.organization || infrastructure?.organization || "Unavailable"}>
            {sourceRdap?.organization || infrastructure?.organization || "Unavailable"}
          </div>
          <div className="text-[10px] text-slate-500 font-mono truncate mt-0.5" title={sourceRdap?.network_name || infrastructure?.asn || "Autonomous System"}>
            {sourceRdap?.network_name || infrastructure?.asn || "Autonomous System"}
          </div>
        </div>

        {/* IP Geolocation */}
        <div className="p-2 rounded border border-slate-200 bg-slate-50">
          <div className="flex items-center gap-1 text-[9px] uppercase font-sans text-slate-400">
            <MapPin className="w-3 h-3 text-slate-500" />
            <span>IP Geolocation</span>
          </div>
          <div className="font-semibold text-slate-800 mt-0.5 truncate" title={geoDisplay}>
            {geoDisplay}
          </div>
          <div className="text-[10px] text-slate-400 font-mono truncate mt-0.5">
            {sourceGeo?.latitude && sourceGeo?.longitude
              ? `${sourceGeo.latitude.toFixed(2)}, ${sourceGeo.longitude.toFixed(2)}`
              : "Regional Registry"}
          </div>
        </div>
      </div>

      {/* Telemetry Statuses & Disclaimers */}
      <div className="flex flex-wrap items-center justify-between gap-2 pt-2 border-t border-slate-100 text-[11px]">
        <div className="flex items-center gap-3">
          <span className="text-[10px] text-slate-400 font-mono uppercase">Telemetry:</span>
          <div className="flex items-center gap-1 text-slate-600">
            <span>DNS</span>
            {getStatusBadge(infrastructure?.dns_status)}
          </div>
          <div className="flex items-center gap-1 text-slate-600">
            <span>RDAP</span>
            {getStatusBadge(infrastructure?.rdap_status)}
          </div>
          <div className="flex items-center gap-1 text-slate-600">
            <span>GeoIP</span>
            {getStatusBadge(infrastructure?.geoip_status)}
          </div>
        </div>

        {dns && Object.keys(dns).length > 0 && (
          <span className="text-[10px] font-mono text-slate-400">
            {Object.keys(dns).length} Domains Queried
          </span>
        )}
      </div>

      {/* Mandatory Forensic Safeguard Statement (Requirement 8) */}
      <div className="mt-2.5 p-2 rounded bg-slate-50/80 border border-slate-200/80 text-[10px] text-slate-500 leading-relaxed font-sans italic">
        * Observed source infrastructure reflects network routing artifacts. IP geolocation is approximate and does not prove human identity or exact physical location.
      </div>
    </div>
  );
};
