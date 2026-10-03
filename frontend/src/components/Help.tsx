import { useId, useRef, useState } from "react";

export const fieldHelp: Record<string, string> = {
  Scope: "The approved boundary for a scan. Only targets inside this scope can be scanned. Create a scope in Scopes first.",
  Target: "The IP address, hostname or network to inspect. It must be inside the selected scope; selecting a scope fills its target for you.",
  Profile: "Chooses the discovery workflow. Internal profiles inspect LAN services; external profiles inspect public exposure.",
  Adapter: "The tool for one individual job. Nmap discovers services, web fingerprinting reads web metadata, and Nuclei checks for vulnerabilities.",
  Zone: "Internal IT is for your private network. External is for internet-facing systems. This determines the available scan profiles.",
  Type: "Choose the address format, such as an IP, hostname or CIDR network (for example 192.168.1.0/24).",
  Asset: "The device or host this finding belongs to. Discover it with an assessment or add it in Inventory first.",
  Severity: "The potential impact of a finding, from informational to critical. Severity alone does not confirm exploitability.",
  Baseline: "The earlier snapshot used as the starting point for comparison.",
  Comparison: "The later snapshot to compare with the baseline to find new, changed or removed exposure.",
  Name: "A descriptive name that helps you recognize this entry later.",
  Value: "The actual address or hostname of the asset, matching the selected type.",
  Title: "A short description of the observed issue.",
};

export function Help({ text, label = "Help" }: { text: string; label?: string }) {
  const id = useId();
  const [open, setOpen] = useState(false);
  const anchor = useRef<HTMLSpanElement>(null);
  const [position, setPosition] = useState({ left: 8, top: 8 });
  const show = () => {
    const rect = anchor.current?.getBoundingClientRect();
    if (rect) setPosition({ left: Math.max(8, Math.min(rect.left, window.innerWidth - Math.min(240, window.innerWidth * .65) - 8)), top: rect.bottom });
    setOpen(true);
  };
  return <span ref={anchor} className="help-wrap" onMouseEnter={show} onMouseLeave={() => setOpen(false)}>
    <button type="button" className="help-button" aria-label={label} aria-describedby={open ? id : undefined}
      aria-expanded={open} onFocus={show} onBlur={() => setOpen(false)}
      onClick={show} onKeyDown={(event) => { if (event.key === "Escape") { event.stopPropagation(); setOpen(false); } }}>?</button>
    {open && <span id={id} role="tooltip" className="help-tooltip" style={position}>{text}</span>}
  </span>;
}
