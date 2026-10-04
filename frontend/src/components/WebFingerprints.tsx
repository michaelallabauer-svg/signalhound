import type { AssetDetail, ServiceObservation } from "../api";
import { Help } from "./Help";

const fields = [
  ["title", "Page title", "The title reported by the web page. It is a clue, not a verified product identification."],
  ["http_status", "HTTP status", "200 usually means success; 3xx means redirect; 401/403 indicates restricted access. None of these alone is a vulnerability."],
  ["server", "Server", "The server's self-reported software header. It may be missing, hidden or inaccurate."],
  ["content_type", "Content type", "The format returned by the server, for example HTML or JSON."],
  ["redirect_location", "Redirect", "Where the server asks the browser to go next. Displayed as text; this does not confirm the destination was scanned."],
  ["tls_subject", "TLS subject", "The identity claimed by the certificate. Collection does not establish that it is trusted."],
  ["tls_issuer", "TLS issuer", "Who issued the certificate. Missing data does not mean HTTPS is absent."],
  ["tls_not_after", "TLS expiry", "The expiry date reported by the certificate, if available. No certificate trust assessment is performed."],
] as const;

export function WebFingerprints({ detail }: { detail: AssetDetail }) {
  const latest = new Map<number, ServiceObservation>();
  for (const observation of detail.service_observations) {
    if (observation.source !== "web_fingerprint") continue;
    const previous = latest.get(observation.service_id);
    if (!previous || Date.parse(observation.observed_at) > Date.parse(previous.observed_at) ||
      (observation.observed_at === previous.observed_at && observation.id > previous.id)) latest.set(observation.service_id, observation);
  }
  const services = detail.services.filter(service => latest.has(service.id));
  return <section className="detail-section">
    <h3>Web fingerprints <Help label="About web fingerprints" text="Read-only web metadata collected by fingerprint jobs. These observations are not confirmed vulnerabilities or reliable OS identification." /></h3>
    <p className="guidance">Latest fingerprint per service. Missing values mean not reported or not collected, not a security verdict.</p>
    {!services.length && <div className="empty-inline">No web fingerprints yet. In Scanners, select a completed assessment, prepare web fingerprinting, then start its prepared jobs. Return here after completion.</div>}
    {services.map(service => {
      const observation = latest.get(service.id)!;
      const metadata = observation.metadata;
      const value = (key: string) => typeof metadata[key] === "string" || typeof metadata[key] === "number" ? String(metadata[key]) : "Not available";
      const invalidTarget = detail.value.includes("/");
      const hasResponse = typeof metadata.http_status === "number" && metadata.http_status >= 100 && metadata.http_status <= 599;
      return <article className="fingerprint-card" key={service.id}>
        <h4>{invalidTarget || !hasResponse ? "Unconfirmed attempt · " : "HTTP response observed · "}{service.name ?? "Web service"} · {service.protocol}/{service.port}{!service.active && " · Inactive service"}</h4>
        <p className="guidance">Observed {new Date(observation.observed_at).toLocaleString()} · Source: web fingerprint</p>
        {invalidTarget && <div className="notice error">Invalid historical target: a subnet is not a host. This entry does not establish any open port in the LAN.</div>}
        {!invalidTarget && !hasResponse && <div className="notice error">This fingerprint did not record an HTTP response. The attempted port is not a confirmed web service; other discovery evidence may exist.</div>}
        <p className="fingerprint-url">{value("url")}</p>
        {metadata.error && typeof metadata.error === "string" ? <div className="notice error">Collection incomplete: {metadata.error}. Check reachability and run a new fingerprint job to retry.</div> : null}
        <dl className="detail-list">{fields.map(([key, label, help]) => <div key={key}>
          <dt>{label} <Help label={`About ${label}`} text={help} /></dt><dd>{value(key)}</dd>
        </div>)}</dl>
      </article>;
    })}
  </section>;
}
