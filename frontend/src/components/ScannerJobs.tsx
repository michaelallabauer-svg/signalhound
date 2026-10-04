import { useEffect, useMemo, useState } from "react";
import type { ScannerJob } from "../api";

const names: Record<string, string> = { nmap: "Nmap", web_fingerprint: "Web fingerprint", nuclei: "Nuclei", amass: "Amass" };
export function ScannerJobs({ jobs, runningJobId, onRun, onSelect, describe }: {
  jobs: ScannerJob[]; runningJobId: number | null;
  onRun: (id: number) => void; onSelect: (job: ScannerJob) => void; describe: (job: ScannerJob) => string;
}) {
  const [adapter, setAdapter] = useState("all");
  const [status, setStatus] = useState("all");
  const [query, setQuery] = useState("");
  const [assessment, setAssessment] = useState("all");
  const [page, setPage] = useState(0);
  const [selected, setSelected] = useState<number | null>(null);
  const tabs = ["all", ...Array.from(new Set(jobs.map(job => job.adapter_name))).sort()];
  const assessments = Array.from(new Set(jobs.flatMap(job => job.assessment_run_id ? [job.assessment_run_id] : []))).sort((a,b)=>b-a);
  const filtered = useMemo(() => jobs.filter(job =>
    (adapter === "all" || job.adapter_name === adapter) &&
    (status === "all" || (runningJobId === job.id ? "RUNNING" : job.status) === status) &&
    (assessment === "all" || (assessment === "standalone" ? !job.assessment_run_id : String(job.assessment_run_id) === assessment)) &&
    `${job.id} ${job.target} ${job.adapter_name}`.toLowerCase().includes(query.trim().toLowerCase())
  ).sort((a,b) => b.id-a.id), [jobs, adapter, status, assessment, query, runningJobId]);
  useEffect(() => setPage(0), [adapter, status, assessment, query]);
  const currentPage = Math.min(page, Math.max(0, Math.ceil(filtered.length / 20)-1));
  function chooseTab(value: string) { setAdapter(value); setPage(0); }
  return <>
    <div className="scanner-job-tabs" role="tablist" aria-label="Scanner job types">
      {tabs.map((name, index) => <button key={name} type="button" role="tab" id={`scanner-tab-${name}`}
        aria-selected={adapter===name} aria-controls="scanner-job-results" tabIndex={adapter===name ? 0 : -1}
        onClick={()=>chooseTab(name)} onKeyDown={event=>{
          let next = index;
          if(event.key === "ArrowRight") next = (index+1)%tabs.length;
          else if(event.key === "ArrowLeft") next = (index+tabs.length-1)%tabs.length;
          else if(event.key === "Home") next=0;
          else if(event.key === "End") next=tabs.length-1;
          else return;
          event.preventDefault(); chooseTab(tabs[next]); document.getElementById(`scanner-tab-${tabs[next]}`)?.focus();
        }}>{name === "all" ? "All jobs" : names[name] ?? name} ({jobs.filter(job=>name==="all" || job.adapter_name===name).length})</button>)}
    </div>
    <div className="scanner-job-filters">
      <label>Search jobs<input value={query} onChange={event=>setQuery(event.target.value)} placeholder="Target, job ID or scanner" /></label>
      <label>Job status<select aria-label="Job status" value={status} onChange={event=>setStatus(event.target.value)}>
        <option value="all">All statuses</option>{["PREPARED","RUNNING","COMPLETED","FAILED","CANCELLED"].map(value=><option key={value}>{value}</option>)}
      </select></label>
      <label>Assessment<select aria-label="Assessment" value={assessment} onChange={event=>setAssessment(event.target.value)}>
        <option value="all">All assessments</option><option value="standalone">Standalone jobs</option>
        {assessments.map(id=><option key={id} value={id}>Assessment #{id}</option>)}
      </select></label>
      <button type="button" onClick={()=>{setQuery("");setStatus("all");setAssessment("all");chooseTab("all");}}>Reset filters</button>
    </div>
    <div id="scanner-job-results" role="tabpanel" aria-labelledby={`scanner-tab-${adapter}`}>
      <p className="guidance" aria-live="polite">{filtered.length} of {jobs.length} jobs · Newest first</p>
      <div className="scanner-table-scroll"><table className="scanner-jobs-table compact">
        <thead><tr><th>Job / scanner</th><th>Target / result</th><th>Status</th><th>Actions</th></tr></thead>
        <tbody>{filtered.slice(currentPage*20, currentPage*20+20).map(job=><tr key={job.id} className={selected===job.id ? "selected-job-row" : job.status==="FAILED" ? "failed-row" : undefined}>
          <td><strong>#{job.id}</strong><div>{names[job.adapter_name] ?? job.adapter_name}</div>
            <small>{job.assessment_run_id ? `Assessment #${job.assessment_run_id}` : "Standalone"}</small>
            {job.requested_at && <div><time dateTime={job.requested_at}>{new Date(job.requested_at).toLocaleString()}</time></div>}</td>
          <td><div className="job-target">{job.target}</div><div className="job-detail">{describe(job)}</div></td>
          <td><span className={`status-pill status-${job.status.toLowerCase()}`}>{runningJobId===job.id ? "RUNNING" : job.status}</span></td>
          <td><div className="job-actions"><button type="button" aria-label={`View job ${job.id}`} aria-pressed={selected===job.id} onClick={()=>{setSelected(job.id);onSelect(job);}}>Details</button>
            {job.status==="PREPARED" && <button type="button" disabled={runningJobId!==null} onClick={()=>{setSelected(job.id);onRun(job.id);}}>Run</button>}</div></td>
        </tr>)}</tbody>
      </table></div>
      {!filtered.length && <div className="empty-inline">{jobs.length ? "No matching jobs. Change or reset the filters." : "No scanner jobs"}</div>}
      {filtered.length>20 && <div className="job-pagination"><button disabled={currentPage===0} onClick={()=>setPage(currentPage-1)}>Previous</button><span>Page {currentPage+1} of {Math.ceil(filtered.length/20)}</span><button disabled={(currentPage+1)*20>=filtered.length} onClick={()=>setPage(currentPage+1)}>Next</button></div>}
    </div>
  </>;
}
