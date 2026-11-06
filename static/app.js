const $ = (id) => document.getElementById(id);
let latestReportId = null;
const views = {overview: $("overviewView"), analysis: $("analysisView"), reports: $("reportsView")};
function toast(message){const el=$("toast");el.textContent=message;el.classList.add("show");setTimeout(()=>el.classList.remove("show"),2600)}
function showView(name){
  Object.entries(views).forEach(([key,el])=>el.classList.toggle("hidden",key!==name));
  document.querySelectorAll(".nav").forEach(btn=>btn.classList.toggle("active",btn.dataset.view===name));
  const labels={overview:["OVERVIEW","Security overview"],analysis:["ANALYSIS LAB","Analysis workbench"],reports:["REPORT ARCHIVE","Investigation reports"]};
  $("pageName").textContent=labels[name][0];$("pageTitle").textContent=labels[name][1];
  if(name==="reports") loadReports();
}
document.querySelectorAll("[data-view]").forEach(btn=>btn.addEventListener("click",()=>showView(btn.dataset.view)));
document.querySelectorAll("[data-goto]").forEach(btn=>btn.addEventListener("click",()=>showView(btn.dataset.goto)));
$("startAnalysis").addEventListener("click",()=>showView("analysis"));
$("refresh").addEventListener("click",loadOverview);
$("refreshReports").addEventListener("click",loadReports);
async function api(path,options={}){const res=await fetch(path,options);const body=await res.json().catch(()=>({detail:"Unexpected server response"}));if(!res.ok)throw new Error(body.detail||"Request failed");return body}
function badgeClass(verdict){return verdict==="HIGH RISK"?"high":verdict==="REVIEW REQUIRED"?"review":""}
function renderRow(item){const date=new Date(item.created_at).toLocaleString();return `<div class="recent-row"><div class="recent-icon">${item.kind.includes("URL")?"⌕":"⇧"}</div><div><b>${escapeHtml(item.target)}</b><small>${escapeHtml(item.kind)} · ${item.id}</small></div><span class="risk-badge ${badgeClass(item.verdict)}">${escapeHtml(item.verdict)}</span><small class="date">${date}</small></div>`}
function escapeHtml(value){return String(value).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]))}
async function loadOverview(){
  try{const [stats,items]=await Promise.all([api("/api/stats"),api("/api/scans")]);$("totalStat").textContent=stats.total;$("highStat").textContent=stats.high_risk;$("reviewStat").textContent=stats.review;$("safeStat").textContent=stats.protected;$("recentList").innerHTML=items.length?items.slice(0,5).map(renderRow).join(""):'<div class="empty">No investigations yet. Launch your first analysis.</div>';$("updated").textContent="Updated "+new Date().toLocaleTimeString()}catch(e){toast(e.message)}
}
async function loadReports(){try{const items=await api("/api/scans");$("allReports").innerHTML=items.length?items.map(renderRow).join(""):'<div class="empty">No reports yet. Your completed investigations will appear here.</div>'}catch(e){$("allReports").innerHTML='<div class="empty">Could not load reports.</div>'}}
function showResult(report){
  latestReportId=report.id;$("resultPanel").classList.remove("hidden");$("resultTitle").textContent=report.kind+" complete";$("resultTarget").textContent=report.target;$("resultMeta").textContent="Case "+report.id+" · "+new Date(report.created_at).toLocaleString();$("scoreValue").textContent=report.score;$("resultBadge").textContent=report.verdict;$("resultBadge").className="risk-badge "+badgeClass(report.verdict);$("scoreRing").style.borderColor=report.score>=60?"#ff647c":report.score>=25?"#f4bd67":"#65d6a2";$("findingsList").innerHTML=report.findings.map(f=>`<div class="finding"><div class="severity ${f.severity}">${escapeHtml(f.severity)}</div><div><b>${escapeHtml(f.title)}</b><p>${escapeHtml(f.detail)}</p></div></div>`).join("");$("resultPanel").scrollIntoView({behavior:"smooth",block:"start"});loadOverview()}
$("downloadReport").addEventListener("click",()=>{if(latestReportId)window.open("/api/report/"+latestReportId,"_blank")});
$("urlForm").addEventListener("submit",async e=>{e.preventDefault();const btn=e.submitter;btn.disabled=true;btn.textContent="Analyzing…";try{const report=await api("/api/analyze/url",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({url:$("urlInput").value})});showResult(report);toast("URL triage completed")}catch(err){toast(err.message)}finally{btn.disabled=false;btn.innerHTML='Analyze URL <span>↗</span>'}});
$("fileInput").addEventListener("change",()=>{$("fileLabel").textContent=$("fileInput").files[0]?.name||"Drop a file here or browse"});
$("fileForm").addEventListener("submit",async e=>{e.preventDefault();const file=$("fileInput").files[0];if(!file){toast("Choose a file first");return}const btn=e.submitter;btn.disabled=true;btn.textContent="Inspecting file…";try{const form=new FormData();form.append("file",file);const report=await api("/api/analyze/file",{method:"POST",body:form});showResult(report);toast("File analysis completed")}catch(err){toast(err.message)}finally{btn.disabled=false;btn.innerHTML='Analyze file <span>↗</span>'}});
loadOverview();
