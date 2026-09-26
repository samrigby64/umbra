// Investigation tools extend the existing local UI and use its authenticated API helper.
get('/health').then(r=>{
  if(r.preview){
    const banner=document.createElement('p');banner.className='panel';banner.setAttribute('role','status');
    banner.textContent='Synthetic test environment — fictional pages, separate database. Cases, reviews and exports work here. Real collection is disabled; scope previews are available.';
    document.querySelector('main').prepend(banner);
  }
}).catch(()=>{});
document.querySelector('main').insertAdjacentHTML('beforeend', `
<section id="cases"><h2>Cases</h2>
<p class="hint">Save specific page versions, assign an analyst, record findings, and export exhibits.
Administrators can see all cases. Other accounts need explicit case membership. Assignment is a label; manage permissions separately.</p>
<div class="panel"><div class="inline"><button class="btn" onclick="editCase()">New case</button>
<button class="btn secondary" onclick="loadCases()">Refresh</button></div><div id="case-list"></div></div>
<div id="case-detail"></div></section>
<section id="relationships"><h2>Relationship review</h2>
<p class="hint">These links come from identifiers appearing on the same page. They do not establish common ownership.
Confirm or reject a link with a reason. Rejected pairs are kept apart when clusters are rebuilt, including through indirect links.
“Confirmed” records an analyst's assessment of the link, not a verified personal identity.</p>
<div class="panel"><button class="btn secondary" onclick="loadRelationships()">Refresh links</button>
<div id="relationship-list"></div><div class="inline"><button id="rel-prev" onclick="relationshipPage(-1)">Previous</button>
<span id="rel-page" aria-live="polite"></span><button id="rel-next" onclick="relationshipPage(1)">Next</button></div></div></section>
<section id="quality"><h2>Extraction quality</h2>
<p class="hint">A repeatable offline check against labelled examples. This small synthetic set measures regressions;
it does not measure accuracy across your live collection. No paid AI key or external requests are used.</p>
<div class="panel"><button class="btn" onclick="loadQuality()">Run benchmark</button><div id="quality-results" aria-live="polite"></div></div></section>`);
TABS.push('cases','relationships','quality');
Object.assign(LABELS,{cases:'Cases',relationships:'Review links',quality:'Quality'});
const originalShow = show;
show = function(tab){ originalShow(tab); ({cases:loadCases,relationships:loadRelationships,quality:loadQuality}[tab]||(()=>{}))(); };
buildNav();
document.querySelector(`nav a[data-tab="${document.querySelector('main section.active').id}"]`).classList.add('active');
let activeCase = null, relationshipOffset = 0, relationshipTotal = 0, relationshipData = [];

async function previewScope(){
  try {
    const payload = {seeds:el('seeds').value.split('\n').map(x=>x.trim()).filter(Boolean),
      strict_scope:el('strict_scope').checked,
      allowed_hosts:el('allowed_hosts').value.split(',').map(x=>x.trim()).filter(Boolean),
      max_depth:Number(el('max_depth').value||3),max_pages:Number(el('max_pages').value||50)};
    const r = await post('/admin/crawl-preview',payload);
    el('scope-preview').textContent = `${r.allowed_hosts.length ? 'Allowed hosts: '+r.allowed_hosts.join(', ') : 'All hosts allowed'}. Depth ${r.max_depth}; budget ${r.max_pages} pages. ${r.existing_pages_in_scope} existing pages fit this scope (not necessarily due). ${r.redirects}. ${r.note}`;
  } catch(e){el('scope-preview').textContent=e.message;}
}

async function loadCases(){
  try {
    const r = await get('/cases');
    el('case-list').innerHTML=table(['Case','Assigned analyst','Status','Tags'],r.cases,
      x=>`<tr class="clickable" onclick="openCase(${x.id})"><td>${esc(x.name)}</td><td>${esc(x.assigned_to||'Unassigned')}</td><td>${esc(x.status)}</td><td>${esc(x.tags)}</td></tr>`,
      'No cases yet. Create one, then open a page to save a version.',{cap:100,total:r.total});
  } catch(e){toast(e.message);}
}
function editCase(row=null){
  openModal(`<h2>${row?'Edit case':'New case'}</h2>
    <label for="case-name">Case name</label><input id="case-name" maxlength="255" value="${esc(row?.name||'')}">
    <label for="case-assignee">Assigned analyst</label><input id="case-assignee" maxlength="255" value="${esc(row?.assigned_to||'')}">
    <label for="case-tags">Tags (comma-separated)</label><input id="case-tags" maxlength="1000" value="${esc(row?.tags||'')}">
    <label for="case-notes">Notes</label><textarea id="case-notes" maxlength="20000">${esc(row?.notes||'')}</textarea>
    <label for="case-state">Status</label><select id="case-state"><option value="open">Open</option><option value="closed">Closed</option></select>
    <button class="btn" id="save-case">Save case</button>`);
  el('case-state').value=row?.status||'open';
  el('save-case').onclick=async()=>{
    try {
      const payload={name:el('case-name').value.trim(),assigned_to:el('case-assignee').value.trim(),
        tags:el('case-tags').value.trim(),notes:el('case-notes').value,status:el('case-state').value};
      const saved=await req(row?'PUT':'POST',row?'/cases/'+row.id:'/cases',payload);
      closeModal(); await loadCases(); await openCase(saved.id);
    } catch(e){toast(e.message);}
  };
}
async function openCase(id){
  try {
    const r=await get('/cases/'+id);activeCase=r.case;
    el('case-detail').innerHTML=`<div class="panel"><h3>${esc(r.case.name)}</h3>
      <p>${esc(r.case.assigned_to||'Unassigned')} · ${esc(r.case.status)} · ${esc(r.case.tags)}</p>
      <pre style="white-space:pre-wrap">${esc(r.case.notes)}</pre>
      <div class="inline"><button id="edit-case" class="btn secondary">Edit case</button>
      <button class="btn" onclick="download('/cases/${id}/export','case-${id}.zip','Case evidence')">Export saved versions</button></div>
      <h3>Saved exhibits</h3>${table(['Page / version','Review','Tags','Notes','Action'],r.items,
        x=>`<tr><td>${esc(x.page_url)}<br>Version ${x.version_id}${x.available?'':' — removed by retention/policy'}</td><td>${esc(x.verdict)}</td><td>${esc(x.tags)}</td><td>${esc(x.notes)}</td><td><button data-item="${x.id}" ${x.available?'':'disabled'}>Review</button></td></tr>`,
        'Open Pages → select a page → Versions → Save to case.')}
      <h3>Recent activity and exports</h3>${table(['Time','Action','User','Detail'],r.activity,
        x=>`<tr><td>${esc(x.created_at)}</td><td>${esc(x.action.replaceAll('_',' '))}</td><td>${esc(x.actor)}</td><td style="word-break:break-word">${esc(activityText(x))}</td></tr>`,'No activity.',{cap:100})}</div>`;
    el('edit-case').onclick=()=>editCase(r.case);
    el('case-detail').querySelectorAll('[data-item]').forEach(button=>button.onclick=()=>editExhibit(id,r.items.find(x=>x.id===Number(button.dataset.item))));
  } catch(e){toast(e.message);}
}
function editExhibit(caseId,item){
  openModal(`<h2>Review saved exhibit</h2><p>Version ${item.version_id} · ${esc(item.page_url)}</p>
    <label for="ex-verdict">Finding</label><select id="ex-verdict"><option value="unreviewed">Unreviewed</option><option value="relevant">Relevant</option><option value="irrelevant">Irrelevant</option><option value="needs_followup">Needs follow-up</option></select>
    <label for="ex-tags">Tags</label><input id="ex-tags" value="${esc(item.tags||'')}">
    <label for="ex-notes">Notes and reasoning</label><textarea id="ex-notes">${esc(item.notes||'')}</textarea><button id="save-exhibit" class="btn">Save review</button>`);
  el('ex-verdict').value=item.verdict||'unreviewed';
  el('save-exhibit').onclick=async()=>{
    try {await post(`/cases/${caseId}/items`,{version_id:item.version_id,notes:el('ex-notes').value,tags:el('ex-tags').value,verdict:el('ex-verdict').value});closeModal();await openCase(caseId);}
    catch(e){toast(e.message);}
  };
}
async function pageVersions(encoded){
  try {
    const url=decodeURIComponent(encoded);
    const [r,c]=await Promise.all([get('/versions?url='+encoded),get('/cases')]);
    const options=r.versions.map(v=>`<option value="${v.id}">#${v.id} · ${esc(v.captured_at||'time unknown')} ${v.legacy?'(legacy stored state)':''} ${v.truncated?'(truncated)':''}</option>`).join('');
    openModal(`<h2>Page versions</h2><p style="word-break:break-word">${esc(url)}</p>
      <p class="muted">Retains up to 20 recent versions by default; case exhibits are protected from that limit. Explicit retention or content-policy removal can still remove them. Legacy history cannot be reconstructed.</p>
      ${options?`<label for="version-old">Earlier version</label><select id="version-old">${options}</select>
      <label for="version-new">Later version / exhibit</label><select id="version-new">${options}</select>
      <button class="btn secondary" id="compare-versions">Compare</button><pre id="version-diff"></pre>`:'<p>No capture history yet.</p>'}
      <button class="btn secondary" id="snapshot-stored">Snapshot current stored page</button>
      <label for="version-case">Save selected version to case</label><select id="version-case">${c.cases.map(x=>`<option value="${x.id}">${esc(x.name)}</option>`).join('')}</select>
      <button class="btn" id="save-version" ${options&&c.cases.length?'':'disabled'}>Save to case</button>`);
    el('snapshot-stored').onclick=async()=>{try{await post('/versions/capture-stored',{url});await pageVersions(encoded);}catch(e){toast(e.message);}};
    if(options){
      el('version-old').selectedIndex=Math.min(1,r.versions.length-1);
      el('compare-versions').onclick=async()=>{try{const d=await get(`/versions/compare?before=${el('version-old').value}&after=${el('version-new').value}`);el('version-diff').textContent=(d.diff||'No text differences.')+(d.display_truncated?'\n[Display limited; captures retained separately]':'');}catch(e){toast(e.message);}};
      el('save-version').onclick=async()=>{try{await post(`/cases/${el('version-case').value}/items`,{version_id:Number(el('version-new').value)});toast('Saved this version to the case');}catch(e){toast(e.message);}};
    }
  } catch(e){toast(e.message);}
}
async function loadRelationships(){
  try {
    const r=await get('/relationships?limit=100&offset='+relationshipOffset);
    relationshipData=r.relationships;relationshipTotal=r.total;
    el('relationship-list').innerHTML=table(['Identifier','Linked identifier','Sources','Assessment','Review'],r.relationships,
      (x)=>`<tr><td style="word-break:break-all">${esc(x.left.join(': '))}</td><td style="word-break:break-all">${esc(x.right.join(': '))}</td><td>${x.source_count}</td><td>${esc(x.verdict)}</td><td><button data-link="${x.key}">Inspect</button></td></tr>`,'No candidate relationships yet.');
    el('relationship-list').querySelectorAll('[data-link]').forEach(b=>b.onclick=()=>reviewLink(relationshipData.find(x=>x.key===b.dataset.link)));
    el('rel-page').textContent=`${r.total?relationshipOffset+1:0}–${Math.min(relationshipOffset+100,r.total)} of ${r.total}`;
    el('rel-prev').disabled=relationshipOffset===0;el('rel-next').disabled=relationshipOffset+100>=r.total;
  }catch(e){toast(e.message);}
}
function relationshipPage(step){relationshipOffset=Math.max(0,relationshipOffset+step*100);loadRelationships();}
function reviewLink(link){
  openModal(`<h2>Review relationship</h2><p style="word-break:break-all">${esc(link.left.join(': '))}<br>${esc(link.right.join(': '))}</p>
    <p>${esc(link.reason)} ${link.reviewer?' · Reviewed by '+esc(link.reviewer):''}</p>
    <h3>Source observations (up to 10)</h3>${link.sources.map(s=>`<p><button class="btn secondary" data-source="${esc(s.url)}">Open source</button></p><pre>${esc(s.left_context||'Snippet unavailable')}\n${esc(s.right_context||'Snippet unavailable')}</pre>`).join('')||'<p>No current source observations remain.</p>'}
    <label for="link-verdict">Assessment</label><select id="link-verdict"><option value="inferred">Inferred / unconfirmed</option><option value="confirmed">Analyst-confirmed link</option><option value="rejected">Rejected link</option></select>
    <label for="link-reason">Reason (required)</label><textarea id="link-reason" maxlength="4000">${esc(link.verdict==='inferred'?'':link.reason)}</textarea><button class="btn" id="save-link">Save assessment</button>`);
  el('link-verdict').value=link.verdict;
  el('modal-box').querySelectorAll('[data-source]').forEach(b=>b.onclick=()=>openPage(encodeURIComponent(b.dataset.source)));
  el('save-link').onclick=async()=>{try{await req('PUT','/relationships/review',{left:link.left,right:link.right,verdict:el('link-verdict').value,reason:el('link-reason').value});closeModal();await loadRelationships();toast('Assessment saved; clusters rebuilt');}catch(e){toast(e.message);}};
}
async function loadQuality(){
  el('quality-results').textContent='Running labelled examples…';
  try{
    const r=await get('/quality');
    const pct=x=>x==null?'Not defined':(100*x).toFixed(1)+'%';
    el('quality-results').innerHTML=`<p>${r.sample_count} samples. ${esc(r.notice)}</p>`+table(['Extractor','Precision','Recall','Correct','False positives','Missed'],Object.entries(r.metrics),
      ([name,m])=>`<tr><td>${esc(name)}</td><td>${pct(m.precision)}</td><td>${pct(m.recall)}</td><td>${m.true_positive}</td><td>${m.false_positive}</td><td>${m.false_negative}</td></tr>`)+
      '<h3>Example-level results</h3>'+table(['Example','Purpose','Disagreements'],r.samples,
      s=>`<tr><td>${esc(s.id)}</td><td>${esc(s.description)}</td><td>${esc(qualityDisagreements(s))}</td></tr>`);
  }catch(e){el('quality-results').textContent=e.message;}
}
function qualityDisagreements(sample){
  const notes=[];
  for(const kind of ['indicators','listings']){
    const result=sample[kind];
    if(result.false_positives.length)notes.push(`Extra ${kind}: ${result.false_positives.map(x=>x.join(' ')).join(', ')}`);
    if(result.false_negatives.length)notes.push(`Missed ${kind}: ${result.false_negatives.map(x=>x.join(' ')).join(', ')}`);
  }
  return notes.join(' · ')||'Matches the labelled example';
}
function activityText(activity){
  try{
    const d=JSON.parse(activity.detail);
    if(activity.action==='exported')return `${d.versions.length} version(s) exported · SHA-256 ${d.sha256}`;
    if(activity.action==='item_saved')return `Version ${d.version_id} · ${d.verdict} · ${d.notes||'No notes'}${d.tags?' · Tags: '+d.tags:''}`;
    if(activity.action==='updated')return Object.keys(d.after).filter(k=>d.before[k]!==d.after[k]).map(k=>`${k.replaceAll('_',' ')}: ${d.before[k]||'(empty)'} → ${d.after[k]||'(empty)'}`).join(' · ')||'No fields changed';
  }catch(_){}
  return activity.detail;
}
