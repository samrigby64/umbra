// Four investigation stages; all existing views remain reachable.
document.querySelector('main').insertAdjacentHTML('beforeend', `
<section id="jobs"><h2>Collection jobs</h2><p class="hint">Save a bounded collection, then start it when ready. Schedules run while Umbra is open. After a restart, interrupted work becomes eligible again after the 90-second lease expires. Jobs share the installation's page queue.</p>
<div class="panel"><label for="job-name">Job name</label><input id="job-name" placeholder="Weekly source monitoring">
<label for="job-seeds">Starting URLs (one per line)</label><textarea id="job-seeds" placeholder="http://…onion/"></textarea>
<div class="grid2"><div><label for="job-depth">Link depth (0 = seeds only)</label><input id="job-depth" type="number" value="1" min="0" max="20"></div>
<div><label for="job-pages">Successful pages per run</label><input id="job-pages" type="number" value="25" min="1" max="10000"></div>
<div><label for="job-duration">Maximum run time (minutes)</label><input id="job-duration" type="number" value="10" min="1" max="1440"></div>
<div><label for="job-interval">Repeat every (minutes; 0 = once)</label><input id="job-interval" type="number" value="0" min="0"></div></div>
<label><input id="job-strict" type="checkbox" checked> Stay on the seed hosts</label>
<label><input id="job-bytes" type="checkbox" checked> Retain body bytes for evidence verification</label>
<p class="hint">Turning off host restriction allows discovery across sites. Depth and page limits still apply. Existing recrawl backoff is respected; starting a job does not force every seed to be fetched again.</p>
<button class="btn" onclick="saveCollectionJob()">Save paused job</button><p id="job-message" role="status"></p></div>
<button onclick="loadJobs()">Refresh jobs</button><div id="job-list"></div></section>
<section id="feedback"><h2>Extraction review</h2><p class="hint">Record a correction against a retained version. Reviews preserve the original capture and produce test examples; they do not silently rewrite intelligence. Open a page's Versions view to select the capture.</p>
<div class="panel"><label for="feedback-version">Retained version number</label><input id="feedback-version" type="number" min="1">
<label for="feedback-extractor">Extractor</label><select id="feedback-extractor"><option value="listings">Listings</option><option value="iocs">Indicators</option></select>
<label for="feedback-value">Exact indicator or product text being reviewed</label><input id="feedback-value">
<label for="feedback-verdict">Assessment</label><select id="feedback-verdict"><option value="false_positive">False positive</option><option value="missed">Missed extraction</option><option value="correct">Correct extraction</option></select>
<label for="feedback-reason">Reason and expected result</label><textarea id="feedback-reason"></textarea><button class="btn" onclick="saveExtractionReview()">Save review</button>
<button onclick="download('/collection/regression-examples','extraction-examples.json','Reviewed examples')">Export test examples</button><p id="feedback-status" role="status"></p></div><div id="feedback-list"></div></section>
<section id="reports"><h2>Reports and evidence</h2><p class="hint">Select a case to review its saved versions, download an analyst report, or export an evidence ZIP. Reports support literal redactions. Every new ZIP includes an offline Python verifier.</p>
<div class="panel"><h3>Verify a received bundle</h3><p>Use a trusted copy of <code>verify_evidence.py</code> and run:</p><pre>python verify_evidence.py case-evidence.zip</pre><p>For HMAC authentication, add <code>--key-file protected-key.txt</code>. Checksums alone establish internal consistency; they do not establish site identity or a trusted capture time.</p></div><div id="report-cases"></div></section>`);
TABS.push('jobs','feedback','reports');
Object.assign(LABELS,{jobs:'Saved jobs',feedback:'Extraction review',reports:'Case exports'});
const STAGES = [
  {name:'Collect',tabs:['dashboard','jobs','crawl','sites','timeline'],hint:'Choose sources, set limits, and check collection health.'},
  {name:'Review',tabs:['workbench','inbox','quality','feedback','duplicates','pages','iocs','listings','credentials','search'],hint:'Inspect captures, remove noise from your assessment, and record corrections.'},
  {name:'Investigate',tabs:['cases','graph','relationships','actors'],hint:'Save relevant versions in cases and assess connections against source material.'},
  {name:'Report',tabs:['reports'],hint:'Export reviewed exhibits and explain your findings.'},
  {name:'Settings',tabs:['operations','watchlists'],hint:'Manage accounts, backups and monitoring rules.'}
];
let activeStage=0;
const stageBar=document.createElement('div');stageBar.id='stage-nav';
stageBar.setAttribute('aria-label','Investigation workflow');
el('nav').before(stageBar);
const stageHelp=document.createElement('p');stageHelp.className='hint';stageHelp.id='stage-help';el('nav').after(stageHelp);
const originalWorkflowNav=buildNav;
buildNav=function(){originalWorkflowNav();renderStage();};
function renderStage(){
  stageBar.innerHTML=STAGES.map((s,i)=>`<button class="${i===activeStage?'selected':''}" data-stage="${i}" aria-pressed="${i===activeStage}">${i<4?(i+1)+'. ':''}${s.name}</button>`).join('');
  stageBar.querySelectorAll('[data-stage]').forEach(b=>b.onclick=()=>show(STAGES[+b.dataset.stage].tabs[0]));
  el('nav').querySelectorAll('[data-tab]').forEach(a=>{a.style.display=STAGES[activeStage].tabs.includes(a.dataset.tab)?'':'none';});
  STAGES[activeStage].tabs.forEach(t=>{const a=el('nav').querySelector('[data-tab="'+t+'"]');if(a)el('nav').append(a);});
  stageHelp.textContent=STAGES[activeStage].hint;
}
const previousWorkflowShow=show;
show=function(tab){
  const stage=STAGES.findIndex(s=>s.tabs.includes(tab));if(stage>=0)activeStage=stage;
  previousWorkflowShow(tab);renderStage();
  ({jobs:loadJobs,feedback:loadExtractionReviews,reports:loadReportCases,quality:loadCollectionQuality}[tab]||(()=>{}))();
  if(tab==='jobs')pollTimer=setInterval(loadJobs,5000);
};
const workflowStyle=document.createElement('style');
workflowStyle.textContent=`#stage-nav{display:flex;gap:8px;flex-wrap:wrap;padding:18px 24px 4px}#stage-nav button{padding:10px 20px;border-radius:8px;font-size:15px}#stage-nav .selected{background:#6555da;color:white;border-color:#a99fff}#stage-help{padding:0 24px}#live-quality{margin-bottom:24px}.quality-cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(155px,1fr));gap:12px}.quality-cards article{padding:16px;border:1px solid #444;border-radius:8px}.quality-cards strong{font-size:28px;display:block}#job-list td{overflow-wrap:anywhere}#job-list table{table-layout:fixed;width:100%}`;
document.head.append(workflowStyle);
el('quality').insertAdjacentHTML('afterbegin','<div id="live-quality" class="panel" aria-live="polite"></div>');
el('operations').insertAdjacentHTML('beforeend',`<div class="panel"><h3>Account security</h3><p>Use an individual account to enable an authenticator. Keep the security key and backup encryption key in your organisation’s protected recovery storage, separately from database backups. API keys remain machine credentials and do not use MFA.</p>
<button onclick="accountSecurity()">Manage authenticator</button><button onclick="issueRecovery()">Issue account recovery token</button><button onclick="recoverAccount()">Recover password</button><p>Automatic and manual GUI backups are encrypted. Restore to a new database file with the backup key before switching an installation.</p></div>`);
const oldSignIn=signIn;
signIn=function(){oldSignIn();el('login-password').insertAdjacentHTML('afterend','<label for="login-otp">Authenticator code (if enabled)</label><input id="login-otp" inputmode="numeric" maxlength="6" autocomplete="one-time-code">');el('login-submit').onclick=async()=>{try{const r=await post('/auth/login',{username:el('login-name').value,password:el('login-password').value,otp:el('login-otp').value});key=r.token;sessionStorage.setItem('umbra_session',key);el('apikey').value='';closeModal();show('cases');toast('Signed in');}catch(e){el('login-error').textContent=e.message;}};};
loginButton.onclick=()=>signIn();
async function loadCollectionQuality(){try{const q=await get('/collection/quality');el('live-quality').innerHTML='<h2>Collection quality</h2><div class="quality-cards">'+[
  ['Retained pages',q.retained_pages],['Unique complete bodies',q.unique_complete_bodies],['Substantive pages',q.unique_substantive_pages],
  ['Duplicate rate',q.duplicate_rate===null?'—':Math.round(q.duplicate_rate*100)+'%'],['Captured within 7 days',q.fresh_within_7_days],
  ['Extraction errors',q.pages_with_extraction_errors]
].map(([label,value])=>`<article><strong>${esc(value)}</strong>${esc(label)}</article>`).join('')+`</div><p>${esc(q.definition)}</p><p>${q.extraction_status_unknown} captures without extraction diagnostics · ${q.older_than_7_days} older captures · ${q.capture_date_unknown} unknown dates · ${q.truncated_or_unknown} truncated or incomplete metadata.</p>`;}catch(e){el('live-quality').textContent=e.message;}}
async function saveCollectionJob(){try{const p={name:el('job-name').value,seeds:el('job-seeds').value.split(/\s+/).filter(Boolean),max_depth:+el('job-depth').value,max_pages:+el('job-pages').value,max_duration_s:+el('job-duration').value*60,interval_s:+el('job-interval').value*60,strict_scope:el('job-strict').checked,store_html:el('job-bytes').checked};const r=await post('/collection/jobs',p);el('job-message').textContent='Saved job #'+r.id+'. Choose Start / resume below when ready.';loadJobs();}catch(e){el('job-message').textContent=typeof e.message==='string'?e.message:'Check the job fields';}}
async function loadJobs(){try{const r=await get('/collection/jobs');el('job-list').innerHTML=table(['Job / scope','State','Last result','Next run (UTC)','Control'],r.jobs,j=>`<tr><td><b>${esc(j.name)}</b><br>${j.config.seeds.length} seeds · depth ${j.config.max_depth} · ${j.config.max_pages} pages<br>${j.config.strict_scope?'Seed hosts only':'Discovery enabled'}</td><td>${esc(j.status)}</td><td>${esc((j.stop_reason||'No run yet').replaceAll('_',' '))}<br>${j.last_result.crawled??0} fetched</td><td>${esc(j.next_run_at||'Not scheduled')}</td><td><button data-job="${j.id}" data-action="${j.paused?'resume':'pause'}">${j.paused?'Start / resume':'Pause'}</button></td></tr>`,'No saved jobs. Save one above.');el('job-list').querySelectorAll('[data-job]').forEach(b=>b.onclick=async()=>{try{await post('/collection/jobs/'+b.dataset.job+'/'+b.dataset.action);loadJobs();}catch(e){toast(e.message);}});}catch(e){el('job-list').textContent=e.message;}}
async function saveExtractionReview(){try{await post('/collection/feedback',{version_id:+el('feedback-version').value,extractor:el('feedback-extractor').value,value:el('feedback-value').value,verdict:el('feedback-verdict').value,reason:el('feedback-reason').value});el('feedback-status').textContent='Review saved with its source version.';loadExtractionReviews();}catch(e){el('feedback-status').textContent=e.message;}}
async function loadExtractionReviews(){try{const r=await get('/collection/feedback');el('feedback-list').innerHTML=table(['Version','Extractor / value','Assessment','Reason'],r.reviews,x=>`<tr><td>#${x.version_id}</td><td>${esc(x.extractor)} · ${esc(x.value)}</td><td>${esc(x.verdict.replaceAll('_',' '))}</td><td>${esc(x.reason)}</td></tr>`,'No extraction reviews yet.');}catch(e){el('feedback-list').textContent=e.message;}}
const oldPageVersions=pageVersions;
pageVersions=async function(encoded){await oldPageVersions(encoded);if(el('version-new')){const b=document.createElement('button');b.textContent='Review extraction from this version';b.onclick=()=>{const version=el('version-new').value;closeModal();show('feedback');el('feedback-version').value=version;};el('modal-box').append(b);}};
async function loadReportCases(){try{const r=await get('/cases');el('report-cases').innerHTML=r.cases.map(c=>`<article class="panel"><h3>${esc(c.name)}</h3><button data-report-case="${c.id}">Open case and export</button></article>`).join('')||'<p>Create a case and save page versions before exporting.</p>';el('report-cases').querySelectorAll('[data-report-case]').forEach(b=>b.onclick=()=>{show('cases');openCase(+b.dataset.reportCase);});}catch(e){el('report-cases').textContent=e.message;}}
function securitySignedOut(){key='';sessionStorage.removeItem('umbra_session');closeModal();toast('Security settings changed. Sign in again with a fresh code.');}
async function accountSecurity(){try{const r=await get('/auth/security');openModal(`<h2>Authenticator ${r.mfa_enabled?'enabled':'setup'}</h2><label for="sec-password">Current password</label><input id="sec-password" type="password"><label for="sec-code">Authenticator code</label><input id="sec-code" maxlength="6" inputmode="numeric"><button id="sec-start">${r.mfa_enabled?'Disable authenticator':'Generate setup secret'}</button><div id="sec-result" role="status"></div>`);el('sec-start').onclick=async()=>{try{const proof={password:el('sec-password').value,otp:el('sec-code').value};if(r.mfa_enabled){await post('/auth/mfa/disable',proof);securitySignedOut();return;}const setup=await post('/auth/mfa/setup',proof);el('sec-result').innerHTML='<p>Enter this secret in your authenticator app, then enter its six-digit code above.</p><code>'+esc(setup.secret)+'</code><p><button id="sec-confirm">Confirm and enable</button></p>';el('sec-confirm').onclick=async()=>{try{await post('/auth/mfa/confirm',{otp:el('sec-code').value});securitySignedOut();}catch(e){toast(e.message);}};}catch(e){el('sec-result').textContent=e.message;}};}catch(e){toast(e.message);}}
function issueRecovery(){openModal('<h2>Issue password recovery</h2><p>Check the account owner’s identity before privately handing over the token. MFA is preserved.</p><label for="recover-user">Account ID from the team list</label><input id="recover-user" type="number"><button id="recover-issue">Generate one-use token</button><p id="recover-token"></p>');el('recover-issue').onclick=async()=>{try{const r=await post('/team/'+Number(el('recover-user').value)+'/recovery');el('recover-token').textContent=r.token+' — expires in 15 minutes. '+r.notice;}catch(e){el('recover-token').textContent=e.message;}};}
function recoverAccount(){openModal('<h2>Recover password</h2><label for="reset-token">Recovery token from your administrator</label><input id="reset-token"><label for="reset-password">New password (12+ characters)</label><input id="reset-password" type="password"><label for="reset-otp">Authenticator code (if enabled)</label><input id="reset-otp" maxlength="6"><button id="reset-submit">Set new password</button><p id="reset-status"></p>');el('reset-submit').onclick=async()=>{try{await post('/auth/recover',{token:el('reset-token').value,password:el('reset-password').value,otp:el('reset-otp').value});securitySignedOut();}catch(e){el('reset-status').textContent=e.message;}};}
const guide=document.createElement('article');guide.className='panel';guide.id='first-use-guide';
guide.innerHTML='<h2>Your first investigation</h2><p>Start with one source and review what was actually captured before expanding collection.</p><ol><li><button data-guide="operations">Check setup and Tor</button> — sign in, check connectivity, and confirm backup status.</li><li><button data-guide="jobs">Create a small saved job</button> — use one seed, depth 0, one page and a two-minute limit. Save paused, review the scope, then resume.</li><li><button data-guide="pages">Inspect captured pages</button> — open the source and its Versions view. An unreachable source is not proof it has disappeared.</li><li><button data-guide="feedback">Review extraction</button> — compare each candidate with its retained source. Record mistakes and missing results.</li><li><button data-guide="cases">Save an exhibit in a case</button> — distinguish source statements from your interpretation.</li><li><button data-guide="reports">Export and verify</button> — download the case ZIP and run the independent verifier. Preserve the original bundle.</li></ol><p>This guide does not mark steps complete automatically. Check the result at each stage.</p>';
el('dashboard').prepend(guide);
guide.querySelectorAll('[data-guide]').forEach(button=>button.onclick=()=>{
  show(button.dataset.guide);
  if(button.dataset.guide==='jobs'&&!el('job-name').value&&!el('job-seeds').value){
    el('job-depth').value='0';el('job-pages').value='1';el('job-duration').value='2';
  }
});
buildNav();show(document.querySelector('main section.active')?.id||'dashboard');
