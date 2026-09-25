export const adminHtml = `<!doctype html>
<html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Personal MCP Gateway</title>
<style>body{font:16px system-ui;max-width:780px;margin:2rem auto;padding:0 1rem;color:#17212f;background:#f7f9fc}section{background:white;border:1px solid #d8e0ec;border-radius:10px;padding:1rem;margin:1rem 0}label{display:block;margin:.7rem 0}input,select,textarea,button{font:inherit;padding:.55rem;box-sizing:border-box}input,select,textarea{width:100%;border:1px solid #aab8cb;border-radius:5px}button{background:#194a88;color:white;border:0;border-radius:5px;cursor:pointer;margin:.3rem .4rem .3rem 0}button.secondary{background:#526275}small{color:#526275}li{padding:.5rem 0;border-bottom:1px solid #e1e5ed}code{overflow-wrap:anywhere}#status{min-height:1.4em}</style>
<main><h1>Personal MCP Gateway</h1><p>Add a service connection, store its API key, then add an action the AI can call. Use <code>/mcp</code> as the agent endpoint.</p>
<section><h2>Admin access</h2><label>Admin token <input id="token" type="password" autocomplete="off"></label><button id="connect">Unlock</button><small>The token stays in this page’s memory until you close or reload it.</small></section>
<p id="status" role="status"></p>
<section><h2>Connections</h2><ul id="connections"></ul><form id="connection"><label>Name <input name="name" required maxlength="100"></label><label>Type <select name="kind"><option value="api">Service API</option><option value="mcp">MCP server</option></select></label><label>Base URL <input name="baseUrl" type="url" placeholder="https://api.example.com" required></label><label>Authentication <select name="authType"><option value="bearer">Bearer token</option><option value="apiKeyHeader">API key header</option><option value="none">None</option></select></label><label>Header name (when using API key header) <input name="headerName" placeholder="X-API-Key"></label><label><input name="enabled" type="checkbox" checked style="width:auto"> Enabled</label><button>Add connection</button></form></section>
<section><h2>Store a key</h2><form id="secret"><label>Connection <select name="connectionId" id="secretConnection"></select></label><label>API key or token <input type="password" name="secret" required autocomplete="off"></label><button>Store key</button></form><small>The saved key cannot be viewed through this interface.</small></section>
<section id="toolPicker" hidden><h2>Choose MCP tools</h2><p id="toolConnection"></p><div id="toolChoices"></div><label>Allowed tool names, one per line <textarea id="allowedTools" rows="5" placeholder="search\nget_record"></textarea></label><button id="saveTools">Save selected tools</button><small>Only these exact names will be exposed to your AI agent. You can enter names manually if discovery is unavailable.</small></section>
<section><h2>API actions</h2><ul id="operations"></ul><form id="operation"><label>Connection <select name="connectionId" id="operationConnection"></select></label><label>Action name <input name="name" required></label><label>Description for AI <input name="description" required></label><label>HTTP method <select name="method"><option>GET</option><option>POST</option><option>PUT</option><option>PATCH</option><option>DELETE</option></select></label><label>Path <input name="path" value="/" required></label><label>Input schema (JSON) <textarea name="inputSchema" rows="5">{"type":"object","properties":{},"additionalProperties":false}</textarea></label><button>Add action</button></form></section></main>
<script>
let token = '';
let selectedConnection = '';
const byId = id => document.getElementById(id);
const status = message => { byId('status').textContent = message; };
async function api(path, method = 'GET', body) {
  const response = await fetch(path, { method, headers: { Authorization: 'Bearer ' + token, ...(body ? {'Content-Type':'application/json'} : {}) }, body: body ? JSON.stringify(body) : undefined, cache: 'no-store' });
  if (!response.ok) throw new Error((await response.json().catch(() => ({}))).error || 'Request failed');
  return response.json();
}
function option(select, record) { const node = document.createElement('option'); node.value=record.id; node.textContent=record.name; select.append(node); }
async function refresh() {
  const [connections, operations] = await Promise.all([api('/admin/connections'),api('/admin/operations')]);
  byId('connections').replaceChildren(); byId('operations').replaceChildren();
  byId('secretConnection').replaceChildren(); byId('operationConnection').replaceChildren();
  for (const record of connections.connections) {
    const item=document.createElement('li'); item.textContent=record.name+' · '+record.kind+' · '+record.baseUrl+' ';
    const remove=document.createElement('button'); remove.textContent='Remove'; remove.className='secondary';
    remove.onclick=async()=>{ try { await api('/admin/connections/'+record.id,'DELETE'); await refresh(); status('Connection removed'); } catch(error){status(error.message);} }; item.append(remove); byId('connections').append(item);
    if(record.kind==='mcp') { const select=document.createElement('button'); select.textContent='Choose tools'; select.onclick=()=>chooseTools(record); item.append(select); }
    option(byId('secretConnection'),record); if(record.kind==='api') option(byId('operationConnection'),record);
  }
  for (const record of operations.operations) {
    const item=document.createElement('li'); item.textContent=record.name+' · '+record.method+' '+record.path+' ';
    const remove=document.createElement('button'); remove.textContent='Remove'; remove.className='secondary';
    remove.onclick=async()=>{ try { await api('/admin/operations/'+record.id,'DELETE'); await refresh(); status('Action removed'); } catch(error){status(error.message);} }; item.append(remove); byId('operations').append(item);
  }
}
async function chooseTools(connection) {
  selectedConnection=connection.id; byId('toolPicker').hidden=false;
  byId('toolConnection').textContent=connection.name;
  byId('allowedTools').value=(connection.allowedTools || []).join('\n');
  byId('toolChoices').replaceChildren();
  try {
    const result=await api('/admin/connections/'+connection.id+'/tools');
    for(const tool of result.tools) {
      const label=document.createElement('label'); const checkbox=document.createElement('input');
      checkbox.type='checkbox'; checkbox.style.width='auto'; checkbox.checked=(connection.allowedTools || []).includes(tool.name);
      checkbox.onchange=()=>{
        const names=new Set(byId('allowedTools').value.split(/[\n,]/).map(name=>name.trim()).filter(Boolean));
        if(checkbox.checked) names.add(tool.name); else names.delete(tool.name);
        byId('allowedTools').value=[...names].join('\n');
      };
      label.append(checkbox, document.createTextNode(' '+tool.name+' — '+tool.description)); byId('toolChoices').append(label);
    }
    status(result.truncated ? 'Showing the first 100 upstream tools' : 'Upstream tools loaded');
  } catch(error) { status(error.message+'; enter exact tool names manually'); }
  byId('toolPicker').scrollIntoView({behavior:'smooth'});
}
byId('saveTools').onclick=async()=>{
  const allowedTools=[...new Set(byId('allowedTools').value.split(/[\n,]/).map(name=>name.trim()).filter(Boolean))];
  try { await api('/admin/connections/'+selectedConnection,'PATCH',{allowedTools}); await refresh(); status('Allowed tools saved'); }
  catch(error) { status(error.message); }
};
byId('connect').onclick=async()=>{ token=byId('token').value; byId('token').value=''; try { await refresh(); status('Unlocked'); } catch(error) { token=''; status(error.message); } };
byId('connection').onsubmit=async event=>{ event.preventDefault(); const data=Object.fromEntries(new FormData(event.target)); data.enabled=event.target.elements.enabled.checked; if(data.authType!=='apiKeyHeader') delete data.headerName; try { await api('/admin/connections','POST',data); event.target.reset(); await refresh(); status('Connection added'); } catch(error){status(error.message);} };
byId('secret').onsubmit=async event=>{ event.preventDefault(); const data=Object.fromEntries(new FormData(event.target)); try { await api('/admin/connections/'+data.connectionId+'/secret','PUT',{secret:data.secret}); event.target.elements.secret.value=''; status('Key stored'); } catch(error){status(error.message);} };
byId('operation').onsubmit=async event=>{ event.preventDefault(); const data=Object.fromEntries(new FormData(event.target)); try { data.inputSchema=JSON.parse(data.inputSchema); await api('/admin/operations','POST',data); await refresh(); status('Action added'); } catch(error){status(error.message);} };
</script></html>`;
