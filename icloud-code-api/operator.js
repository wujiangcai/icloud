const $ = id => document.getElementById(id);
let token = localStorage.getItem("platformOperatorSession") || "";
let accounts = [];
let selected = new Set();
let inventoryPage = 1;
let toastTimer;
let statusLabels = {
  inventory: "库存中", sold: "已卖出", self_member: "自用会员",
  self_no_member: "自用未开会员", disabled: "停用", trash: "失效/垃圾"
};

const safe = value => String(value ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[c]));
const fmt = value => value ? new Date(value).toLocaleString("zh-CN", {timeZone:"Asia/Shanghai", hour12:false}) : "未同步";
const showToast = (message, error=false) => {
  const node = $("toast"); node.textContent = message; node.className = "toast" + (error ? " error" : "");
  clearTimeout(toastTimer); toastTimer = setTimeout(() => node.className = "toast hidden", 3200);
};
const clearSession = () => {
  token = ""; localStorage.removeItem("platformOperatorSession");
  $("appView").classList.add("hidden"); $("loginView").classList.remove("hidden");
};
const api = async (path, options={}) => {
  const headers = {...(options.body !== undefined ? {"Content-Type":"application/json"} : {}), ...(options.headers || {})};
  if (token) headers.Authorization = "Bearer " + token;
  const response = await fetch(path, {...options, headers, cache:"no-store"});
  const data = await response.json().catch(() => ({}));
  if (!response.ok) { if (response.status === 401) clearSession(); throw Error(data.detail || data.error || "请求失败"); }
  return data;
};
const statusOptions = (first="全部状态") => `<option value="">${first}</option>` + Object.entries(statusLabels).map(([key,label]) => `<option value="${key}">${label}</option>`).join("");
const accountOptions = () => `<option value="">全部 iCloud 账号</option>` + accounts.map(a => `<option value="${safe(a.id)}">${safe(a.apple_id || a.display_name || a.id)}</option>`).join("");

function closeModal() { $("modalRoot").className = "hidden"; $("modalRoot").textContent = ""; }
function openModal(title, body, submitLabel, submit) {
  const root = $("modalRoot"); root.className = "modal-backdrop";
  root.innerHTML = `<div class="modal"><div class="modal-head"><h3>${title}</h3><button class="modal-close">×</button></div><div class="modal-body">${body}</div></div>`;
  root.querySelector(".modal-close").onclick = closeModal;
  root.onclick = event => { if (event.target === root) closeModal(); };
  const button = root.querySelector("[data-submit]");
  if (!button) return;
  button.textContent = submitLabel;
  button.onclick = async () => {
    button.disabled = true;
    try { await submit(root.querySelector(".modal-body")); }
    catch (error) { const node = root.querySelector("[data-error]"); if (node) node.textContent = error.message; else showToast(error.message, true); }
    finally { button.disabled = false; }
  };
}
function showOutput(title, text) {
  openModal(title, `<div class="notice" data-output></div><div class="form-actions"><button data-copy class="button primary">复制</button><button data-submit class="button">关闭</button></div>`, "关闭", async () => closeModal());
  setTimeout(() => {
    const output = document.querySelector("[data-output]"); if (output) output.textContent = text;
    const copy = document.querySelector("[data-copy]"); if (copy) copy.onclick = async () => { await navigator.clipboard.writeText(text); showToast("已复制"); };
  }, 0);
}
function downloadText(text, filename) {
  const blob = new Blob(["\ufeff", text], {type:"text/plain;charset=utf-8"});
  const url = URL.createObjectURL(blob); const link = document.createElement("a");
  link.href = url; link.download = filename; link.click(); URL.revokeObjectURL(url);
}
function inventoryDeliveryFilters() {
  return {
    ids: [], search: $("inventorySearch").value.trim(), status: $("inventoryStatus").value,
    account_id: $("inventoryAccount").value,
    has_code: $("inventoryCode").value === "" ? null : $("inventoryCode").value === "true",
    include_inactive: true,
  };
}
async function exportDelivery(payload, filename) {
  const response = await fetch("/api/v1/operator/mailboxes/delivery-export", {
    method:"POST", headers:{"Content-Type":"application/json", Authorization:"Bearer "+token},
    body: JSON.stringify(payload), cache:"no-store",
  });
  const text = await response.text();
  if (!response.ok) {
    let detail = "导出发货信息失败";
    try { const data = JSON.parse(text); detail = data.detail || data.error || detail; } catch (_) {}
    if (response.status === 401) clearSession();
    throw Error(detail);
  }
  downloadText(text.replace(/^\ufeff/, ""), filename);
  return {text, count: response.headers.get("X-Exported-Count") || ""};
}
function setView(view) {
  document.querySelectorAll(".nav button").forEach(button => button.classList.toggle("active", button.dataset.view === view));
  document.querySelectorAll(".view").forEach(node => node.classList.toggle("active", node.id === view + "View"));
  const titles = {overview:["概览","查看平台状态和库存分布"], accounts:["iCloud 账号","管理多账号 CK、隐藏邮箱同步和生成任务"], inventory:["邮箱库存","分页检索、分类和批量操作"], tenants:["客户管理","客户账号与邮箱分配"]};
  $("pageTitle").textContent = titles[view][0]; $("pageSubtitle").textContent = titles[view][1]; $("sidebar").classList.remove("open");
  if (view === "overview") loadOverview(); if (view === "accounts") loadAccounts(); if (view === "inventory") loadInventory(); if (view === "tenants") loadTenants();
}

async function loadOverview() {
  const data = await api("/api/v1/operator/overview");
  statusLabels = data.mailbox_status_labels || statusLabels;
  const c = data.counts || {};
  const cards = [["邮箱总量",c.mailboxes||0,"含停用邮箱"],["iCloud 账号",c.icloud_accounts||0,"多账号归类"],["接码链接",c.public_links||0,"正在开放"],["24小时验证码",c.codes_24h||0,"新邮件"],["同步异常",c.sync_errors||0,"需要检查"]];
  $("overviewStats").innerHTML = cards.map(item => `<div class="stat"><span>${item[0]}</span><b>${item[1]}</b><small>${item[2]}</small></div>`).join("");
  $("overviewChips").innerHTML = Object.entries(statusLabels).map(([key,label]) => `<span class="chip">${label} <b>${(data.status_counts||{})[key]||0}</b></span>`).join("");
  $("inventoryStatus").innerHTML = statusOptions(); $("bulkStatus").innerHTML = statusOptions("批量改状态");
  const usage = data.r2_usage || {}; const pct = usage.max_bytes ? Math.min(100, Math.round(usage.put_bytes / usage.max_bytes * 100)) : 0;
  $("r2Text").textContent = `${Math.round((usage.put_bytes||0)/1024/1024*10)/10} MB / ${Math.round((usage.max_bytes||0)/1024/1024/1024*10)/10} GB`; $("r2Bar").style.width = pct + "%";
  const jobs = await api("/api/v1/operator/generation-jobs"); renderJobs(jobs.jobs || []);
}
function renderJobs(jobs) {
  const root = $("jobTable"); root.textContent = "";
  if (!jobs.length) { root.innerHTML = `<div class="empty">暂无生成任务</div>`; return; }
  const table = document.createElement("table"); table.className = "data-table"; table.innerHTML = "<thead><tr><th>账号</th><th>目标</th><th>已生成</th><th>状态</th><th>下次运行</th><th>错误</th><th>操作</th></tr></thead>";
  const body = document.createElement("tbody");
  jobs.forEach(job => {
    const row = document.createElement("tr"); [job.apple_id||job.account_id,job.target_total,job.generated_count,job.status,job.next_run_at?fmt(job.next_run_at):"立即",job.last_error||"—"].forEach(value => { const cell=document.createElement("td"); cell.textContent=value; row.append(cell); });
    const cell = document.createElement("td");
    if (job.status === "running") { const button=document.createElement("button"); button.className="button small"; button.textContent="停止"; button.onclick=async()=>{await api(`/api/v1/operator/generation-jobs/${job.id}/stop`,{method:"POST",body:"{}"});showToast("任务已停止");loadOverview();};cell.append(button); }
    if (job.status === "stopped" || job.status === "failed") { const button=document.createElement("button");button.className="button small";button.textContent="继续";button.onclick=async()=>{await api(`/api/v1/operator/generation-jobs/${job.id}/resume`,{method:"POST",body:"{}"});showToast("任务已继续");loadOverview();};cell.append(button); }
    row.append(cell); body.append(row);
  }); table.append(body); root.append(table);
}

async function loadAccounts() {
  const data = await api("/api/v1/operator/icloud-accounts"); accounts = data.accounts || []; $("inventoryAccount").innerHTML = accountOptions();
  const root = $("accountList"); root.textContent = "";
  if (!accounts.length) { root.innerHTML = `<div class="empty" style="grid-column:1/-1">还没有 iCloud 账号，点击“导入 CK 账号”开始。</div>`; return; }
  accounts.forEach(account => {
    const card=document.createElement("article");card.className="account-card";
    card.innerHTML=`<div style="display:flex;justify-content:space-between;gap:8px"><h3>${safe(account.apple_id||account.display_name||"未命名账号")}</h3><span class="status ${account.status==='active'?'inventory':'off'}">${account.status==='active'?'正常':'异常'}</span></div><div class="meta">${safe(account.display_name||"")} · ${safe(account.region)} · ${account.imap_configured?'IMAP 已配置':'IMAP 未配置'}</div><div class="account-counts">${Object.entries(statusLabels).filter(([key])=>(account.status_counts||{})[key]).map(([key,label])=>`<span class="chip">${label} ${(account.status_counts||{})[key]}</span>`).join("")||'<span class="muted">暂无邮箱</span>'}</div><div class="meta" style="margin-top:10px">Apple 同步：${fmt(account.last_apple_sync_at)} · IMAP：${fmt(account.last_imap_sync_at)}</div>${account.last_error?`<div class="danger-text" style="font-size:12px;margin-top:7px">${safe(account.last_error)}</div>`:''}`;
    const actions=document.createElement("div");actions.className="account-actions";
    const add=(text,fn)=>{const b=document.createElement("button");b.className="button small";b.textContent=text;b.onclick=fn;actions.append(b);};
    add("同步隐藏邮箱",async()=>{try{const x=await api(`/api/v1/operator/icloud-accounts/${account.id}/sync`,{method:"POST",body:"{}"});showToast(`已同步 ${x.synced} 个隐藏邮箱`);loadAccounts();loadInventory();}catch(e){showToast(e.message,true);}});
    add("配置 IMAP",()=>openImapModal(account)); add("生成一批",()=>openGenerateModal(account,"batch")); add("批量生成任务",()=>openGenerateModal(account,"campaign"));
    card.append(actions);root.append(card);
  });
}
function openImportModal() {
  openModal("导入 iCloud CK 账号",`<p class="muted">粘贴 new-icloud 支持的完整 cURL、Cookie 文本或 CK。系统会先校验账号，再保存加密 CK。</p><div class="form-grid"><label>CK / cURL<textarea data-cookie placeholder="粘贴完整 Cookie 或 Copy as cURL 内容"></textarea></label><label>区域<select data-region><option value="auto">自动检测</option><option value="global">全球</option><option value="china">中国区</option></select></label><div data-error class="error"></div></div><div class="form-actions"><button data-submit class="button primary"></button></div>`,"校验并导入",async box=>{const x=await api("/api/v1/operator/icloud-accounts/import",{method:"POST",body:JSON.stringify({cookie:box.querySelector("[data-cookie]").value,region:box.querySelector("[data-region]").value})});closeModal();showToast("账号已导入："+(x.account.apple_id||"成功"));loadAccounts();});
}
function openImapModal(account) {
  openModal("配置账号级 IMAP",`<p class="muted">同一 Apple 账号下的隐藏邮箱共享一个主 iCloud IMAP 连接。</p><div class="form-grid"><label>主 iCloud 邮箱<input data-email class="input" value="${safe(account.imap_username)}" placeholder="name@icloud.com"></label><label>App 专用密码<input data-password class="input" type="password" placeholder="首次配置必填，留空保留原密码"></label><label>IMAP 主机<input data-host class="input" value="${safe(account.imap_host||"imap.mail.me.com")}"></label><label>端口<input data-port class="input" type="number" value="${account.imap_port||993}"></label><label>文件夹<input data-mailbox class="input" value="${safe(account.imap_mailbox||"INBOX")}"></label><div data-error class="error"></div></div><div class="form-actions"><button data-submit class="button primary"></button></div>`,"保存配置",async box=>{await api(`/api/v1/operator/icloud-accounts/${account.id}/imap`,{method:"PATCH",body:JSON.stringify({email:box.querySelector("[data-email]").value,app_password:box.querySelector("[data-password]").value||null,host:box.querySelector("[data-host]").value,port:Number(box.querySelector("[data-port]").value),mailbox:box.querySelector("[data-mailbox]").value})});closeModal();showToast("IMAP 配置已保存");loadAccounts();});
}
function openGenerateModal(account, mode) {
  const batch=mode==="batch";
  openModal(batch?"生成隐藏邮箱":"创建批量生成任务",`<div class="form-grid"><div class="notice">每批最多 5 个。批量任务会按 Apple 账号冷却时间自动继续。</div>${batch?'<label>本批数量（1-5）<input data-count class="input" type="number" min="1" max="5" value="1"></label>':'<label>目标总数量<input data-target class="input" type="number" min="1" max="700" value="700"></label><label>每批数量（1-5）<input data-batch class="input" type="number" min="1" max="5" value="5"></label>'}<label>Apple 标签前缀<input data-prefix class="input" value="${safe(account.label_prefix||"icloud")}"></label><div data-error class="error"></div></div><div class="form-actions"><button data-submit class="button primary"></button></div>`,batch?"开始生成":"创建任务",async box=>{const prefix=box.querySelector("[data-prefix]").value;const path=batch?`/api/v1/operator/icloud-accounts/${account.id}/generate`:`/api/v1/operator/icloud-accounts/${account.id}/generation-campaigns`;const body=batch?{count:Number(box.querySelector("[data-count]").value),label_prefix:prefix}:{target_total:Number(box.querySelector("[data-target]").value),batch_size:Number(box.querySelector("[data-batch]").value),label_prefix:prefix};const x=await api(path,{method:"POST",body:JSON.stringify(body)});closeModal();showToast(batch?`生成完成 ${(x.generated||[]).length} 个`:"批量任务已创建");loadAccounts();loadInventory();loadOverview();});
}

async function loadInventory() {
  const params=new URLSearchParams({page:String(inventoryPage),page_size:$("pageSize").value,search:$("inventorySearch").value.trim(),status:$("inventoryStatus").value,account_id:$("inventoryAccount").value,include_inactive:"true"});
  if ($("inventoryCode").value) params.set("has_code",$("inventoryCode").value);
  const data=await api("/api/v1/operator/mailboxes?"+params);const rows=data.mailboxes||[];const root=$("inventoryRows");root.textContent="";
  selected=new Set([...selected].filter(id=>rows.some(row=>row.id===id)));$("selectedText").textContent=selected.size?`已选择 ${selected.size} 条`:"未选择";$("inventoryEmpty").classList.toggle("hidden",rows.length>0);rows.forEach(row=>root.append(makeMailboxRow(row)));
  const page=data.pagination;$("pageText").textContent=`第 ${page.page} / ${page.total_pages} 页，共 ${page.total} 条`;$("prevPage").disabled=page.page<=1;$("nextPage").disabled=page.page>=page.total_pages;$("selectAll").checked=!!rows.length&&rows.every(row=>selected.has(row.id));
}
function makeMailboxRow(mailbox) {
  const row=document.createElement("tr");const check=document.createElement("input");check.type="checkbox";check.className="check";check.checked=selected.has(mailbox.id);check.onchange=()=>{if(check.checked)selected.add(mailbox.id);else selected.delete(mailbox.id);$("selectedText").textContent=selected.size?`已选择 ${selected.size} 条`:"未选择";};let cell=document.createElement("td");cell.append(check);row.append(cell);
  cell=document.createElement("td");cell.className="mail-cell";cell.innerHTML=`<strong>${safe(mailbox.email)}</strong><small>${safe(mailbox.apple_label||mailbox.label||"无标签")} · ${mailbox.source==='generated'?'批量生成':mailbox.source==='synced'?'Apple同步':'手动添加'}</small>`;row.append(cell);
  cell=document.createElement("td");cell.className="mail-cell";cell.innerHTML=`<strong>${safe(mailbox.account_apple_id||"未关联账号")}</strong><small>${safe(mailbox.tenant_email||"")}</small>`;row.append(cell);
  cell=document.createElement("td");cell.innerHTML=`<span class="status ${safe(mailbox.business_status||"inventory")}">${safe(mailbox.business_status_label||statusLabels[mailbox.business_status]||mailbox.business_status)}</span>${mailbox.apple_active?'':'<small class="danger-text" style="display:block">Apple列表未返回</small>'}`;row.append(cell);
  cell=document.createElement("td");cell.innerHTML=mailbox.latest_code?`<span class="code">${safe(mailbox.latest_code)}</span><small style="display:block;color:#98a2b3">${fmt(mailbox.latest_code_at)}</small>`:'<span class="muted">—</span>';row.append(cell);
  cell=document.createElement("td");cell.textContent=String(mailbox.message_count||0);row.append(cell);
  cell=document.createElement("td");cell.className="mail-cell";cell.innerHTML=`<strong class="${mailbox.last_error?'danger-text':''}">${mailbox.last_error?'异常':fmt(mailbox.last_sync_at)}</strong><small>${safe(mailbox.last_error||"")}</small>`;row.append(cell);
  cell=document.createElement("td");const actions=document.createElement("div");actions.className="actions";const add=(text,fn)=>{const b=document.createElement("button");b.className="button small";b.textContent=text;b.onclick=fn;actions.append(b);};add("状态",()=>openStatusModal(mailbox));add("历史",()=>showMessages(mailbox));add("发货",async()=>{try{const x=await api(`/api/v1/operator/mailboxes/${mailbox.id}/delivery`);showOutput("单个发货格式",x.delivery_line);loadInventory();}catch(e){showToast(e.message,true);}});add(mailbox.public_access_enabled?"重置链接":"生成链接",async()=>{try{const x=await api(`/api/v1/operator/mailboxes/${mailbox.id}/public-access`,{method:"POST",body:"{}"});showOutput("发货信息",`${x.delivery_line}\n\n查看页：\n${x.viewer_url}\n\n访问令牌：\n${x.token}`);loadInventory();}catch(e){showToast(e.message,true);}});cell.append(actions);row.append(cell);return row;
}
function openStatusModal(mailbox) {
  openModal("修改邮箱状态",`<div class="form-grid"><label>状态<select data-status>${statusOptions("")}</select></label><label>客户ID（可选）<input data-customer class="input" value="${safe(mailbox.customer_id)}"></label><label>订单号（可选）<input data-order class="input" value="${safe(mailbox.order_no)}"></label><label>备注<textarea data-note>${safe(mailbox.note)}</textarea></label><div data-error class="error"></div></div><div class="form-actions"><button data-submit class="button primary"></button></div>`,"保存",async box=>{box.querySelector("[data-status]").value=mailbox.business_status;await api(`/api/v1/operator/mailboxes/${mailbox.id}/business`,{method:"PATCH",body:JSON.stringify({status:box.querySelector("[data-status]").value,customer_id:box.querySelector("[data-customer]").value,order_no:box.querySelector("[data-order]").value,note:box.querySelector("[data-note]").value})});closeModal();showToast("状态已更新");loadInventory();loadOverview();});
}
async function showMessages(mailbox) { try { const data=await api(`/api/v1/operator/mailboxes/${mailbox.id}/messages?limit=50`);const messages=data.messages||[];showOutput(`历史邮件 · ${mailbox.email}`,messages.length?messages.map(item=>`[${fmt(item.received_at)}] ${item.code?`验证码 ${item.code} · `:""}${item.subject||"无主题"}\n${item.preview||""}`).join("\n\n"):"暂无历史邮件"); } catch(error) { showToast(error.message,true); } }

async function loadTenants() { const data=await api("/api/v1/operator/tenants");const root=$("tenantRows");root.textContent="";(data.tenants||[]).forEach(tenant=>{const row=document.createElement("tr");[tenant.email,tenant.active?"正常":"停用",tenant.mailbox_count,tenant.message_count,fmt(tenant.last_sync_at)].forEach(value=>{const cell=document.createElement("td");cell.textContent=value;row.append(cell);});const cell=document.createElement("td");const button=document.createElement("button");button.className="button small";button.textContent=tenant.active?"停用":"启用";button.onclick=async()=>{await api(`/api/v1/operator/tenants/${tenant.id}`,{method:"PATCH",body:JSON.stringify({active:!tenant.active})});showToast("客户状态已更新");loadTenants();};cell.append(button);row.append(cell);root.append(row);});if(!data.tenants?.length)root.innerHTML='<tr><td colspan="6" class="empty">暂无客户，邮箱库存不需要先创建客户。</td></tr>'; }
function openTenantModal() { openModal("创建客户",`<div class="form-grid"><label>客户邮箱<input data-email class="input" type="email"></label><label>初始密码<input data-password class="input" type="password"></label><div data-error class="error"></div></div><div class="form-actions"><button data-submit class="button primary"></button></div>`,"创建",async box=>{await api("/api/v1/operator/tenants",{method:"POST",body:JSON.stringify({email:box.querySelector("[data-email]").value,password:box.querySelector("[data-password]").value})});closeModal();showToast("客户已创建");loadTenants();}); }

$("loginBtn").onclick=async()=>{const error=$("loginError");error.textContent="";try{const data=await api("/api/v1/operator/login",{method:"POST",body:JSON.stringify({key:$("loginKey").value})});token=data.access_token;localStorage.setItem("platformOperatorSession",token);$("loginView").classList.add("hidden");$("appView").classList.remove("hidden");await loadOverview();await loadAccounts();}catch(e){error.textContent=e.message;}};
$("loginKey").onkeydown=event=>{if(event.key==="Enter")$("loginBtn").click()};
document.querySelectorAll(".nav button").forEach(button=>button.onclick=()=>setView(button.dataset.view));
$("logoutBtn").onclick=async()=>{try{await api("/api/v1/operator/logout",{method:"POST",body:"{}"});}catch(_){}clearSession();};
$("refreshBtn").onclick=()=>{const view=document.querySelector(".view.active")?.id.replace("View","")||"overview";setView(view);};
$("menuBtn").onclick=()=>$("sidebar").classList.toggle("open");$("importAccountBtn").onclick=openImportModal;$("accountRefreshBtn").onclick=loadAccounts;$("newTenantBtn").onclick=openTenantModal;
$("inventorySearchBtn").onclick=()=>{inventoryPage=1;loadInventory();};$("inventorySearch").onkeydown=event=>{if(event.key==="Enter")$("inventorySearchBtn").click();};$("prevPage").onclick=()=>{if(inventoryPage>1){inventoryPage--;loadInventory();}};$("nextPage").onclick=()=>{inventoryPage++;loadInventory();};$("pageSize").onchange=()=>{inventoryPage=1;loadInventory();};
$("selectAll").onchange=event=>{document.querySelectorAll("#inventoryRows input[type=checkbox]").forEach(check=>{check.checked=event.target.checked;check.dispatchEvent(new Event("change"));});};
$("bulkApply").onclick=async()=>{const status=$("bulkStatus").value;if(!status||!selected.size){showToast("请选择邮箱和目标状态",true);return;}try{await api("/api/v1/operator/mailboxes/batch-business",{method:"PATCH",body:JSON.stringify({ids:[...selected],status,customer_id:$("bulkCustomer").value||null,order_no:$("bulkOrder").value||null})});showToast(`已批量更新 ${selected.size} 条`);selected.clear();loadInventory();loadOverview();}catch(e){showToast(e.message,true);}};
$("bulkDeliveryBtn").onclick=async()=>{if(!selected.size){showToast("请先选择要导出的邮箱",true);return;}try{const count=selected.size;const x=await exportDelivery({...inventoryDeliveryFilters(),ids:[...selected]},"icloud-delivery-selected.txt");showToast(`已导出 ${x.count||count} 条发货信息`);}catch(e){showToast(e.message,true);}};
$("deliveryExportBtn").onclick=async()=>{try{const x=await exportDelivery(inventoryDeliveryFilters(),"icloud-delivery.txt");showToast(`已导出 ${x.count||"筛选结果"} 条发货信息`);}catch(e){showToast(e.message,true);}};
$("exportBtn").onclick=async()=>{try{const params=new URLSearchParams({search:$("inventorySearch").value.trim(),status:$("inventoryStatus").value,account_id:$("inventoryAccount").value,include_inactive:"true"});const response=await fetch("/api/v1/operator/mailboxes/export?"+params,{headers:{Authorization:"Bearer "+token}});if(!response.ok)throw Error("导出失败");const url=URL.createObjectURL(await response.blob());const link=document.createElement("a");link.href=url;link.download="icloud-mailboxes.csv";link.click();URL.revokeObjectURL(url);}catch(e){showToast(e.message,true);}};

if (token) { $("loginView").classList.add("hidden");$("appView").classList.remove("hidden");Promise.all([loadOverview(),loadAccounts()]).catch(clearSession); }
