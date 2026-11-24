/* SecureVault PWA — local encrypted vault.
   Face ID is requested through WebAuthn platform passkeys. The WebAuthn PRF
   extension supplies the secret used to derive the AES-GCM encryption key.
   If PRF is unavailable, setup fails closed rather than storing plaintext. */
const DB_NAME = "securevault-local";
const STORE = "meta";
const CRED_KEY = "credential";
const SALT_KEY = "prfSalt";
const VAULT_KEY = "encryptedVault";
const $ = (id) => document.getElementById(id);
let cryptoKey = null;
let accounts = [];
let selectedId = null;
let selectedAccount = null;
let passwordRevealed = false;
let toastTimer;

function b64u(bytes) {
  let s = ""; new Uint8Array(bytes).forEach(b => s += String.fromCharCode(b));
  return btoa(s).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
}
function fromB64u(s) {
  s = s.replace(/-/g,"+").replace(/_/g,"/");
  while (s.length % 4) s += "=";
  return Uint8Array.from(atob(s), c => c.charCodeAt(0));
}
function randomBytes(n) { return crypto.getRandomValues(new Uint8Array(n)); }
function openDB() {
  return new Promise((resolve,reject) => {
    const req = indexedDB.open(DB_NAME,1);
    req.onupgradeneeded = () => req.result.createObjectStore(STORE);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}
async function dbGet(key) {
  const db=await openDB(); return new Promise((resolve,reject)=>{
    const tx=db.transaction(STORE,"readonly"),r=tx.objectStore(STORE).get(key);
    r.onsuccess=()=>resolve(r.result);r.onerror=()=>reject(r.error);
  });
}
async function dbSet(key,value) {
  const db=await openDB(); return new Promise((resolve,reject)=>{
    const tx=db.transaction(STORE,"readwrite");tx.objectStore(STORE).put(value,key);
    tx.oncomplete=()=>resolve();tx.onerror=()=>reject(tx.error);
  });
}
async function deriveKey(prfBytes) {
  const material=await crypto.subtle.importKey("raw",prfBytes,"HKDF",false,["deriveKey"]);
  return crypto.subtle.deriveKey(
    {name:"HKDF",hash:"SHA-256",salt:new TextEncoder().encode("SecureVault v1"),info:new TextEncoder().encode(location.hostname)},
    material,{name:"AES-GCM",length:256},false,["encrypt","decrypt"]
  );
}
async function encryptVault(data) {
  const iv=randomBytes(12),plain=new TextEncoder().encode(JSON.stringify(data));
  const cipher=await crypto.subtle.encrypt({name:"AES-GCM",iv},cryptoKey,plain);
  await dbSet(VAULT_KEY,{iv:b64u(iv),cipher:b64u(cipher),version:1});
}
async function decryptVault() {
  const record=await dbGet(VAULT_KEY);
  if(!record){accounts=[];return;}
  const plain=await crypto.subtle.decrypt({name:"AES-GCM",iv:fromB64u(record.iv)},cryptoKey,fromB64u(record.cipher));
  accounts=JSON.parse(new TextDecoder().decode(plain));
}
function supportsSecurePasskeys() {
  return window.isSecureContext && !!window.PublicKeyCredential &&
    !!navigator.credentials && !!crypto.subtle;
}
function showLockMessage(message){$("lockMessage").textContent=message||"";}
function showToast(message){
  const el=$("toast");el.textContent=message;el.classList.add("show");
  clearTimeout(toastTimer);toastTimer=setTimeout(()=>el.classList.remove("show"),2100);
}
function showVault(){
  $("lockScreen").classList.add("hidden");$("vaultScreen").classList.remove("hidden");
  renderAccounts();
}
function showLocked(){
  cryptoKey=null;accounts=[];$("vaultScreen").classList.add("hidden");$("lockScreen").classList.remove("hidden");
  $("setupButton").classList.toggle("hidden",!!localStorage.getItem("sv-ready"));
  $("unlockButton").classList.toggle("hidden",!localStorage.getItem("sv-ready"));
  $("lockTitle").textContent=localStorage.getItem("sv-ready")?"Your vault is locked":"Set up your vault";
  $("lockDescription").textContent=localStorage.getItem("sv-ready")?
    "Authenticate with Face ID or your iPhone passcode to decrypt your vault.":
    "Create a passkey protected by Face ID. Your vault will be encrypted on this device.";
}
async function setupVault(){
  showLockMessage("");
  try{
    if(!supportsSecurePasskeys()) throw new Error("Open SecureVault from Safari on an HTTPS website. Passkeys and secure encryption are required.");
    if(!PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable ||
       !await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable())
      throw new Error("This browser does not report an available device authenticator.");
    const rpId=location.hostname;
    const salt=randomBytes(32),challenge=randomBytes(32),userId=randomBytes(16);
    const credential=await navigator.credentials.create({publicKey:{
      challenge,rp:{name:"SecureVault",id:rpId},
      user:{id:userId,name:"local-user",displayName:"SecureVault user"},
      pubKeyCredParams:[{type:"public-key",alg:-7},{type:"public-key",alg:-257}],
      authenticatorSelection:{authenticatorAttachment:"platform",residentKey:"preferred",userVerification:"required"},
      timeout:60000,
      extensions:{prf:{eval:{first:salt}}}
    }});
    if(!credential) throw new Error("Passkey setup was cancelled.");
    const ext=credential.getClientExtensionResults();
    if(!ext.prf || ext.prf.enabled!==true) throw new Error("This iPhone/browser did not confirm support for the WebAuthn PRF extension. SecureVault stopped setup rather than using weaker unprotected storage.");
    const assertion=await navigator.credentials.get({publicKey:{
      challenge:randomBytes(32),rpId,allowCredentials:[{type:"public-key",id:credential.rawId}],
      userVerification:"required",timeout:60000,extensions:{prf:{eval:{first:salt}}}
    }});
    const output=assertion?.getClientExtensionResults()?.prf?.results?.first;
    if(!output) throw new Error("Face ID succeeded, but the secure key derivation response was unavailable. Try a supported iOS/Safari version.");
    cryptoKey=await deriveKey(output);
    await dbSet(CRED_KEY,b64u(credential.rawId));
    await dbSet(SALT_KEY,b64u(salt));
    await encryptVault([]);
    localStorage.setItem("sv-ready","1");
    showVault();
  }catch(e){showLockMessage(prettyError(e));}
}
async function unlockVault(){
  showLockMessage("");
  try{
    if(!supportsSecurePasskeys()) throw new Error("SecureVault needs Safari on an HTTPS website.");
    const id=await dbGet(CRED_KEY),saltString=await dbGet(SALT_KEY);
    if(!id||!saltString) throw new Error("Vault setup data is missing on this browser.");
    const salt=fromB64u(saltString);
    const assertion=await navigator.credentials.get({publicKey:{
      challenge:randomBytes(32),rpId:location.hostname,
      allowCredentials:[{type:"public-key",id:fromB64u(id)}],
      userVerification:"required",timeout:60000,extensions:{prf:{eval:{first:salt}}}
    }});
    const output=assertion?.getClientExtensionResults()?.prf?.results?.first;
    if(!output) throw new Error("Your browser did not return the biometric-protected key. No data was decrypted.");
    cryptoKey=await deriveKey(output);
    await decryptVault();
    showVault();
  }catch(e){cryptoKey=null;showLockMessage(prettyError(e));}
}
function prettyError(e){
  if(e.name==="NotAllowedError")return "Authentication was cancelled or not completed. Please try again.";
  if(e.name==="InvalidStateError")return "A passkey already exists for this site. Try unlocking the existing vault.";
  return e.message||"Something went wrong. Please try again.";
}
function renderAccounts(){
  const q=$("searchInput").value.trim().toLowerCase();
  const filtered=accounts.filter(a=>a.title.toLowerCase().includes(q)||a.username.toLowerCase().includes(q));
  $("accountCount").textContent=`${accounts.length} SAVED`;
  $("emptyState").classList.toggle("hidden",accounts.length!==0);
  $("accountList").innerHTML="";
  filtered.forEach(a=>{
    const button=document.createElement("button");button.className="account-card";
    const icon=document.createElement("span");icon.className="account-icon";icon.textContent=/lms|learn|school|college/i.test(a.title)?"▤":"✉";
    const meta=document.createElement("span");meta.className="account-meta";
    const title=document.createElement("b");title.textContent=a.title;
    const user=document.createElement("small");user.textContent=a.username;
    meta.append(title,user);
    const chevron=document.createElement("span");chevron.className="chevron";chevron.textContent="›";
    button.append(icon,meta,chevron);button.addEventListener("click",()=>openDetail(a.id));$("accountList").append(button);
  });
  if(accounts.length && !filtered.length){const p=document.createElement("p");p.className="muted";p.textContent="No matching accounts."; $("accountList").append(p);}
}
async function persistAccounts(){
  try{await encryptVault(accounts);renderAccounts();}catch(e){showToast("Could not encrypt and save changes.");}
}
function openAccountEditor(a=null){
  $("accountForm").reset();$("accountId").value=a?.id||"";
  $("accountDialogTitle").textContent=a?"Edit account":"Add account";
  $("accountTitle").value=a?.title||"";$("accountUsername").value=a?.username||"";
  $("accountPassword").value=a?.password||"";$("accountNotes").value=a?.notes||"";
  $("accountPassword").type="password";$("toggleAccountPassword").textContent="Show";
  $("accountDialog").showModal();
}
function openDetail(id){
  selectedId=id;selectedAccount=accounts.find(a=>a.id===id);if(!selectedAccount)return;
  passwordRevealed=false;
  $("detailTitle").textContent=selectedAccount.title;$("detailUsername").textContent=selectedAccount.username;
  $("detailPassword").textContent="••••••••••••";$("revealPassword").textContent="Show";
  $("detailNotes").textContent=selectedAccount.notes||"";$("detailNotes").classList.toggle("hidden",!selectedAccount.notes);
  $("detailDialog").showModal();
}
function secureRandomPassword(){
  const length=Number($("lengthRange").value);
  const sets=[];
  if($("useUpper").checked)sets.push("ABCDEFGHJKLMNPQRSTUVWXYZ");
  if($("useLower").checked)sets.push("abcdefghijkmnopqrstuvwxyz");
  if($("useNumbers").checked)sets.push("23456789");
  if($("useSymbols").checked)sets.push("!@#$%^&*()-_=+?");
  if(!sets.length){showToast("Choose at least one character type.");return "";}
  const alphabet=sets.join("");
  const bytes=randomBytes(length);
  let out="";
  for(let i=0;i<length;i++)out+=alphabet[bytes[i]%alphabet.length];
  return out;
}
function refreshPassword(){
  const p=secureRandomPassword();if(p){$("generatedPassword").textContent=p;$("copyGenerated").textContent="Copy";}
}
function copyText(text){
  if(!text)return;
  if(navigator.clipboard?.writeText){navigator.clipboard.writeText(text).then(()=>showToast("Copied to clipboard")).catch(()=>showToast("Copy unavailable in this browser."));}
  else showToast("Clipboard access requires HTTPS.");
}
$("setupButton").addEventListener("click",setupVault);
$("unlockButton").addEventListener("click",unlockVault);
$("lockButton").addEventListener("click",showLocked);
$("addAccount").addEventListener("click",()=>openAccountEditor());
$("openGenerator").addEventListener("click",()=>{refreshPassword();$("generatorDialog").showModal();});
$("searchInput").addEventListener("input",renderAccounts);
$("accountForm").addEventListener("submit",async e=>{
  e.preventDefault();
  const id=$("accountId").value||crypto.randomUUID();
  const record={id,title:$("accountTitle").value.trim(),username:$("accountUsername").value.trim(),password:$("accountPassword").value,notes:$("accountNotes").value.trim()};
  if(!record.title||!record.username||!record.password)return;
  const idx=accounts.findIndex(a=>a.id===id);if(idx>=0)accounts[idx]=record;else accounts.unshift(record);
  await persistAccounts();$("accountDialog").close();showToast("Saved in your encrypted vault.");
});
$("toggleAccountPassword").addEventListener("click",()=>{
  const input=$("accountPassword");input.type=input.type==="password"?"text":"password";
  $("toggleAccountPassword").textContent=input.type==="password"?"Show":"Hide";
});
$("lengthRange").addEventListener("input",()=>{$("lengthValue").textContent=$("lengthRange").value;});
$("refreshPassword").addEventListener("click",refreshPassword);
$("copyGenerated").addEventListener("click",()=>copyText($("generatedPassword").textContent));
$("revealPassword").addEventListener("click",()=>{
  passwordRevealed=!passwordRevealed;$("detailPassword").textContent=passwordRevealed?selectedAccount.password:"••••••••••••";
  $("revealPassword").textContent=passwordRevealed?"Hide":"Show";
});
document.querySelectorAll("[data-copy]").forEach(btn=>btn.addEventListener("click",()=>{
  copyText(btn.dataset.copy==="username"?selectedAccount?.username:selectedAccount?.password);
}));
$("editAccount").addEventListener("click",()=>{$("detailDialog").close();openAccountEditor(selectedAccount);});
$("deleteAccount").addEventListener("click",async()=>{
  if(!selectedAccount)return;
  if(confirm(`Delete ${selectedAccount.title} from SecureVault?`)){
    accounts=accounts.filter(a=>a.id!==selectedId);await persistAccounts();$("detailDialog").close();showToast("Account deleted.");
  }
});
document.querySelectorAll("[data-close]").forEach(btn=>btn.addEventListener("click",()=>$(btn.dataset.close).close()));
$("generatorDialog").addEventListener("close",()=>{});
document.addEventListener("visibilitychange",()=>{if(document.hidden&&cryptoKey)showLocked();});
window.addEventListener("pagehide",()=>{cryptoKey=null;});
if("serviceWorker" in navigator && location.protocol==="https:")navigator.serviceWorker.register("./sw.js").catch(()=>{});
if(!supportsSecurePasskeys()){
  $("lockDescription").textContent="For security, open this app from Safari on an HTTPS website on a compatible iPhone. Face ID/passkey PRF support is required.";
}
showLocked();
