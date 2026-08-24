const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const querystring = require('querystring');

const PORT = Number(process.env.PORT || 3000);
const ROOT = __dirname;
const DATA_DIR = path.join(ROOT, 'data');
const MUSIC_DIR = path.join(DATA_DIR, 'music');
const STATE_FILE = path.join(DATA_DIR, 'state.json');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const SESSIONS_FILE = path.join(DATA_DIR, 'sessions.json');
const OAUTH_STATES = new Map();

fs.mkdirSync(MUSIC_DIR, {recursive:true});
if (!fs.existsSync(STATE_FILE)) fs.writeFileSync(STATE_FILE, JSON.stringify({products:null,music:Array(6).fill(null),active:-1,seller:{name:'Keliton Ateliê',whatsapp:''},gmail:{connected:false,email:''}}, null, 2));
if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, '[]');
if (!fs.existsSync(SESSIONS_FILE)) fs.writeFileSync(SESSIONS_FILE, '{}');

function readJson(file,fallback){try{return JSON.parse(fs.readFileSync(file,'utf8'))}catch{return fallback}}
function writeJson(file,value){fs.writeFileSync(file,JSON.stringify(value,null,2))}
function readState(){return readJson(STATE_FILE,{products:null,music:Array(6).fill(null),active:-1,seller:{name:'Keliton Ateliê',whatsapp:''},gmail:{connected:false,email:''}})}
function writeState(s){writeJson(STATE_FILE,s)}
function readUsers(){return readJson(USERS_FILE,[])}
function writeUsers(v){writeJson(USERS_FILE,v)}
function readSessions(){return readJson(SESSIONS_FILE,{})}
function writeSessions(v){writeJson(SESSIONS_FILE,v)}
function mimeFor(ext){return ({'.mp3':'audio/mpeg','.wav':'audio/wav','.ogg':'audio/ogg','.m4a':'audio/mp4','.aac':'audio/aac','.webm':'audio/webm'})[ext.toLowerCase()]||'application/octet-stream'}
function safeName(name){return String(name||'musica').replace(/[^a-zA-Z0-9._-]/g,'_').slice(0,120)}
function send(res,status,type,body,extra={}){res.writeHead(status,{'Content-Type':type,'Cache-Control':'no-store','Access-Control-Allow-Origin':'*',...extra});res.end(body)}
function json(res,status,obj,extra={}){send(res,status,'application/json; charset=utf-8',JSON.stringify(obj),extra)}
function readBody(req){return new Promise((resolve,reject)=>{const chunks=[];req.on('data',c=>chunks.push(c));req.on('end',()=>resolve(Buffer.concat(chunks)));req.on('error',reject)})}
function randomToken(bytes=32){return crypto.randomBytes(bytes).toString('hex')}
function hashToken(token){return crypto.createHash('sha256').update(token).digest('hex')}
function cookieOptions(){return `Path=/; HttpOnly; SameSite=Lax${process.env.COOKIE_SECURE==='true'?'; Secure':''}`}
function setCookie(res,name,value,maxAge=60*60*24*7){res.setHeader('Set-Cookie',`${name}=${encodeURIComponent(value)}; ${cookieOptions()}; Max-Age=${maxAge}`)}
function clearCookie(res,name){res.setHeader('Set-Cookie',`${name}=; ${cookieOptions()}; Max-Age=0`)}
function cookies(req){return Object.fromEntries((req.headers.cookie||'').split(';').filter(Boolean).map(x=>{let i=x.indexOf('=');return [x.slice(0,i).trim(),decodeURIComponent(x.slice(i+1))]}))}
function sessionFromRequest(req){const token=cookies(req).ka_session;if(!token)return null;const sessions=readSessions();const key=hashToken(token),s=sessions[key];if(!s||s.expiresAt<Date.now()){if(s){delete sessions[key];writeSessions(sessions)}return null}return s}
function requireSession(req,res){const s=sessionFromRequest(req);if(!s){json(res,401,{error:'unauthorized'});return null}return s}
function baseUrl(req){return process.env.PUBLIC_BASE_URL || `http://${req.headers.host||`localhost:${PORT}`}`}
function googleConfig(){return {clientId:process.env.GOOGLE_CLIENT_ID,clientSecret:process.env.GOOGLE_CLIENT_SECRET}}
function facebookConfig(){return {appId:process.env.FACEBOOK_APP_ID,appSecret:process.env.FACEBOOK_APP_SECRET}}
function requireConfig(res,ok,names){if(!ok){json(res,503,{error:'oauth_not_configured',message:`Configure ${names.join(' e ')} no ambiente do servidor.`});return false}return true}
function httpsRequest(url,method='GET',body=null,headers={}){return new Promise((resolve,reject)=>{const u=new URL(url);const req=https.request({hostname:u.hostname,path:u.pathname+u.search,method,headers:{...(body?{'Content-Type':'application/x-www-form-urlencoded','Content-Length':Buffer.byteLength(body)}:{}),...headers}},r=>{let data='';r.setEncoding('utf8');r.on('data',c=>data+=c);r.on('end',()=>{try{resolve({status:r.statusCode||500,data:JSON.parse(data)})}catch{resolve({status:r.statusCode||500,data})}})});req.on('error',reject);if(body)req.write(body);req.end()})}
function encrypt(value){const key=Buffer.from(process.env.ENCRYPTION_KEY_HEX||'','hex');if(key.length!==32)throw new Error('ENCRYPTION_KEY_HEX must be 64 hex characters');const iv=crypto.randomBytes(12);const c=crypto.createCipheriv('aes-256-gcm',key,iv);const enc=Buffer.concat([c.update(value,'utf8'),c.final()]);return `${iv.toString('base64url')}.${c.getAuthTag().toString('base64url')}.${enc.toString('base64url')}`}
function decrypt(payload){const key=Buffer.from(process.env.ENCRYPTION_KEY_HEX||'','hex');if(key.length!==32)throw new Error('ENCRYPTION_KEY_HEX must be 64 hex characters');const [ivS,tagS,dataS]=payload.split('.');const d=crypto.createDecipheriv('aes-256-gcm',key,Buffer.from(ivS,'base64url'));d.setAuthTag(Buffer.from(tagS,'base64url'));return Buffer.concat([d.update(Buffer.from(dataS,'base64url')),d.final()]).toString('utf8')}
function createSession(user){const token=randomToken(32),sessions=readSessions();sessions[hashToken(token)]={userId:user.id,email:user.email,name:user.name,role:user.role||'customer',expiresAt:Date.now()+1000*60*60*24*7};writeSessions(sessions);return token}
function upsertUser(provider,profile){const users=readUsers();let u=users.find(x=>x.provider===provider&&x.providerId===profile.id)||users.find(x=>x.email&&profile.email&&x.email.toLowerCase()===profile.email.toLowerCase());if(!u){u={id:randomToken(12),provider,providerId:profile.id,name:profile.name||'Cliente',email:profile.email||'',photo:profile.photo||'',role:(process.env.ADMIN_EMAIL&&profile.email&&profile.email.toLowerCase()===process.env.ADMIN_EMAIL.toLowerCase())?'admin':'customer',createdAt:new Date().toISOString()};users.push(u)}else{u.name=profile.name||u.name;u.email=profile.email||u.email;u.photo=profile.photo||u.photo;u.provider=provider;u.providerId=profile.id;if(process.env.ADMIN_EMAIL&&u.email&&u.email.toLowerCase()===process.env.ADMIN_EMAIL.toLowerCase())u.role='admin'}writeUsers(users);return u}
function beginOAuth(req,res,purpose,provider){const cfg=provider==='google'?googleConfig():facebookConfig();if(!requireConfig(res,provider==='google'?(!!cfg.clientId&&!!cfg.clientSecret):(!!cfg.appId&&!!cfg.appSecret),provider==='google'?['GOOGLE_CLIENT_ID','GOOGLE_CLIENT_SECRET']:['FACEBOOK_APP_ID','FACEBOOK_APP_SECRET']))return;const state=randomToken(24);const session=sessionFromRequest(req);OAUTH_STATES.set(state,{provider,purpose,sessionToken:session?cookies(req).ka_session:null,createdAt:Date.now()});setTimeout(()=>OAUTH_STATES.delete(state),10*60*1000);let redirect=provider==='google'?`${baseUrl(req)}/auth/google/callback`:`${baseUrl(req)}/auth/facebook/callback`;let params=provider==='google'?{client_id:cfg.clientId,redirect_uri:redirect,response_type:'code',scope:purpose==='gmail'?'openid email profile https://www.googleapis.com/auth/gmail.readonly':'openid email profile',access_type:'offline',prompt:purpose==='gmail'?'consent':'select_account',state}:{client_id:cfg.clientId,redirect_uri:redirect,response_type:'code',scope:'email,public_profile',state};res.writeHead(302,{Location:`https://${provider==='google'?'accounts.google.com/o/oauth2/v2/auth':'www.facebook.com/v20.0/dialog/oauth'}?${querystring.stringify(params)}`});res.end()}
async function googleCallback(req,res){const u=new URL(req.url,baseUrl(req)),code=u.searchParams.get('code'),state=u.searchParams.get('state'),meta=OAUTH_STATES.get(state);OAUTH_STATES.delete(state);if(!code||!meta||Date.now()-meta.createdAt>10*60*1000)return send(res,400,'text/plain','OAuth inválido ou expirado.');const cfg=googleConfig(),redirect=`${baseUrl(req)}/auth/google/callback`;const token=await httpsRequest('https://oauth2.googleapis.com/token','POST',querystring.stringify({code,client_id:cfg.clientId,client_secret:cfg.clientSecret,redirect_uri:redirect,grant_type:'authorization_code'}));if(token.status!==200)return send(res,502,'text/plain','Falha ao autenticar com Google.');let access=token.data.access_token,refresh=token.data.refresh_token;
if(meta.purpose==='gmail'){const current=sessionFromRequest(req);if(!current||current.role!=='admin')return send(res,403,'text/plain','Entre no painel administrativo com a conta Google autorizada antes de conectar o Gmail.');if(!refresh){try{const old=readState().gmail?.refreshToken;if(old)refresh=decrypt(old)}catch{}}
if(!refresh)return send(res,400,'text/plain','O Google não forneceu refresh token. Revogue o acesso do app e conecte novamente.');
const me=await httpsRequest('https://openidconnect.googleapis.com/v1/userinfo', 'GET', null, {Authorization:`Bearer ${access}`});if(me.status!==200)return send(res,502,'text/plain','Não foi possível identificar a conta Google.');const s=readState();s.gmail={connected:true,email:me.data.email||'',refreshToken:encrypt(refresh),connectedAt:new Date().toISOString()};writeState(s);return redirectAfter(res,'/?gmail=connected')}
const me=await httpsRequest('https://openidconnect.googleapis.com/v1/userinfo','GET',null,{Authorization:`Bearer ${access}`});if(me.status!==200)return send(res,502,'text/plain','Não foi possível obter o perfil Google.');const user=upsertUser('google',{id:me.data.sub,name:me.data.name,email:me.data.email,photo:me.data.picture});const session=createSession(user);setCookie(res,'ka_session',session);redirectAfter(res,'/?auth=success')}
async function facebookCallback(req,res){const u=new URL(req.url,baseUrl(req)),code=u.searchParams.get('code'),state=u.searchParams.get('state'),meta=OAUTH_STATES.get(state);OAUTH_STATES.delete(state);if(!code||!meta)return send(res,400,'text/plain','OAuth inválido ou expirado.');const cfg=facebookConfig(),redirect=`${baseUrl(req)}/auth/facebook/callback`;const token=await httpsRequest(`https://graph.facebook.com/v20.0/oauth/access_token?${querystring.stringify({client_id:cfg.appId,client_secret:cfg.appSecret,redirect_uri:redirect,code})}`);if(token.status!==200)return send(res,502,'text/plain','Falha ao autenticar com Facebook.');const me=await httpsRequest(`https://graph.facebook.com/me?fields=id,name,email,picture.type(large)&access_token=${encodeURIComponent(token.data.access_token)}`);if(me.status!==200)return send(res,502,'text/plain','Não foi possível obter o perfil Facebook.');const user=upsertUser('facebook',{id:me.data.id,name:me.data.name,email:me.data.email||'',photo:me.data.picture?.data?.url||''});const session=createSession(user);setCookie(res,'ka_session',session);redirectAfter(res,'/?auth=success')}
function redirectAfter(res,target){res.writeHead(302,{Location:target});res.end()}
async function gmailAccessToken(){const s=readState();if(!s.gmail?.refreshToken)throw new Error('gmail_not_connected');const refresh=decrypt(s.gmail.refreshToken),cfg=googleConfig();const token=await httpsRequest('https://oauth2.googleapis.com/token','POST',querystring.stringify({client_id:cfg.clientId,client_secret:cfg.clientSecret,refresh_token:refresh,grant_type:'refresh_token'}));if(token.status!==200)throw new Error('gmail_token_failed');return token.data.access_token}

const server=http.createServer(async (req,res)=>{
  const u=new URL(req.url,`http://${req.headers.host||'localhost'}`);
  if(req.method==='OPTIONS'){res.writeHead(204,{'Access-Control-Allow-Origin':'*','Access-Control-Allow-Headers':'Content-Type,X-Filename','Access-Control-Allow-Methods':'GET,POST,OPTIONS'});return res.end()}
  try{
    if(u.pathname==='/health'&&req.method==='GET')return json(res,200,{ok:true,service:'keliton-atelie',version:'2.1.0'});
    if(u.pathname==='/auth/google'&&req.method==='GET')return beginOAuth(req,res,u.searchParams.get('purpose')==='gmail'?'gmail':'login','google');
    if(u.pathname==='/auth/facebook'&&req.method==='GET')return beginOAuth(req,res,'login','facebook');
    if(u.pathname==='/auth/google/callback'&&req.method==='GET')return googleCallback(req,res);
    if(u.pathname==='/auth/facebook/callback'&&req.method==='GET')return facebookCallback(req,res);
    if(u.pathname==='/api/auth/me'&&req.method==='GET'){const s=requireSession(req,res);if(!s)return;return json(res,200,{authenticated:true,user:readUsers().find(x=>x.id===s.userId)||{id:s.userId,email:s.email,name:s.name,role:s.role}})}
    if(u.pathname==='/api/auth/logout'&&req.method==='POST'){const token=cookies(req).ka_session;if(token){const sessions=readSessions();delete sessions[hashToken(token)];writeSessions(sessions)}clearCookie(res,'ka_session');return json(res,200,{ok:true})}
    if(u.pathname==='/api/gmail/status'&&req.method==='GET'){const admin=requireSession(req,res);if(!admin)return;if(admin.role!=='admin')return json(res,403,{error:'admin_only'});const g=readState().gmail||{};return json(res,200,{connected:!!g.connected,email:g.email||''})}
    if(u.pathname==='/api/admin/session'&&req.method==='GET'){const s=requireSession(req,res);if(!s)return;if(s.role!=='admin')return json(res,403,{error:'admin_only'});return json(res,200,{ok:true,email:s.email,name:s.name})}
    if(u.pathname==='/api/admin/gmail/messages'&&req.method==='GET'){const admin=requireSession(req,res);if(!admin)return;if(admin.role!=='admin')return json(res,403,{error:'admin_only'});const g=readState().gmail||{};if(!g.connected)return json(res,409,{error:'gmail_not_connected'});const access=await gmailAccessToken();const list=await httpsRequest(`https://gmail.googleapis.com/gmail/v1/users/me/messages?maxResults=20&labelIds=INBOX`,'GET',null,{Authorization:`Bearer ${access}`});if(list.status!==200)return json(res,502,{error:'gmail_list_failed',detail:list.data});const msgs=[];for(const m of (list.data.messages||[]).slice(0,20)){const one=await httpsRequest(`https://gmail.googleapis.com/gmail/v1/users/me/messages/${m.id}?format=metadata&metadataHeaders=From&metadataHeaders=To&metadataHeaders=Subject&metadataHeaders=Date`,'GET',null,{Authorization:`Bearer ${access}`});if(one.status===200){const headers=Object.fromEntries((one.data.payload?.headers||[]).map(h=>[h.name.toLowerCase(),h.value]));msgs.push({id:m.id,threadId:m.threadId,from:headers.from||'',to:headers.to||'',subject:headers.subject||'(sem assunto)',date:headers.date||'',snippet:one.data.snippet||''})}}return json(res,200,{email:g.email,messages:msgs})}
    if(u.pathname==='/api/state'&&req.method==='GET'){const s=readState();if(s.gmail&&s.gmail.refreshToken){s.gmail={connected:!!s.gmail.connected,email:s.gmail.email||'',connectedAt:s.gmail.connectedAt||''}}return json(res,200,s)}
    if(u.pathname==='/api/seller'&&req.method==='GET') return json(res,200,readState().seller||{name:'Keliton Ateliê',whatsapp:''});
    if(u.pathname==='/api/seller'&&req.method==='POST'){const body=JSON.parse((await readBody(req)).toString('utf8'));if(!body||typeof body.whatsapp!=='string')return json(res,400,{error:'seller'});const s=readState();s.seller={name:String(body.name||'Keliton Ateliê'),whatsapp:String(body.whatsapp)};writeState(s);return json(res,200,{ok:true,seller:s.seller})}
    if(u.pathname==='/api/products'&&req.method==='POST'){const body=await readBody(req);const products=JSON.parse(body.toString('utf8'));if(!Array.isArray(products))return json(res,400,{error:'products must be an array'});const s=readState();s.products=products;writeState(s);return json(res,200,{ok:true})}
    if(u.pathname.startsWith('/api/music/')&&req.method==='POST'){
      const index=Number(u.pathname.split('/').pop()); if(!Number.isInteger(index)||index<0||index>5)return json(res,400,{error:'slot'});
      const body=await readBody(req); if(!body.length)return json(res,400,{error:'empty'});
      const name=safeName(decodeURIComponent(req.headers['x-filename']||`musica_${index}`));
      const ext=path.extname(name)||'.bin'; const stored=`slot_${index}_${crypto.randomBytes(5).toString('hex')}${ext}`;
      fs.writeFileSync(path.join(MUSIC_DIR,stored),body); const s=readState(); s.music[index]={name,url:`/music/${stored}`,remote:true}; writeState(s); return json(res,200,{ok:true,url:`/music/${stored}`,name});
    }
    if(u.pathname==='/api/music/active'&&req.method==='POST'){const b=JSON.parse((await readBody(req)).toString('utf8'));const s=readState();s.active=Number.isInteger(b.active)?b.active:-1;writeState(s);return json(res,200,{ok:true})}
    if(u.pathname.startsWith('/music/')&&req.method==='GET'){const file=path.basename(u.pathname.slice('/music/'.length));const full=path.join(MUSIC_DIR,file);if(!fs.existsSync(full))return send(res,404,'text/plain','Not found');res.writeHead(200,{'Content-Type':mimeFor(path.extname(file)),'Cache-Control':'public,max-age=31536000'});return fs.createReadStream(full).pipe(res)}
    let file=u.pathname==='/'?'/index.html':u.pathname; if(file.includes('..'))return send(res,400,'text/plain','Bad request');const full=path.join(ROOT,file);if(fs.existsSync(full)&&fs.statSync(full).isFile()){const ext=path.extname(full);const type=ext==='.html'?'text/html; charset=utf-8':ext==='.jpg'?'image/jpeg':ext==='.js'?'text/javascript; charset=utf-8':ext==='.png'?'image/png':'application/octet-stream';return send(res,200,type,fs.readFileSync(full))}
    send(res,404,'text/plain','Not found');
  }catch(e){console.error(e);json(res,500,{error:'server error',detail:process.env.NODE_ENV==='development'?String(e.message):undefined})}
});
server.listen(PORT,'0.0.0.0',()=>console.log(`Keliton Atelie: http://localhost:${PORT}`));
