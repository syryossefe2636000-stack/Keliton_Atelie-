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

const WEBAUTHN_FILE = path.join(DATA_DIR, 'webauthn.json');
const WEBAUTHN_CHALLENGES_FILE = path.join(DATA_DIR, 'webauthn_challenges.json');
if (!fs.existsSync(WEBAUTHN_FILE)) fs.writeFileSync(WEBAUTHN_FILE, '[]');
if (!fs.existsSync(WEBAUTHN_CHALLENGES_FILE)) fs.writeFileSync(WEBAUTHN_CHALLENGES_FILE, '{}');
function readWebAuthn(){return readJson(WEBAUTHN_FILE,[])}
function writeWebAuthn(v){writeJson(WEBAUTHN_FILE,v)}
function readWebAuthnChallenges(){return readJson(WEBAUTHN_CHALLENGES_FILE,{})}
function writeWebAuthnChallenges(v){writeJson(WEBAUTHN_CHALLENGES_FILE,v)}
function b64urlBuf(v){return Buffer.from(v).toString('base64url')}
function bufB64url(v){return Buffer.from(String(v||''),'base64url')}
function requestOrigin(req){
  const proto=String(req.headers['x-forwarded-proto']||'').split(',')[0].trim() || (process.env.NODE_ENV==='production'?'https':(req.socket.encrypted?'https':'http'));
  const host=req.headers['x-forwarded-host']||req.headers.host||`localhost:${PORT}`;
  return `${proto}://${host}`;
}
function rpIdFor(req){return new URL(process.env.PUBLIC_BASE_URL||requestOrigin(req)).hostname}
function webauthnChallenge(sessionToken){return hashToken(sessionToken||'anonymous')}
function setWebAuthnChallenge(req,kind,value){const token=cookies(req).ka_session; if(!token)throw new Error('unauthorized');const all=readWebAuthnChallenges();all[webauthnChallenge(token)]={kind,challenge:value,expiresAt:Date.now()+5*60*1000};writeWebAuthnChallenges(all)}
function takeWebAuthnChallenge(req,kind){const token=cookies(req).ka_session;if(!token)return null;const all=readWebAuthnChallenges(),key=webauthnChallenge(token),x=all[key];if(!x||x.kind!==kind||x.expiresAt<Date.now()){if(x){delete all[key];writeWebAuthnChallenges(all)}return null}delete all[key];writeWebAuthnChallenges(all);return x.challenge}
function sha256(v){return crypto.createHash('sha256').update(v).digest()}
function derLen(n){if(n<128)return Buffer.from([n]);const a=[];while(n){a.unshift(n&255);n>>=8}return Buffer.from([0x80|a.length,...a])}
function der(type,body){return Buffer.concat([Buffer.from([type]),derLen(body.length),body])}
function derInt(buf){let b=Buffer.from(buf);while(b.length>1&&b[0]===0)b=b.slice(1);if(b[0]&0x80)b=Buffer.concat([Buffer.from([0]),b]);return der(0x02,b)}
function coseToSpki(cose){
  const alg=cose.get(3), kty=cose.get(1);
  if(kty===2 && alg===-7){
    const x=Buffer.from(cose.get(-2)), y=Buffer.from(cose.get(-3));
    if(x.length!==32||y.length!==32)throw new Error('invalid ec key');
    const algId=Buffer.from('301306072a8648ce3d020106082a8648ce3d030107','hex');
    return der(0x30,Buffer.concat([algId,der(0x03,Buffer.concat([Buffer.from([0]),Buffer.from([4]),x,y]))]));
  }
  if(kty===3 && alg===-257){
    const n=Buffer.from(cose.get(-1)), e=Buffer.from(cose.get(-2));
    const rsa=der(0x30,Buffer.concat([derInt(n),derInt(e)]));
    const algId=Buffer.from('300d06092a864886f70d0101010500','hex');
    return der(0x30,Buffer.concat([algId,der(0x03,Buffer.concat([Buffer.from([0]),rsa]))]));
  }
  throw new Error(`unsupported cose key kty=${kty} alg=${alg}`);
}
function cborDecode(buf){
  let o=0;
  function readLen(ai){
    if(ai<24)return ai;
    if(ai===24)return buf[o++];
    if(ai===25){const n=buf.readUInt16BE(o);o+=2;return n}
    if(ai===26){const n=buf.readUInt32BE(o);o+=4;return n}
    if(ai===27){const n=Number(buf.readBigUInt64BE(o));o+=8;return n}
    if(ai===31)throw new Error('indefinite cbor unsupported');
    throw new Error('bad cbor length');
  }
  function val(){
    const ib=buf[o++], mt=ib>>5, ai=ib&31;
    if(mt===0)return readLen(ai);
    if(mt===1)return -1-readLen(ai);
    if(mt===2){const n=readLen(ai),v=buf.slice(o,o+n);o+=n;return v}
    if(mt===3){const n=readLen(ai),v=buf.slice(o,o+n).toString('utf8');o+=n;return v}
    if(mt===4){const n=readLen(ai),a=[];for(let i=0;i<n;i++)a.push(val());return a}
    if(mt===5){const n=readLen(ai),m=new Map();for(let i=0;i<n;i++)m.set(val(),val());return m}
    if(mt===7){if(ai===20)return false;if(ai===21)return true;if(ai===22)return null;if(ai===23)return undefined;if(ai===25){const h=buf.readUInt16BE(o);o+=2;return h}if(ai===26){const f=buf.readFloatBE(o);o+=4;return f}if(ai===27){const f=buf.readDoubleBE(o);o+=8;return f}}
    throw new Error('unsupported cbor type');
  }
  return val();
}
function parseAttestationObject(attestationObject){
  const obj=cborDecode(attestationObject),auth=Buffer.from(obj.get('authData'));let p=0;
  if(auth.length<37)throw new Error('invalid authData');
  const rpIdHash=auth.slice(p,p+32);p+=32;const flags=auth[p++];const signCount=auth.readUInt32BE(p);p+=4;
  if(!(flags&0x40))throw new Error('credential data missing');
  p+=16;const credLen=auth.readUInt16BE(p);p+=2;const credentialId=auth.slice(p,p+credLen);p+=credLen;
  const cose=cborDecode(auth.slice(p));
  return {rpIdHash,flags,signCount,credentialId,spki:coseToSpki(cose),alg:cose.get(3)};
}
function parseAuthenticatorData(data){const b=Buffer.from(data);if(b.length<37)throw new Error('invalid authenticatorData');return {rpIdHash:b.slice(0,32),flags:b[32],signCount:b.readUInt32BE(33)}}
function parseClientData(data){try{return JSON.parse(Buffer.from(data).toString('utf8'))}catch{throw new Error('invalid clientDataJSON')}}
function expectedOrigin(req){return process.env.PUBLIC_BASE_URL ? new URL(process.env.PUBLIC_BASE_URL).origin : requestOrigin(req)}
function verifyClientData(data,expectedType,challenge,origin){const c=parseClientData(data);if(c.type!==expectedType)throw new Error('invalid clientData type');if(c.challenge!==challenge)throw new Error('challenge mismatch');if(c.origin!==origin)throw new Error('origin mismatch');return c}
function adminCredentials(){return readWebAuthn()}
function adminCredentialLimit(){return 2}
function ensureAdminSession(req,res){const s=requireSession(req,res);if(!s)return null;if(s.role!=='admin'){json(res,403,{error:'admin_only'});return null}return s}
function hashAdminPasswordServer(value){return crypto.createHash('sha256').update(String(value)).digest('hex')}
function serverAdminPasswordHash(){return process.env.ADMIN_PASSWORD_HASH||'ff30ccef8c82e013a5da02170ac6811e5da71574266b4563817b3717c9c8f46b'}

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
    if(u.pathname==='/health'&&req.method==='GET')return json(res,200,{ok:true,service:'keliton-atelie',version:'2.2.0'});
    if(u.pathname==='/auth/google'&&req.method==='GET')return beginOAuth(req,res,u.searchParams.get('purpose')==='gmail'?'gmail':'login','google');
    if(u.pathname==='/auth/facebook'&&req.method==='GET')return beginOAuth(req,res,'login','facebook');
    if(u.pathname==='/auth/google/callback'&&req.method==='GET')return googleCallback(req,res);
    if(u.pathname==='/auth/facebook/callback'&&req.method==='GET')return facebookCallback(req,res);
    if(u.pathname==='/api/auth/me'&&req.method==='GET'){const s=requireSession(req,res);if(!s)return;return json(res,200,{authenticated:true,user:readUsers().find(x=>x.id===s.userId)||{id:s.userId,email:s.email,name:s.name,role:s.role}})}
    if(u.pathname==='/api/auth/logout'&&req.method==='POST'){const token=cookies(req).ka_session;if(token){const sessions=readSessions();delete sessions[hashToken(token)];writeSessions(sessions)}clearCookie(res,'ka_session');return json(res,200,{ok:true})}
    if(u.pathname==='/api/gmail/status'&&req.method==='GET'){const admin=requireSession(req,res);if(!admin)return;if(admin.role!=='admin')return json(res,403,{error:'admin_only'});const g=readState().gmail||{};return json(res,200,{connected:!!g.connected,email:g.email||''})}
    if(u.pathname==='/api/admin/session'&&req.method==='GET'){const s=requireSession(req,res);if(!s)return;if(s.role!=='admin')return json(res,403,{error:'admin_only'});return json(res,200,{ok:true,email:s.email,name:s.name})}

    if(u.pathname==='/api/admin/unlock'&&req.method==='POST'){
      const body=JSON.parse((await readBody(req)).toString('utf8')||'{}');
      if(hashAdminPasswordServer(body.password||'')!==serverAdminPasswordHash())return json(res,401,{error:'invalid_password'});
      const email=process.env.ADMIN_EMAIL||'admin@keliton.local';
      const users=readUsers();let user=users.find(x=>x.email&&x.email.toLowerCase()===email.toLowerCase());
      if(!user){user={id:'admin-local',provider:'local',providerId:'admin-local',name:'Keliton Ateliê',email,photo:'',role:'admin',createdAt:new Date().toISOString()};users.push(user);writeUsers(users)}else if(user.role!=='admin'){user.role='admin';writeUsers(users)}
      const token=createSession(user);setCookie(res,'ka_session',token);return json(res,200,{ok:true,email:user.email,name:user.name,role:'admin'});
    }
    if(u.pathname==='/api/admin/webauthn/list'&&req.method==='GET'){
      const admin=ensureAdminSession(req,res);if(!admin)return;
      return json(res,200,{credentials:adminCredentials().filter(x=>x.userId===admin.userId).map(x=>({id:x.credentialId,name:x.name,createdAt:x.createdAt}))});
    }
    if(u.pathname==='/api/admin/webauthn/register/options'&&req.method==='POST'){
      const admin=ensureAdminSession(req,res);if(!admin)return;
      const creds=adminCredentials().filter(x=>x.userId===admin.userId);if(creds.length>=adminCredentialLimit())return json(res,409,{error:'limit_reached'});
      const challenge=b64urlBuf(crypto.randomBytes(32));setWebAuthnChallenge(req,'register',challenge);
      const userId=crypto.randomBytes(16);
      return json(res,200,{challenge,rp:{name:'Keliton Ateliê',id:rpIdFor(req)},user:{id:b64urlBuf(userId),name:admin.email||'administrador',displayName:admin.name||'Administrador'},pubKeyCredParams:[{type:'public-key',alg:-7},{type:'public-key',alg:-257}],authenticatorSelection:{residentKey:'preferred',userVerification:'required'},timeout:60000,attestation:'none'});
    }
    if(u.pathname==='/api/admin/webauthn/register/verify'&&req.method==='POST'){
      const admin=ensureAdminSession(req,res);if(!admin)return;
      const challenge=takeWebAuthnChallenge(req,'register');if(!challenge)return json(res,400,{error:'challenge_expired'});
      const body=JSON.parse((await readBody(req)).toString('utf8')||'{}');
      try{
        const clientData=bufB64url(body.response?.clientDataJSON);const attObj=bufB64url(body.response?.attestationObject);
        verifyClientData(clientData,'webauthn.create',challenge,expectedOrigin(req));
        const parsed=parseAttestationObject(attObj);if(!parsed.rpIdHash.equals(sha256(rpIdFor(req))))throw new Error('rpId mismatch');if(!(parsed.flags&0x01)||!(parsed.flags&0x04))throw new Error('user verification required');
        const creds=adminCredentials();if(creds.some(x=>x.credentialId===b64urlBuf(parsed.credentialId)))throw new Error('credential already registered');
        creds.push({userId:admin.userId,credentialId:b64urlBuf(parsed.credentialId),publicKeySpki:b64urlBuf(parsed.spki),alg:parsed.alg,signCount:parsed.signCount,name:String(body.name||'Administrador').slice(0,80),createdAt:new Date().toISOString()});writeWebAuthn(creds);
        return json(res,200,{ok:true,credentialId:b64urlBuf(parsed.credentialId),name:String(body.name||'Administrador').slice(0,80)});
      }catch(e){return json(res,400,{error:'registration_failed',message:e.message})}
    }
    if(u.pathname==='/api/admin/webauthn/auth/options'&&req.method==='POST'){
      const challenge=b64urlBuf(crypto.randomBytes(32)),flowId=randomToken(18);const all=readWebAuthnChallenges();all['auth:'+flowId]={kind:'auth',challenge,expiresAt:Date.now()+5*60*1000};writeWebAuthnChallenges(all);
      const creds=adminCredentials();
      return json(res,200,{flowId,challenge,rpId:rpIdFor(req),allowCredentials:creds.map(x=>({type:'public-key',id:x.credentialId})),userVerification:'required',timeout:60000});
    }
    if(u.pathname==='/api/admin/webauthn/auth/verify'&&req.method==='POST'){
      const body=JSON.parse((await readBody(req)).toString('utf8')||'{}');const flowId=String(body.flowId||'');const all=readWebAuthnChallenges(),entry=all['auth:'+flowId];if(!entry||entry.expiresAt<Date.now()){if(entry){delete all['auth:'+flowId];writeWebAuthnChallenges(all)}return json(res,400,{error:'challenge_expired'})}delete all['auth:'+flowId];writeWebAuthnChallenges(all);const challenge=entry.challenge;
      try{
        const credId=String(body.rawId||body.id||'');const stored=adminCredentials().find(x=>x.credentialId===credId);if(!stored)return json(res,401,{error:'unknown_credential'});
        const clientData=bufB64url(body.response?.clientDataJSON),authData=bufB64url(body.response?.authenticatorData),signature=bufB64url(body.response?.signature);
        verifyClientData(clientData,'webauthn.get',challenge,expectedOrigin(req));
        const parsed=parseAuthenticatorData(authData);if(!parsed.rpIdHash.equals(sha256(rpIdFor(req))))throw new Error('rpId mismatch');if(!(parsed.flags&0x01)||!(parsed.flags&0x04))throw new Error('user verification required');
        const verifyData=Buffer.concat([authData,sha256(clientData)]);const ok=crypto.verify('sha256',verifyData,{key:Buffer.from(stored.publicKeySpki,'base64url'),dsaEncoding:'der'},signature);if(!ok)throw new Error('invalid signature');
        if(stored.signCount!==0&&parsed.signCount!==0&&parsed.signCount<=stored.signCount)throw new Error('sign counter invalid');stored.signCount=parsed.signCount;writeWebAuthn(adminCredentials());
        const users=readUsers();const user=users.find(x=>x.id===stored.userId);if(!user||user.role!=='admin')return json(res,403,{error:'admin_only'});const token=createSession(user);setCookie(res,'ka_session',token);return json(res,200,{ok:true,name:stored.name,email:user.email});
      }catch(e){return json(res,401,{error:'authentication_failed',message:e.message})}
    }
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
