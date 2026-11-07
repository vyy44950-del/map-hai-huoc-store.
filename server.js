import express from 'express';
import helmet from 'helmet';
import Database from 'better-sqlite3';
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname=path.dirname(fileURLToPath(import.meta.url));
const app=express();
app.use(helmet({contentSecurityPolicy:false}));
app.use(express.json({limit:'30kb'}));
app.use(express.static(path.join(__dirname,'public')));
app.use((req,res,next)=>{ // minimal cookie parser
 req.cookies=Object.fromEntries((req.headers.cookie||'').split(';').filter(Boolean).map(v=>{const i=v.indexOf('=');return [v.slice(0,i).trim(),v.slice(i+1).trim()]}));next();
});
const db=new Database(path.join(__dirname,'store.sqlite'));
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, balance INTEGER NOT NULL DEFAULT 0, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY,user_id INTEGER NOT NULL,expires_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS topups(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL,amount INTEGER NOT NULL,memo TEXT UNIQUE NOT NULL,status TEXT NOT NULL DEFAULT 'PENDING',created_at TEXT DEFAULT CURRENT_TIMESTAMP,reviewed_at TEXT);
CREATE TABLE IF NOT EXISTS card_topups(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL,provider TEXT NOT NULL,amount INTEGER NOT NULL,serial TEXT NOT NULL,card_code TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'PENDING',created_at TEXT DEFAULT CURRENT_TIMESTAMP,reviewed_at TEXT);
CREATE UNIQUE INDEX IF NOT EXISTS card_topups_serial_once ON card_topups(provider,serial);
CREATE TABLE IF NOT EXISTS ledger(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL,kind TEXT NOT NULL,amount INTEGER NOT NULL,ref TEXT UNIQUE NOT NULL,note TEXT,created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS orders(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL,product_id TEXT NOT NULL,product_name TEXT NOT NULL,amount INTEGER NOT NULL,created_at TEXT DEFAULT CURRENT_TIMESTAMP);
`);
const products={aimlock:{name:'AIMLOCK',price:200000},aimbody:{name:'AIMBODY',price:250000},vip:{name:'MENU VIP',price:450000}};
const ADMIN_USER=process.env.ADMIN_USERNAME||'';
const ADMIN_PASS=process.env.ADMIN_PASSWORD||'';
const COOKIE='mahh_session';
const hash=s=>crypto.createHash('sha256').update(s).digest('hex');
const newToken=()=>crypto.randomBytes(32).toString('hex');
function setSession(res,token){res.cookie(COOKIE,token,{httpOnly:true,sameSite:'lax',secure:process.env.NODE_ENV==='production',maxAge:7*86400000,path:'/'});}
function auth(req,res,next){
 const token=req.cookies?.[COOKIE] || (req.headers.cookie||'').split(';').map(x=>x.trim()).find(x=>x.startsWith(COOKIE+'='))?.slice(COOKIE.length+1);
 if(!token)return res.status(401).json({error:'Vui lòng đăng nhập.'});
 const row=db.prepare('SELECT u.id,u.username,u.balance,s.expires_at FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=?').get(hash(decodeURIComponent(token)));
 if(!row||row.expires_at<Date.now())return res.status(401).json({error:'Phiên đăng nhập hết hạn.'});
 req.user=row;next();
}
function admin(req,res,next){
 const h=req.headers.authorization||'';
 const encoded=Buffer.from(`${ADMIN_USER}:${ADMIN_PASS}`).toString('base64');
 if(!ADMIN_USER||!ADMIN_PASS||h!==`Basic ${encoded}`)return res.set('WWW-Authenticate','Basic realm="MHH Admin"').status(401).send('Cần đăng nhập quản trị');
 next();
}
app.get('/api/me',(req,res)=>{const token=req.cookies[COOKIE];if(!token)return res.json({user:null});const row=db.prepare('SELECT u.id,u.username,u.balance FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?').get(hash(decodeURIComponent(token)),Date.now());res.json({user:row||null});});
app.post('/api/register',(req,res)=>{
 const username=String(req.body?.username||'').trim().toLowerCase(),password=String(req.body?.password||'');
 if(!/^[a-z0-9_]{4,20}$/.test(username))return res.status(400).json({error:'Tên đăng nhập cần 4–20 ký tự, chỉ gồm chữ thường, số và _.'});
 if(password.length<8||password.length>100)return res.status(400).json({error:'Mật khẩu cần ít nhất 8 ký tự.'});
 const salt=crypto.randomBytes(16).toString('hex');
 const password_hash=salt+':'+crypto.scryptSync(password,salt,64).toString('hex');
 try{const info=db.prepare('INSERT INTO users(username,password_hash) VALUES(?,?)').run(username,password_hash);const token=newToken();db.prepare('INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)').run(hash(token),info.lastInsertRowid,Date.now()+7*86400000);setSession(res,token);res.json({ok:true,username});}
 catch(e){res.status(409).json({error:'Tên đăng nhập đã tồn tại.'});}
});
app.post('/api/login',(req,res)=>{
 const username=String(req.body?.username||'').trim().toLowerCase(),password=String(req.body?.password||'');
 const u=db.prepare('SELECT * FROM users WHERE username=?').get(username);
 if(!u)return res.status(401).json({error:'Sai tên đăng nhập hoặc mật khẩu.'});
 const [salt,stored]=u.password_hash.split(':');const actual=crypto.scryptSync(password,salt,64);
 if(!crypto.timingSafeEqual(actual,Buffer.from(stored,'hex')))return res.status(401).json({error:'Sai tên đăng nhập hoặc mật khẩu.'});
 const token=newToken();db.prepare('INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)').run(hash(token),u.id,Date.now()+7*86400000);setSession(res,token);res.json({ok:true,username:u.username});
});
app.post('/api/logout',(req,res)=>{const token=req.cookies[COOKIE];if(token)db.prepare('DELETE FROM sessions WHERE token_hash=?').run(hash(decodeURIComponent(token)));res.clearCookie(COOKIE,{path:'/'});res.json({ok:true});});
app.get('/api/wallet',auth,(req,res)=>{
 const topups=db.prepare('SELECT id,amount,memo,status,created_at FROM topups WHERE user_id=? ORDER BY id DESC LIMIT 30').all(req.user.id);
 const ledger=db.prepare('SELECT kind,amount,ref,note,created_at FROM ledger WHERE user_id=? ORDER BY id DESC LIMIT 30').all(req.user.id);
 const cardTopups=db.prepare('SELECT id,provider,amount,status,created_at FROM card_topups WHERE user_id=? ORDER BY id DESC LIMIT 20').all(req.user.id);
 res.json({balance:req.user.balance,topups,ledger,cardTopups});
});
app.post('/api/card-topups',auth,(req,res)=>{
 const providers=['VIETTEL','VINAPHONE','MOBIFONE','VIETNAMOBILE','ZING'];
 const amounts=[10000,20000,50000,100000,200000,500000];
 const provider=String(req.body?.provider||'').trim().toUpperCase();
 const amount=Number(req.body?.amount);
 const serial=String(req.body?.serial||'').trim().toUpperCase();
 const cardCode=String(req.body?.cardCode||'').trim().toUpperCase();
 if(!providers.includes(provider))return res.status(400).json({error:'Nhà mạng/thẻ không hợp lệ.'});
 if(!amounts.includes(amount))return res.status(400).json({error:'Mệnh giá thẻ không hợp lệ.'});
 if(!/^[A-Z0-9]{6,30}$/.test(serial)||!/^[A-Z0-9]{6,30}$/.test(cardCode))return res.status(400).json({error:'Serial và mã thẻ phải gồm 6–30 ký tự chữ hoặc số.'});
 try{const info=db.prepare('INSERT INTO card_topups(user_id,provider,amount,serial,card_code) VALUES(?,?,?,?,?)').run(req.user.id,provider,amount,serial,cardCode);res.json({ok:true,id:info.lastInsertRowid,message:'Đã gửi thẻ. Vui lòng chờ quản trị viên kiểm tra và duyệt.'});}
 catch(e){if(String(e.message).includes('UNIQUE'))return res.status(409).json({error:'Serial thẻ này đã được gửi trước đó.'});throw e;}
});
app.get('/api/card-topups',auth,(req,res)=>{const rows=db.prepare('SELECT id,provider,amount,status,created_at,reviewed_at FROM card_topups WHERE user_id=? ORDER BY id DESC LIMIT 30').all(req.user.id);res.json(rows);});
app.post('/api/topups',auth,(req,res)=>{
 const amount=Number(req.body?.amount);
 if(!Number.isSafeInteger(amount)||amount<10000||amount>5000000||amount%1000!==0)return res.status(400).json({error:'Số tiền nạp từ 10.000đ đến 5.000.000đ, bội số 1.000đ.'});
 const memo='MHH'+crypto.randomBytes(4).toString('hex').toUpperCase();
 const info=db.prepare('INSERT INTO topups(user_id,amount,memo) VALUES(?,?,?)').run(req.user.id,amount,memo);
 res.json({ok:true,id:info.lastInsertRowid,amount,memo,bank:{name:'MB Bank',account:process.env.BANK_ACCOUNT||'0348934705',owner:process.env.BANK_OWNER||'TRAN QUANG QUOC'}});
});
const approve=db.transaction((id)=>{
 const t=db.prepare("SELECT * FROM topups WHERE id=? AND status='PENDING'").get(id);
 if(!t)throw new Error('Yêu cầu không tồn tại hoặc đã được xử lý.');
 db.prepare("UPDATE topups SET status='APPROVED',reviewed_at=CURRENT_TIMESTAMP WHERE id=?").run(id);
 db.prepare('UPDATE users SET balance=balance+? WHERE id=?').run(t.amount,t.user_id);
 db.prepare("INSERT INTO ledger(user_id,kind,amount,ref,note) VALUES(?,?,?,?,?)").run(t.user_id,'TOPUP',t.amount,'TOPUP-'+t.id,'Nạp tiền được quản trị viên duyệt');
});
app.get('/api/admin/topups',admin,(req,res)=>res.json(db.prepare(`SELECT t.*,u.username FROM topups t JOIN users u ON u.id=t.user_id ORDER BY t.id DESC LIMIT 200`).all()));
app.post('/api/admin/topups/:id/approve',admin,(req,res)=>{try{approve(Number(req.params.id));res.json({ok:true});}catch(e){res.status(409).json({error:e.message});}});
app.post('/api/admin/topups/:id/reject',admin,(req,res)=>{const r=db.prepare("UPDATE topups SET status='REJECTED',reviewed_at=CURRENT_TIMESTAMP WHERE id=? AND status='PENDING'").run(Number(req.params.id));if(!r.changes)return res.status(409).json({error:'Yêu cầu không còn chờ duyệt.'});res.json({ok:true});});
app.get('/api/admin/card-topups',admin,(req,res)=>res.json(db.prepare(`SELECT c.*,u.username FROM card_topups c JOIN users u ON u.id=c.user_id ORDER BY c.id DESC LIMIT 300`).all()));
const approveCard=db.transaction((id)=>{const c=db.prepare("SELECT * FROM card_topups WHERE id=? AND status='PENDING'").get(id);if(!c)throw new Error('Yêu cầu không tồn tại hoặc đã được xử lý.');db.prepare("UPDATE card_topups SET status='APPROVED',reviewed_at=CURRENT_TIMESTAMP WHERE id=?").run(id);db.prepare('UPDATE users SET balance=balance+? WHERE id=?').run(c.amount,c.user_id);db.prepare('INSERT INTO ledger(user_id,kind,amount,ref,note) VALUES(?,?,?,?,?)').run(c.user_id,'CARD_TOPUP',c.amount,'CARD-'+c.id,'Nạp thẻ '+c.provider+' được quản trị viên duyệt');});
app.post('/api/admin/card-topups/:id/approve',admin,(req,res)=>{try{approveCard(Number(req.params.id));res.json({ok:true});}catch(e){res.status(409).json({error:e.message});}});
app.post('/api/admin/card-topups/:id/reject',admin,(req,res)=>{const r=db.prepare("UPDATE card_topups SET status='REJECTED',reviewed_at=CURRENT_TIMESTAMP WHERE id=? AND status='PENDING'").run(Number(req.params.id));if(!r.changes)return res.status(409).json({error:'Yêu cầu không còn chờ duyệt.'});res.json({ok:true});});
app.post('/api/buy',auth,(req,res)=>{
 const p=products[req.body?.productId];if(!p)return res.status(400).json({error:'Sản phẩm không hợp lệ.'});
 const run=db.transaction(()=>{const u=db.prepare('SELECT balance FROM users WHERE id=?').get(req.user.id);if(u.balance<p.price)throw new Error('Số dư không đủ. Vui lòng nạp tiền.');const info=db.prepare('INSERT INTO orders(user_id,product_id,product_name,amount) VALUES(?,?,?,?)').run(req.user.id,req.body.productId,p.name,p.price);db.prepare('UPDATE users SET balance=balance-? WHERE id=?').run(p.price,req.user.id);db.prepare("INSERT INTO ledger(user_id,kind,amount,ref,note) VALUES(?,?,?,?,?)").run(req.user.id,'PURCHASE',-p.price,'ORDER-'+info.lastInsertRowid,'Mua '+p.name);return info.lastInsertRowid;});
 try{const id=run();res.json({ok:true,orderId:id,message:'Đã ghi nhận đơn hàng. Cửa hàng cần thực hiện giao hàng riêng.'});}catch(e){res.status(400).json({error:e.message});}
});
app.get('/api/health',(_req,res)=>res.json({ok:true}));
app.listen(Number(process.env.PORT||3000),()=>console.log('MHH Store running'));
