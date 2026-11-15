// Шифрование/расшифровка data.enc.js (PBKDF2-SHA256 + AES-256-GCM), совместимо с WebCrypto в браузере.
// node tools/enc.js enc data.json PIN > data.enc.js   |   node tools/enc.js dec data.enc.js PIN > data.json
const c=require('crypto'),fs=require('fs');
const [,,mode,file,pin]=process.argv;const IT=400000;
if(mode==='enc'){
  const salt=c.randomBytes(16),iv=c.randomBytes(12);
  const key=c.pbkdf2Sync(pin,salt,IT,32,'sha256');
  const ci=c.createCipheriv('aes-256-gcm',key,iv);
  const ct=Buffer.concat([ci.update(fs.readFileSync(file)),ci.final(),ci.getAuthTag()]);
  process.stdout.write('window.FLIP_ENC='+JSON.stringify({v:1,it:IT,s:salt.toString('base64'),i:iv.toString('base64'),c:ct.toString('base64')})+';\n');
}else{
  const t=fs.readFileSync(file,'utf8');const E=JSON.parse(t.slice(t.indexOf('{'),t.lastIndexOf('}')+1));
  const key=c.pbkdf2Sync(pin,Buffer.from(E.s,'base64'),E.it,32,'sha256');
  const ct=Buffer.from(E.c,'base64');const de=c.createDecipheriv('aes-256-gcm',key,Buffer.from(E.i,'base64'));
  de.setAuthTag(ct.subarray(ct.length-16));
  process.stdout.write(Buffer.concat([de.update(ct.subarray(0,ct.length-16)),de.final()]));
}
