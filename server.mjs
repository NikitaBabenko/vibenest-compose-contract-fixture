import http from 'node:http';
import net from 'node:net';
import fs from 'node:fs';
import crypto from 'node:crypto';
fs.mkdirSync('/app/data',{recursive:true});
const path='/app/data/state.json';
const state=fs.existsSync(path)?JSON.parse(fs.readFileSync(path)): {marker:crypto.randomUUID(),boots:0};
state.boots++;
fs.writeFileSync(path,JSON.stringify(state));
http.createServer((req,res)=>{
 const sock=net.createConnection({host:'redis',port:6379});
 sock.setTimeout(2000);
 sock.on('connect',()=>sock.write('*1\r\n$4\r\nPING\r\n'));
 sock.once('data',data=>{res.writeHead(200,{'content-type':'application/json'});res.end(JSON.stringify({...state,redis:data.toString().trim()}));sock.end();});
 const fail=()=>{if(!res.writableEnded){res.writeHead(503);res.end('Dependency unavailable');}sock.destroy();};
 sock.on('error',fail);sock.on('timeout',fail);
}).listen(3000,'0.0.0.0');
