// Adapt emitted files only; preserve reviewed Next-compatible source byte-for-byte.
const fs=require('node:fs'),path=require('node:path');
function visit(dir){for(const entry of fs.readdirSync(dir,{withFileTypes:true})){
 const p=path.join(dir,entry.name);if(entry.isDirectory())visit(p);
 else if(p.endsWith('.js'))fs.writeFileSync(p,fs.readFileSync(p,'utf8').replace(/(from\s*["'])(\.{1,2}\/[^"']+)(["'])/g,(all,start,spec,end)=>path.extname(spec)?all:start+spec+'.js'+end));
}}
visit('build');
