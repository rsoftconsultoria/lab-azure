const http=require('http'); const PORT=process.env.PORT||8080; const BACKEND=process.env.BACKEND_URL||'';
http.createServer((req,res)=>{
  if(req.url==='/backend'){
    if(!BACKEND){ res.statusCode=500; return res.end('BACKEND_URL not set'); }
    http.get(BACKEND,(r)=>{let d=''; r.on('data',c=>d+=c); r.on('end',()=>res.end(`Backend says: ${d}\n`));})
      .on('error',e=>{ res.statusCode=502; res.end('ERR '+e.message); });
  } else {
    res.end('Hello Frontend! Try /backend\n');
  }
}).listen(PORT);
