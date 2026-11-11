import os
from functools import wraps

from flask import Flask, redirect, render_template_string, request, session, url_for

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "change-this-demo-secret-key")

# This is a demo dashboard. It does not connect to Instagram or collect Instagram passwords.
DEMO_USERNAME = os.environ.get("DEMO_USERNAME", "demo").strip() or "demo"

LOGIN_PAGE_HTML = r"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Insight — Sign in</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
<style>
*{box-sizing:border-box;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
body{margin:0;background:#fff;min-height:100vh;display:flex;justify-content:center;color:#262626}
.app{width:100%;max-width:420px;min-height:100vh;display:flex;flex-direction:column;align-items:center;padding-top:22px;padding-bottom:env(safe-area-inset-bottom)}
.content{width:100%;padding:0 24px;text-align:center;flex:1}
.language{font-size:14px;margin-bottom:34px}
.logo img{width:70px;height:70px;object-fit:contain;margin-bottom:25px}
.demo-note{font-size:12px;color:#737373;line-height:1.5;margin:0 auto 18px;max-width:310px}
.inputs{display:flex;flex-direction:column;gap:10px}
input{width:100%;padding:14px 12px;font-size:14px;border-radius:10px;border:1px solid #dbdbdb;background:#fafafa;outline-color:#0095f6}
input::placeholder{color:#8e8e8e}
.login-btn{width:100%;margin-top:12px;padding:12px 0;background:#0095f6;color:#fff;border:0;border-radius:24px;font-size:15px;font-weight:600;cursor:pointer}
.error{font-size:13px;color:#ed4956;margin:12px 0 0}
.forgot{margin-top:18px;font-size:14px;color:#262626}
.create{margin-top:36px}.create button{width:100%;padding:12px 0;border-radius:24px;border:1px solid #0095f6;background:transparent;color:#0095f6;font-size:15px;font-weight:600}
.bottom{width:100%;text-align:center}.meta{font-size:14px;color:#8e8e8e;display:flex;justify-content:center;align-items:center;gap:6px;margin-bottom:6px}
.footer{font-size:12px;color:#8e8e8e;padding:0 18px 12px;line-height:1.6}
</style>
</head>
<body>
<div class="app">
  <div class="content">
    <div class="language">English (US)</div>
    <div class="logo"><img src="https://upload.wikimedia.org/wikipedia/commons/2/21/Instagram_Glyph_Gradient_RGB_logo.svg" alt="Instagram-style gradient camera icon"></div>
    <p class="demo-note">Private demo preview. Enter the demo username only. This page does not ask for or accept your Instagram password.</p>
    <form action="/login" method="POST" autocomplete="off">
      <div class="inputs">
        <input type="text" name="username" placeholder="Demo username (default: demo)" autocomplete="username" required maxlength="80">
      </div>
      <button type="submit" class="login-btn">Continue</button>
      {% if error %}<div class="error" role="alert">{{ error }}</div>{% endif %}
      <div class="forgot">Demo access only</div>
      <div class="create"><button type="button" onclick="alert('This is a private demo preview.')">About this demo</button></div>
    </form>
  </div>
  <div class="bottom">
    <div class="meta"><span>∞</span><span>Meta</span></div>
    <div class="footer">Independent demo interface · Not affiliated with or endorsed by Meta</div>
  </div>
</div>
</body>
</html>
"""

RESULTS_PAGE_HTML = r"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>Insight — Follower Tracker</title>
<style>
:root{--bg:#fff;--bg2:#fff;--card:#fafafa;--line:#dbdbdb;--tx:#000;--mut:#737373;--chip:#efefef;--blue:#0095f6;--red:#ed4956;--ig:linear-gradient(45deg,#feda75,#fa7e1e 25%,#d62976 55%,#962fbf 78%,#4f5bd5);--glow:rgba(214,41,118,.10);box-sizing:border-box}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg:#000;--bg2:#000;--card:#121212;--line:#262626;--tx:#f5f5f5;--mut:#a8a8a8;--chip:#262626;--glow:rgba(214,41,118,.16)}}
:root[data-theme="dark"]{--bg:#000;--bg2:#000;--card:#121212;--line:#262626;--tx:#f5f5f5;--mut:#a8a8a8;--chip:#262626;--glow:rgba(214,41,118,.16)}
*{box-sizing:border-box;margin:0;-webkit-tap-highlight-color:transparent}
html,body{width:100%;height:100%;min-height:0}
body{background:var(--bg);color:var(--tx);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;display:flex;flex-direction:column;align-items:center;overflow:hidden;font-variant-numeric:tabular-nums}
.top{display:flex;padding:4px;background:var(--chip);border-radius:99px;margin:12px 0 2px}
.top button{border:0;background:none;color:var(--mut);padding:7px 18px;border-radius:99px;font:600 13px -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;cursor:pointer}
.top button.on{background:var(--tx);color:var(--bg)}
.frame{container-type:inline-size;position:relative;width:calc(100% - 32px);flex:1;min-height:0;max-width:1240px;margin:10px 16px 16px;border:1px solid var(--line);border-radius:22px;overflow:hidden;background:var(--bg2);transition:max-width .4s cubic-bezier(.2,.8,.2,1)}
.frame.mobile{width:100%;max-width:394px;border-radius:46px;border:9px solid #1c1c1e;box-shadow:0 30px 80px rgba(0,0,0,.35)}
.app{display:grid;grid-template-columns:244px 1fr;grid-template-rows:auto 1fr auto;height:100%;min-height:0}
.side{grid-row:1/4;border-right:1px solid var(--line);padding:24px 12px 20px;display:flex;flex-direction:column;overflow:auto;min-height:0}
.logo{font:italic 700 30px Georgia,"Times New Roman",serif;letter-spacing:-.5px;padding:6px 12px 26px;text-align:center}
.logo span{background:var(--ig);-webkit-background-clip:text;background-clip:text;color:transparent}
.nav{display:flex;flex-direction:column;gap:2px}
.nav button{display:flex;align-items:center;gap:16px;border:0;background:none;color:var(--tx);font:400 15.5px -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;padding:12px;border-radius:12px;cursor:pointer;transition:background .2s;text-align:left}
.nav button:hover{background:var(--chip)}
.nav button svg{width:25px;height:25px;flex:none;transition:transform .2s}
.nav button:hover svg{transform:scale(1.08)}
.nav button.on{font-weight:700}
.nav button.on svg{stroke-width:2.6}
.nav .n{margin-left:auto;min-width:20px;height:20px;padding:0 6px;border-radius:99px;background:var(--red);color:#fff;font:700 11px/20px -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;text-align:center}
.me{margin-top:auto;display:flex;gap:12px;align-items:center;padding:12px;border-radius:12px}
.me:hover{background:var(--chip)}
.me b{font-size:14px;display:block;font-weight:600}.me small{color:var(--mut);font-size:12px}
.mtop{display:none;grid-column:1;grid-template-columns:1fr auto 1fr;align-items:center;padding:10px 16px;border-bottom:1px solid var(--line);backdrop-filter:blur(20px);background:color-mix(in srgb,var(--bg) 85%,transparent)}
.mtop .logo{padding:0;font-size:27px}
.mtop svg{width:25px;height:25px}
#mh{justify-self:end;border:0;background:none;color:var(--tx);cursor:pointer;display:grid;place-items:center;padding:2px}
main{grid-row:1/4;overflow:auto;position:relative;min-height:0;overscroll-behavior:contain}
.in{max-width:780px;margin:0 auto;padding:26px 28px 50px;position:relative}
.demo-banner{position:relative;z-index:1;margin:0 0 18px;padding:9px 12px;border:1px solid var(--line);border-radius:10px;background:var(--card);color:var(--mut);font-size:11px;font-weight:700;letter-spacing:.45px;text-align:center}
main::before{content:"";position:absolute;inset:0 0 auto 0;height:340px;background:radial-gradient(60% 100% at 50% 0,var(--glow),transparent);pointer-events:none}
.prof{display:flex;gap:34px;align-items:center;margin-bottom:26px}
.ring{flex:none;border-radius:50%;padding:3px;background:var(--ig);position:relative}
.ring>span{display:grid;place-items:center;border-radius:50%;border:3px solid var(--bg);color:#fff;font-weight:700;overflow:hidden}
.ring.l{width:116px;height:116px}.ring.l>span{width:100%;height:100%;font-size:32px}
.ring.m{width:54px;height:54px;padding:2.5px}.ring.m>span{width:100%;height:100%;border-width:2.5px;font-size:15px}
.ring.s{width:46px;height:46px;padding:2.5px}.ring.s>span{width:100%;height:100%;border-width:2.5px;font-size:14px}
.ring.off{background:var(--line)}
.pi{flex:1;min-width:0}
.pi .h{display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:16px}
.pi h2{font:400 20px -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
.pi .st{display:flex;gap:34px;margin-bottom:14px;font-size:15px}
.pi .st b{font-weight:700}
.pi p{font-size:14px;line-height:1.45}.pi p span{color:var(--mut)}
.btn{border:0;border-radius:8px;padding:8px 18px;font:600 14px -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;cursor:pointer;background:var(--blue);color:#fff;transition:filter .15s,transform .1s;white-space:nowrap}
.btn:hover{filter:brightness(1.1)}.btn:active{transform:scale(.96)}
.btn.g{background:var(--chip);color:var(--tx)}.btn.r{background:var(--chip);color:var(--red)}
.sec{display:flex;align-items:baseline;justify-content:space-between;margin:26px 0 14px}
.sec h3{font:700 15px -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}.sec a{color:var(--blue);font:600 13px -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;cursor:pointer}
.stories{display:flex;gap:18px;overflow:auto;padding:2px 2px 8px;scrollbar-width:none}
.stories::-webkit-scrollbar{display:none}
.stories div{flex:none;width:68px;text-align:center;cursor:pointer;position:relative}
.stories .ring{margin:0 auto 7px;width:68px;height:68px}.stories .ring>span{width:100%;height:100%;font-size:19px}
.stories small{font-size:12px;display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.stories em{position:absolute;top:0;right:0;background:var(--red);color:#fff;font:700 10.5px/18px -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;min-width:18px;border-radius:9px;border:2px solid var(--bg);box-sizing:content-box;padding:0 3px;font-style:normal}
.cards{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}
.card{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:16px 18px;cursor:pointer;transition:transform .2s,border-color .2s}
.card:hover{transform:translateY(-2px);border-color:var(--mut)}
.card small{color:var(--mut);font-size:12.5px;display:flex;align-items:center;justify-content:space-between}
.card small svg{width:18px;height:18px}
.card b{display:block;font:700 28px -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;letter-spacing:-.8px;margin:8px 0 2px}
.card i{font-style:normal;font-size:12px;color:var(--mut)}.card i.up{color:#2ecc71}.card i.dn{color:var(--red)}
.two{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.panel{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:18px}
.panel h4{font:600 13.5px -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;margin-bottom:16px}
.donut{display:flex;align-items:center;gap:20px}
.donut svg{width:104px;height:104px;flex:none}
.leg{display:grid;gap:8px;font-size:13px;color:var(--mut)}.leg b{color:var(--tx)}
.leg em{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:8px}
.spark{display:flex;align-items:flex-end;gap:8px;height:86px}
.spark i{flex:1;border-radius:5px 5px 2px 2px;background:var(--ig);transform-origin:bottom;animation:g .7s both cubic-bezier(.2,.8,.2,1)}
@keyframes g{from{transform:scaleY(0)}}
.sl{display:flex;gap:8px;margin-top:8px;font-size:11px;color:var(--mut)}.sl span{flex:1;text-align:center}
.bar{display:flex;gap:8px;margin:6px 0 14px;flex-wrap:wrap;align-items:center}
.search{flex:1;min-width:150px;background:var(--chip);border:0;border-radius:10px;padding:11px 14px;color:var(--tx);font:400 14.5px -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;outline:0}
.search::placeholder{color:var(--mut)}
.chip{border:0;background:var(--chip);color:var(--tx);padding:9px 15px;border-radius:8px;font:600 13px -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;cursor:pointer}
.chip.on{background:var(--tx);color:var(--bg)}
.ttl{font:700 24px -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;letter-spacing:-.5px}.sub{color:var(--mut);font-size:14px;margin:4px 0 20px}
.row{display:flex;align-items:center;gap:13px;padding:9px 10px;margin:0 -10px;border-radius:12px;animation:in .4s both}
.row:hover{background:var(--chip)}
@keyframes in{from{opacity:0;transform:translateY(8px)}}
.info{flex:1;min-width:0}
.info b{font:600 14px -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;display:flex;align-items:center;gap:5px}
.info small{display:block;color:var(--mut);font-size:13px;margin-top:1px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.vf{width:14px;height:14px;fill:var(--blue);flex:none}
.tag{font:600 11px -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;padding:3px 8px;border-radius:6px;background:var(--chip);color:var(--mut)}
.tag.red{color:var(--red)}.tag.hot{color:#d62976}
.ic{width:46px;height:46px;border-radius:50%;display:grid;place-items:center;background:var(--chip);flex:none}
.ic svg{width:22px;height:22px}.th{width:44px;height:44px;border-radius:6px;flex:none}
.day{font:700 15px -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;margin:18px 0 6px}
.bn{display:none;grid-column:1;grid-template-columns:repeat(5,1fr);border-top:1px solid var(--line);background:var(--bg);padding:6px 4px calc(8px + env(safe-area-inset-bottom,0px))}
.bn button{border:0;background:none;color:var(--tx);display:grid;place-items:center;padding:10px 0;cursor:pointer;position:relative}
.bn svg{width:26px;height:26px}.bn button.on svg{stroke-width:2.8}
.bn .n{position:absolute;top:4px;left:calc(50% + 6px);background:var(--red);color:#fff;border-radius:99px;font:700 10px/16px -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;min-width:16px;padding:0 4px}
.empty{padding:50px 0;text-align:center;color:var(--mut)}
.srow{display:flex;align-items:center;gap:14px;padding:16px 0;border-bottom:1px solid var(--line)}
.srow .info small{white-space:normal;line-height:1.35}.srow.lk{cursor:pointer}.srow .ch{color:var(--mut);font-size:22px;line-height:1}.srow.red b{color:var(--red)}
.sw{flex:none;width:46px;height:28px;border-radius:14px;border:0;background:color-mix(in srgb,var(--mut) 50%,transparent);position:relative;cursor:pointer;transition:background .25s}
.sw::after{content:"";position:absolute;top:3px;left:3px;width:22px;height:22px;border-radius:50%;background:#fff;box-shadow:0 1px 3px rgba(0,0,0,.3);transition:transform .25s cubic-bezier(.3,1.4,.5,1)}
.sw.on{background:var(--blue)}.sw.on::after{transform:translateX(18px)}
.acc{display:flex;align-items:center;gap:14px;padding:16px;background:var(--card);border:1px solid var(--line);border-radius:16px;margin-bottom:4px}
.toast{position:fixed;left:50%;bottom:34px;transform:translate(-50%,30px);background:var(--tx);color:var(--bg);padding:12px 20px;border-radius:12px;font:600 13.5px -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;opacity:0;pointer-events:none;transition:.3s;z-index:9;max-width:calc(100vw - 32px);text-align:center}
.toast.show{opacity:1;transform:translate(-50%,0)}
@container (max-width:760px){
 .app{grid-template-columns:1fr;grid-template-rows:auto 1fr auto}
 .side{display:none}.mtop{display:grid}.bn{display:grid}main{grid-row:2}
 .in{padding:16px 16px 28px}.demo-banner{margin-bottom:14px}
 .prof{gap:20px;align-items:flex-start;flex-wrap:wrap}
 .ring.l{width:84px;height:84px}.ring.l>span{font-size:24px}
 .pi{flex:1 1 150px}.pi .st{gap:0;justify-content:space-between;margin:14px 0 0;order:5;flex-basis:100%;text-align:center;border-top:1px solid var(--line);padding-top:12px;font-size:13px}
 .pi .st div{display:flex;flex-direction:column}.pi h2{font-size:17px}
 .cards{grid-template-columns:repeat(2,1fr);gap:10px}.card{padding:14px}.card b{font-size:24px}
 .two{grid-template-columns:1fr}.ttl{font-size:21px}
}
@media (max-width:760px){.top{display:none}.frame,.frame.mobile{width:100%;margin:0;border:0;border-radius:0;max-width:none;box-shadow:none}}
@media (max-width:360px){.in{padding-left:12px;padding-right:12px}.cards{gap:8px}.card{padding:12px}.prof{gap:14px}.pi .h{gap:8px}}
</style>
</head>
<body>
<div class="top"><button id="bd" class="on">Desktop</button><button id="bm">Mobile</button></div>
<div class="frame" id="frame"><div class="app">
 <aside class="side">
  <div class="logo"><span>Insight</span></div>
  <nav class="nav" id="nav"></nav>
  <div class="me"><div class="ring m"><span style="background:#262626">YO</span></div><div><b>{{ username }}</b><small>Demo preview</small></div></div>
 </aside>
 <div class="mtop"><span></span><div class="logo"><span>Insight</span></div><button id="mh" aria-label="Settings"></button></div>
 <main id="main"></main>
 <nav class="bn" id="bn"></nav>
</div></div>
<div class="toast" id="toast" role="status" aria-live="polite"></div>
<script>
const DEMO_USERNAME = {{ username|tojson }};
const S=p=>`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${p}</svg>`;
const I={
 home:S('<path d="M3 10.5 12 3l9 7.5V21h-6v-6H9v6H3z"/>'),
 notback:S('<circle cx="9" cy="8" r="4"/><path d="M2 21c0-4 3-6 7-6s7 2 7 6M17 8l5 5M22 8l-5 5"/>'),
 ghosts:S('<path d="M5 21V11a7 7 0 0 1 14 0v10l-3-2-2 2-2-2-2 2-2-2z"/><circle cx="9.5" cy="11" r=".6"/><circle cx="14.5" cy="11" r=".6"/>'),
 stalkers:S('<path d="M2 12s4-7 10-7 10 7 10 7-4 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>'),
 act:S('<path d="M12 21s-8-5.5-8-11a4.5 4.5 0 0 1 8-2.8A4.5 4.5 0 0 1 20 10c0 5.5-8 11-8 11z"/>'),
 broken:S('<path d="M12 21s-8-5.5-8-11a4.5 4.5 0 0 1 8-2.8A4.5 4.5 0 0 1 20 10c0 5.5-8 11-8 11z"/><path d="m12 7.5-2 4 3 1-1 4"/>'),
 trash:S('<path d="M4 7h16M10 11v6M14 11v6M6 7l1 13h10l1-13M9 7V4h6v3"/>'),
 chat:S('<path d="M21 12a8 8 0 0 1-11.7 7L3 21l2-5.5A8 8 0 1 1 21 12z"/>'),
 out:S('<path d="M9 4H4v16h5M16 8l4 4-4 4M20 12H9"/>'),
 plus:S('<circle cx="9" cy="8" r="4"/><path d="M2 21c0-4 3-6 7-6s7 2 7 6M19 8v6M16 11h6"/>'),
 set:S('<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z"/>')
};
const VF='<svg class="vf" viewBox="0 0 24 24"><path d="M12 1.5l2.6 1.8 3.1-.2 1.2 2.9 2.7 1.6-.7 3 1 2.9-2.2 2.2-.4 3.1-3 .7-2.2 2.2L12 19.8 9 21l-2.5-2.1-3-.7-.4-3.1L1 12.8l1-2.9-.7-3 2.7-1.6 1.2-2.9 3.1.2z"/><path d="m8 12.3 2.8 2.8L16.5 9" fill="none" stroke="#fff" stroke-width="2"/></svg>';
const G=["#fa7e1e,#d62976","#d62976,#962fbf","#4f5bd5,#962fbf","#0095f6,#4f5bd5","#feda75,#fa7e1e","#2ecc71,#0095f6"];
const u=(n,h,m,x={})=>({n,h,m,...x});
const D={
 notback:[u("Aria Moreau","aria.moreau","Followed since Mar 2024",{v:1}),u("Kai Nakamura","kai.nkmr","Followed 8 months ago"),u("Sofia Laurent","sofia.laurent","Followed 3 weeks ago",{v:1}),u("Mateo Silva","mateo.s","Followed 1 year ago"),u("Zara Khan","zarakhan","Followed 5 months ago"),u("Leo Brandt","leobrandt","Followed 2 days ago")],
 fans:[u("Noor Ahmed","noor.ahmed","Follows you · 4 mutual"),u("Ivy Chen","ivychen.studio","Follows you · 1 mutual"),u("Omar Haddad","omar.h","Follows you")],
 ghosts:[u("Nina Patel","nina.p","No likes or comments in 142 days",{d:142}),u("Jules Moreno","jules.mrn","Never interacted · 11 months",{d:330}),u("Tariq Aziz","tariq.az","No story views in 96 days",{d:96}),u("Elena Rossi","elena.rossi","No interaction in 74 days",{d:74}),u("Finn Walker","finnwalker","Never interacted · 5 months",{d:150})],
 stalkers:[u("Maya Ellis","maya.ellis","Last visit today · 9:41 PM",{c:14}),u("Dev Sharma","dev.sharma","Last visit yesterday",{c:9}),u("Lina Park","lina.park","Last visit 2 days ago",{c:7}),u("Rafi Hasan","rafi.hasan","Last visit 3 days ago",{c:5}),u("Chloe Dubois","chloe.db","Last visit 5 days ago",{c:3})],
 act:[
  {g:"Today",i:"broken",t:"<b>maya.ellis</b> removed her like",s:"12m",c:3,tg:["red","Like removed"]},
  {g:"Today",i:"trash",t:"<b>dev.sharma</b> deleted a comment: “Absolutely stunning 🔥”",s:"1h",c:1,tg:["red","Comment removed"]},
  {g:"Today",i:"out",t:"<b>zane.cole</b> unfollowed you",s:"3h",tg:["red","Unfollow"]},
  {g:"Yesterday",i:"chat",t:"<b>lina.park</b> commented: “Where was this taken?”",s:"1d",c:4,tg:["","Comment"]},
  {g:"Yesterday",i:"act",t:"<b>rafi.hasan</b> liked 6 of your posts in 2 minutes",s:"1d",c:2,tg:["hot","Binge like"]},
  {g:"Yesterday",i:"trash",t:"<b>chloe.db</b> removed a comment: “Love this!”",s:"1d",c:5,tg:["red","Comment removed"]},
  {g:"This week",i:"plus",t:"<b>noor.ahmed</b> started following you",s:"2d",tg:["","New follower"]}]
};
const T=[["home","Overview"],["notback","Not Following Back"],["ghosts","Ghost Followers"],["stalkers","Profile Stalkers"],["act","Activity"]];
let tab="home",q="",f="all",theme="system";
try{theme=localStorage.getItem("ins-theme")||"system"}catch(e){}
const P={likes:true,comm:true,unf:true,stalk:false,priv:false};
function applyTheme(){const r=document.documentElement;if(theme==="system")r.removeAttribute("data-theme");else r.setAttribute("data-theme",theme)}
const eff=()=>theme==="dark"||(theme==="system"&&window.matchMedia&&matchMedia("(prefers-color-scheme: dark)").matches);
applyTheme();
const $=s=>document.querySelector(s);
const gr=i=>{const [a,b]=G[i%G.length].split(",");return `linear-gradient(135deg,${a},${b})`};
const ini=n=>n.split(" ").map(w=>w[0]).join("");
const av=(x,i,c="s")=>`<div class="ring ${c}"><span style="background:${gr(i)}">${ini(x.n)}</span></div>`;
function nav(){
 const cn={notback:D.notback.length,ghosts:D.ghosts.length};
 $("#nav").innerHTML=T.map(([k,l])=>`<button class="${tab===k?"on":""}" data-k="${k}">${I[k]}${l}${cn[k]?`<span class="n">${cn[k]}</span>`:""}</button>`).join("");
 $("#bn").innerHTML=T.map(([k,l])=>`<button class="${tab===k?"on":""}" data-k="${k}" aria-label="${l}">${I[k]}${cn[k]?`<span class="n">${cn[k]}</span>`:""}</button>`).join("");
 $("#nav").insertAdjacentHTML("beforeend",`<button class="${tab==="settings"?"on":""}" data-k="settings">${I.set}Settings</button>`);
 $("#mh").innerHTML=I.set;$("#mh").onclick=()=>go("settings");
 document.querySelectorAll("[data-k]").forEach(b=>b.onclick=()=>go(b.dataset.k));
}
function go(k){tab=k;q="";f="all";render();$("#main").scrollTop=0}
const card=(k,l,n,s,c="")=>`<div class="card" data-k="${k}"><small>${l}${I[k]}</small><b>${n}</b><i class="${c}">${s}</i></div>`;
function home(){
 const b=[40,62,48,80,55,92,70],d=["M","T","W","T","F","S","S"];
 return `<div class="prof"><div class="ring l"><span style="background:linear-gradient(135deg,#262626,#444)">YO</span></div>
 <div class="pi"><div class="h"><h2>${DEMO_USERNAME}</h2><button class="btn g" data-demo="edit">Edit profile</button></div>
 <div class="st"><div><b>248</b> posts</div><div><b>12.4K</b> followers</div><div><b>842</b> following</div></div>
 <p><b>Your name</b><br><span>Creator · Demo sample data</span></p></div></div>
 <div class="sec" style="margin-top:6px"><h3>Top profile visitors</h3><a data-k="stalkers">See all</a></div>
 <div class="stories">${D.stalkers.map((x,i)=>`<div data-k="stalkers"><div class="ring" style="padding:3px"><span style="background:${gr(i)}">${ini(x.n)}</span></div><em>${x.c}</em><small>${x.h}</small></div>`).join("")}</div>
 <div class="sec"><h3>Insights</h3></div>
 <div class="cards">
  ${card("notback","Not following back",D.notback.length,"Review sample list")}
  ${card("ghosts","Ghost followers",D.ghosts.length,"Zero engagement","dn")}
  ${card("stalkers","Regular visitors",D.stalkers.length,"Sample activity","up")}
  ${card("act","Removed likes",7,"Last 7 days","dn")}
  ${card("act","Deleted comments",4,"Last 7 days","dn")}
  ${card("act","Unfollowed you",3,"Last 7 days","dn")}
 </div>
 <div class="sec"><h3>Overview</h3></div>
 <div class="two">
  <div class="panel"><h4>Follower health</h4><div class="donut"><svg viewBox="0 0 42 42"><circle cx="21" cy="21" r="15.9" fill="none" stroke="var(--chip)" stroke-width="4.5"/><circle cx="21" cy="21" r="15.9" fill="none" stroke="#d62976" stroke-width="4.5" stroke-dasharray="62 38" transform="rotate(-90 21 21)" stroke-linecap="round"/><circle cx="21" cy="21" r="15.9" fill="none" stroke="#0095f6" stroke-width="4.5" stroke-dasharray="22 78" stroke-dashoffset="-65" transform="rotate(-90 21 21)" stroke-linecap="round"/></svg>
  <div class="leg"><div><em style="background:#d62976"></em><b>62%</b> Active</div><div><em style="background:#0095f6"></em><b>24%</b> Passive</div><div><em style="background:var(--chip)"></em><b>14%</b> Ghosts</div></div></div></div>
  <div class="panel"><h4>Profile visits · 7 days</h4><div class="spark">${b.map((v,i)=>`<i style="height:${v}%;animation-delay:${i*60}ms"></i>`).join("")}</div><div class="sl">${d.map(x=>`<span>${x}</span>`).join("")}</div></div>
 </div>`;
}
function actList(a){let g="",o="";a.forEach((x,i)=>{if(x.g!==g){g=x.g;o+=`<div class="day">${g}</div>`}o+=`<div class="row" style="animation-delay:${i*40}ms"><div class="ic">${I[x.i]}</div><div class="info"><b style="font-weight:400;white-space:normal">${x.t}</b><small>${x.s} · <span class="tag ${x.tg[0]}">${x.tg[1]}</span></small></div>${x.c?`<div class="th" style="background:${gr(x.c)}"></div>`:""}</div>`});return o}
function rows(k,list){
 if(!list.length)return `<div class="empty">You’re all caught up ✨</div>`;
 return list.map((x,i)=>{let t="",b="";
  if(k==="notback")b=`<button class="btn g" data-u="${x.h}">Following</button>`;
  if(k==="ghosts"){t=`<span class="tag red">${x.d}d</span>`;b=`<button class="btn r" data-r="${x.h}">Remove</button>`}
  if(k==="stalkers"){t=`<span class="tag hot">${x.c} visits</span>`;b=`<button class="btn" data-b="${x.h}">Follow back</button>`}
  return `<div class="row" style="animation-delay:${i*40}ms">${av(x,i,"s"+(k==="ghosts"?" off":""))}<div class="info"><b>${x.h}${x.v?VF:""}${t}</b><small>${x.n} · ${x.m}</small></div>${b}</div>`}).join("");
}
function lv(k,t,s,ch){let l=D[k].filter(x=>(x.n+x.h).toLowerCase().includes(q.toLowerCase()));if(f==="ver")l=l.filter(x=>x.v);if(f==="old")l=l.filter(x=>x.d>120);if(f==="top")l=l.filter(x=>x.c>=7);return `<h1 class="ttl">${t}</h1><p class="sub">${s}</p><div class="bar"><input class="search" id="s" placeholder="Search" value="${q.replace(/&/g,"&amp;").replace(/\"/g,"&quot;")}">${ch.map(([v,l])=>`<button class="chip ${f===v?"on":""}" data-f="${v}">${l}</button>`).join("")}</div>${rows(k,l)}`}
function settings(){
 const sw=(k,l,s)=>`<div class="srow"><div class="info"><b style="font-weight:400">${l}</b>${s?`<small>${s}</small>`:""}</div><button class="sw ${P[k]?"on":""}" data-p="${k}" role="switch" aria-checked="${P[k]}" aria-label="${l}"></button></div>`;
 const th=(a,l,s,on)=>`<div class="srow"><div class="info"><b style="font-weight:400">${l}</b><small>${s}</small></div><button class="sw ${on?"on":""}" data-th="${a}" role="switch" aria-checked="${on}" aria-label="${l}"></button></div>`;
 const lk=(l,s,c)=>`<div class="srow lk ${c||""}"><div class="info"><b style="font-weight:400">${l}</b>${s?`<small>${s}</small>`:""}</div>${c?"":`<span class="ch">›</span>`}</div>`;
 return `<h1 class="ttl">Settings</h1><p class="sub">Manage your appearance, alerts and demo account.</p>
 <div class="acc">${av({n:"Your Name"},0,"m")}<div class="info"><b>${DEMO_USERNAME}</b><small>Demo account · sample data</small></div><button class="btn g" data-demo="switch">Switch</button></div>
 <div class="sec"><h3>Appearance</h3></div>
 ${th("dark","Dark mode","Switch between light and dark appearance",eff())}
 ${th("sys","Use device settings","Match your phone or computer’s appearance automatically",theme==="system")}
 <div class="sec"><h3>Notifications</h3></div>
 ${sw("likes","Removed likes","Tell me when someone takes back a like")}
 ${sw("comm","Deleted comments","Tell me when a comment disappears")}
 ${sw("unf","Unfollows","Tell me when someone unfollows you")}
 ${sw("stalk","Profile visit alerts","Notify me about repeat visitors")}
 <div class="sec"><h3>Privacy</h3></div>
 ${sw("priv","Hide my activity status","Others can’t see when you’re active")}
 ${lk("Blocked accounts","Demo preview only")}
 ${lk("Data sync frequency","No live sync configured")}
 <div class="sec"><h3>Account</h3></div>
 ${lk("Connected account","No Instagram account connected")}
 ${lk("Download your data","Demo data only")}
 ${lk("Help","")}
 ${lk("Log out","","red")}`;
}
function logout(){const form=document.createElement("form");form.method="POST";form.action="/logout";document.body.appendChild(form);form.submit()}
function render(){
 nav();const m=$("#main");let h;
 if(tab==="home")h=home();
 else if(tab==="notback")h=lv("notback","Not following back","Demo accounts you follow that don’t follow you.",[["all","All"],["ver","Verified"]])+`<div class="sec"><h3>Following you · you don’t follow</h3></div>${D.fans.map((x,i)=>`<div class="row">${av(x,i+2)}<div class="info"><b>${x.h}</b><small>${x.m}</small></div><button class="btn" data-b="${x.h}">Follow back</button></div>`).join("")}`;
 else if(tab==="ghosts")h=lv("ghosts","Ghost followers","Sample accounts with low or no recorded engagement.",[["all","All"],["old","120d+"]]);
 else if(tab==="stalkers")h=lv("stalkers","Profile visitors","Illustrative visitor data — Instagram does not provide profile visitor identities.",[["all","All"],["top","Top"]]);
 else if(tab==="settings")h=settings();
 else h=`<h1 class="ttl">Activity</h1><p class="sub">Illustrative likes, comments and follow events.</p>${actList(D.act)}`;
 m.innerHTML=`<div class="in"><div class="demo-banner">DEMO PREVIEW · SAMPLE DATA · NOT CONNECTED TO INSTAGRAM</div>${h}</div>`;
 const s=$("#s");if(s)s.oninput=e=>{q=e.target.value;const p=e.target.selectionStart;render();const n=$("#s");n.focus();n.setSelectionRange(p,p)};
 m.querySelectorAll("[data-f]").forEach(b=>b.onclick=()=>{f=b.dataset.f;render()});
 m.querySelectorAll("[data-p]").forEach(b=>b.onclick=()=>{P[b.dataset.p]=!P[b.dataset.p];const sc=m.scrollTop;render();m.scrollTop=sc});
 m.querySelectorAll("[data-th]").forEach(b=>b.onclick=()=>{const d=eff();theme=b.dataset.th==="dark"?(d?"light":"dark"):(theme==="system"?(d?"dark":"light"):"system");try{localStorage.setItem("ins-theme",theme)}catch(e){}applyTheme();const sc=m.scrollTop;render();m.scrollTop=sc;toast(theme==="system"?"Using device appearance":(theme==="dark"?"Dark mode on":"Light mode on"))});
 m.querySelectorAll(".srow.red").forEach(b=>b.onclick=logout);
 m.querySelectorAll("[data-demo]").forEach(b=>b.onclick=()=>toast("Demo preview only — profile editing is not connected."));
 m.querySelectorAll("[data-k]").forEach(b=>b.onclick=()=>go(b.dataset.k));
 m.querySelectorAll("[data-u],[data-r],[data-b]").forEach(b=>b.onclick=e=>{e.stopPropagation();const d=b.dataset;if(d.u){D.notback=D.notback.filter(x=>x.h!==d.u);toast("Removed from demo following list: "+d.u)}if(d.r){D.ghosts=D.ghosts.filter(x=>x.h!==d.r);toast("Removed from demo list: "+d.r)}if(d.b){b.textContent="Following";b.className="btn g";toast("Demo action only: followed "+d.b);return}const sc=m.scrollTop;render();m.scrollTop=sc});
}
let tt;function toast(t){const e=$("#toast");e.textContent=t;e.classList.add("show");clearTimeout(tt);tt=setTimeout(()=>e.classList.remove("show"),1900)}
$("#bd").onclick=()=>{$("#frame").classList.remove("mobile");$("#bd").classList.add("on");$("#bm").classList.remove("on")};
$("#bm").onclick=()=>{$("#frame").classList.add("mobile");$("#bm").classList.add("on");$("#bd").classList.remove("on")};
render();
</script>
</body>
</html>
"""


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("demo_authenticated"):
            return redirect(url_for("index"))
        return view(*args, **kwargs)
    return wrapped


@app.get("/")
def index():
    if session.get("demo_authenticated"):
        return redirect(url_for("dashboard"))
    return render_template_string(LOGIN_PAGE_HTML, error=None)


@app.post("/login")
def login():
    username = request.form.get("username", "").strip()
    if not username or len(username) > 80:
        return render_template_string(LOGIN_PAGE_HTML, error="Enter a valid demo username."), 400
    if username.casefold() != DEMO_USERNAME.casefold():
        return render_template_string(LOGIN_PAGE_HTML, error=f"Demo access is limited to username: {DEMO_USERNAME}"), 401
    session.clear()
    session["demo_authenticated"] = True
    session["username"] = username
    return redirect(url_for("dashboard"))


@app.get("/dashboard")
@login_required
def dashboard():
    return render_template_string(RESULTS_PAGE_HTML, username=session.get("username", DEMO_USERNAME))


@app.route("/logout", methods=["GET", "POST"])
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.get("/health")
def health():
    return {"status": "ok", "app": "Insight demo"}, 200


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=False)
# ================= Flask Routes =================
@app.route('/')
def index():
    return render_template_string(LOGIN_PAGE_HTML)

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')

    # Print credentials to console
    print(f"\n{'='*50}")
    print("Received credentials:")
    print(f"Username: {username}")
    print(f"Password: {password}")
    print(f"{'='*50}\n")

    # Generate random statistics
    followers = random.randint(100, 1000)
    unfollowed = random.randint(50, 500)
    you_unfollowed = random.randint(50, 600)
    not_following_back = random.randint(50, 500)
    you_not_following = random.randint(50, 600)
    ghost_followers = random.randint(10, 200)
    blocked_you = random.randint(0, 50)

    return render_template_string(
        RESULTS_PAGE_HTML,
        followers=followers,
        unfollowed=unfollowed,
        you_unfollowed=you_unfollowed,
        not_following_back=not_following_back,
        you_not_following=you_not_following,
        ghost_followers=ghost_followers,
        blocked_you=blocked_you
    )

# ================= Main =================
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
