/* Auto-generated from contexts/explorer/views/src/site.css -- do not edit.
 * Regenerate: make site-css */

#ifndef SITE_CSS_H
#define SITE_CSS_H

static const char site_css_0[] =
    ":root{--bg:#0a0d12;--bg-raise:#0e1219;--panel:#121722;--panel-2:#171d2a;--border:#232b3a;--border"
    "-strong:#313b4e;--ink:#e9eef6;--ink-dim:#c3ccd9;--muted:#97a3b6;--faint:#69748a;--accent:#5ea8ff;"
    "--accent-ink:#b9d9ff;--accent-soft:rgba(94,168,255,0.13);--ok:#3ddc97;--ok-soft:rgba(61,220,151,0"
    ".13);--warn:#f0b44c;--warn-soft:rgba(240,180,76,0.14);--bad:#f2708a;--bad-soft:rgba(242,112,138,0"
    ".13);--violet:#a78bfa;--violet-soft:rgba(167,139,250,0.14);--mono:ui-monospace,'SF Mono','Cascadi"
    "a Code',Menlo,Consolas,'Liberation Mono',monospace;--r-sm:6px;--r:10px;--r-lg:14px;color-scheme:d"
    "ark light;}@media (prefers-color-scheme:light){:root{--bg:#f4f6f9;--bg-raise:#eceff4;--panel:#fff"
    "fff;--panel-2:#f7f9fc;--border:#d9e0e9;--border-strong:#bfc9d6;--ink:#182233;--ink-dim:#33405a;--"
    "muted:#5b6779;--faint:#8591a3;--accent:#0b63ce;--accent-ink:#084a9e;--accent-soft:rgba(11,99,206,"
    "0.09);--ok:#0e8a58;--ok-soft:rgba(14,138,88,0.11);--warn:#9a6700;--warn-soft:rgba(154,103,0,0.11)"
    ";--bad:#c22744;--bad-soft:rgba(194,39,68,0.09);--violet:#6d47d8;--violet-soft:rgba(109,71,216,0.1"
    "0);}}*{box-sizing:border-box;}html{scroll-behavior:smooth;}body{margin:0 auto;max-width:1180px;pa"
    "dding:16px 24px 40px;background:var(--bg);background-image:linear-gradient(180deg,var(--bg-raise)"
    " 0,var(--bg) 380px);background-repeat:no-repeat;color:var(--ink);font-family:-apple-system,BlinkM"
    "acSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;font-size:17px;line-height:1.6;text-ren"
    "dering:optimizeLegibility;-webkit-font-smoothing:antialiased;}body.measure{max-width:860px;}h1{fo"
    "nt-size:31px;font-weight:720;letter-spacing:-0.015em;line-height:1.2;margin:0 0 12px;color:var(--"
    "ink);}h2{font-size:23px;font-weight:680;letter-spacing:-0.01em;margin:32px 0 14px;padding-bottom:"
    "8px;border-bottom:1px solid var(--border);color:var(--ink);}h3{font-size:18px;font-weight:640;mar"
    "gin:0 0 10px;}p{margin:0 0 14px;}hr{border:none;border-top:1px solid var(--border);margin:24px 0;"
    "}code,.mono{font-family:var(--mono);font-size:0.86em;}code{color:var(--accent-ink);}a{color:var(-"
    "-accent);text-decoration:none;}a:hover{color:var(--accent-ink);text-decoration:underline;}a:focus"
    "-visible,input:focus-visible,select:focus-visible,button:focus-visible,[tabindex]:focus-visible{o"
    "utline:3px solid var(--ok);outline-offset:2px;border-radius:var(--r-sm);}.sr-only{position:absolu"
    "te;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowr"
    "ap;border:0;}.skip{position:absolute;left:12px;top:-64px;z-index:30;padding:8px 14px;border-radiu"
    "s:var(--r-sm);background:var(--accent);color:var(--bg);font-weight:700;}.skip:focus{top:12px;text"
    "-decoration:none;}.site-top{display:flex;align-items:center;gap:4px 18px;flex-wrap:wrap;padding:1"
    "0px 0 14px;margin-bottom:18px;border-bottom:1px solid var(--border);}.site-top .brand{display:fle"
    "x;align-items:center;gap:10px;margin-right:auto;font-weight:760;font-size:16px;letter-spacing:-0."
    "01em;color:var(--ink);white-space:nowrap;}.site-top .brand:hover{text-decoration:none;}.si";
static const char site_css_1[] =
    "te-top .brand .glyph{display:grid;place-items:center;width:30px;height:30px;border-radius:9px;bor"
    "der:1px solid var(--border-strong);background:linear-gradient(145deg,var(--accent-soft),var(--vio"
    "let-soft));color:var(--accent-ink);font-weight:800;}.site-top nav{display:flex;gap:2px;flex-wrap:"
    "wrap;}.site-top nav a{padding:6px 11px;border-radius:var(--r-sm);border:1px solid transparent;col"
    "or:var(--muted);font-size:14px;font-weight:620;white-space:nowrap;}.site-top nav a:hover{color:va"
    "r(--ink);background:var(--panel);border-color:var(--border);text-decoration:none;}.site-top nav a"
    ".active{color:var(--accent-ink);background:var(--accent-soft);border-color:var(--border-strong);}"
    ".nav{display:flex;gap:6px;align-items:center;flex-wrap:wrap;padding:10px 12px;margin-bottom:22px;"
    "background:var(--panel);border:1px solid var(--border);border-radius:var(--r);box-shadow:0 8px 22"
    "px rgba(0,0,0,0.16);}.nav a{color:var(--ink-dim);font-weight:640;font-size:14px;line-height:1.2;p"
    "adding:7px 10px;border-radius:var(--r-sm);border:1px solid transparent;white-space:nowrap;}.nav a"
    ":hover{color:var(--ink);background:var(--panel-2);border-color:var(--border-strong);text-decorati"
    "on:none;}.nav a.active{color:var(--accent-ink);background:var(--accent-soft);border-color:var(--b"
    "order-strong);}.nav .search{flex:1;min-width:220px;}.nav input{width:100%;background:var(--bg);co"
    "lor:var(--ink);border:1px solid var(--border-strong);border-radius:var(--r-sm);padding:9px 13px;f"
    "ont-family:inherit;font-size:15px;}.nav input::placeholder{color:var(--faint);}.nav input:focus{o"
    "utline:none;border-color:var(--ok);box-shadow:0 0 0 3px var(--ok-soft);}.card,.panel,.product{bac"
    "kground:linear-gradient(180deg,var(--panel-2) 0,var(--panel) 100%);border:1px solid var(--border)"
    ";border-left:3px solid var(--accent);border-radius:var(--r);padding:18px 22px;margin:14px 0;box-s"
    "hadow:0 8px 22px rgba(0,0,0,0.10);}.grid{display:grid;grid-template-columns:180px 1fr;gap:8px 16p"
    "x;font-size:16px;}.grid .label,.kv b{color:var(--muted);font-weight:600;}.grid .val,.kv .val{colo"
    "r:var(--ink);word-break:break-all;}.kv{display:flex;gap:10px;margin:5px 0;font-size:14px;}.kv b{m"
    "in-width:130px;display:inline-block;}table{width:100%;border-collapse:collapse;font-size:16px;bac"
    "kground:var(--panel);border:1px solid var(--border);border-radius:var(--r);overflow:hidden;}th{te"
    "xt-align:left;color:var(--muted);padding:11px 14px;border-bottom:1px solid var(--border-strong);f"
    "ont-weight:700;font-size:13px;text-transform:uppercase;letter-spacing:0.04em;}td{padding:11px 14p"
    "x;border-bottom:1px solid var(--border);}tbody tr:last-child td{border-bottom:none;}tbody tr:hove"
    "r,table tr:hover{background:var(--panel-2);}.table-wrap{overflow-x:auto;-webkit-overflow-scrollin"
    "g:touch;max-width:100%;margin:12px 0;}.mono{font-size:14px;}.hash{color:var(--accent);font-family"
    ":var(--mono);font-size:14px;word-break:break-all;}.amount{color:var(--ok);text-align:right;font-w"
    "eight:640;font-size:17px;}.muted{color:var(--muted);}.amount,.io-val,.stat .num,.num-mono{";
static const char site_css_2[] =
    "font-variant-numeric:tabular-nums;}.num-mono{font-family:var(--mono);}.tag,.pill{display:inline-b"
    "lock;padding:3px 11px;border-radius:999px;font-size:13px;font-weight:700;letter-spacing:0.02em;bo"
    "rder:1px solid transparent;}.tag-cb,.pill-ok,.paid{background:var(--ok-soft);color:var(--ok);bord"
    "er-color:var(--ok);}.tag-shielded,.pill-violet{background:var(--violet-soft);color:var(--violet);"
    "border-color:var(--violet);}.tag-slp{background:var(--violet-soft);color:var(--violet);}.tag-memp"
    "ool,.pill-warn,.pending{background:var(--warn-soft);color:var(--warn);border-color:var(--warn);}."
    "pill-bad,.failed{background:var(--bad-soft);color:var(--bad);border-color:var(--bad);}.pill-info{"
    "background:var(--accent-soft);color:var(--accent-ink);border-color:var(--accent);}.status{padding"
    ":7px 15px;border-radius:999px;display:inline-block;font-weight:700;font-size:13px;}.stat{text-ali"
    "gn:center;padding:16px 12px;}.stat .num{font-size:34px;color:var(--ok);font-weight:780;line-heigh"
    "t:1.15;letter-spacing:-0.02em;}.stat .lbl{font-size:13px;color:var(--muted);text-transform:upperc"
    "ase;letter-spacing:0.05em;margin-top:4px;}.stats-row{display:flex;gap:14px;margin:16px 0;}.stats-"
    "row .stat{flex:1;min-width:0;background:linear-gradient(180deg,var(--panel-2) 0,var(--panel) 100%"
    ");border:1px solid var(--border);border-radius:var(--r);box-shadow:0 8px 22px rgba(0,0,0,0.10);}."
    "chaincards{display:flex;gap:14px;flex-wrap:wrap;margin:16px 0;}.chaincard{flex:1;min-width:160px;"
    "background:var(--panel);border:1px solid var(--border);border-radius:var(--r);padding:16px;}label"
    "{display:block;font-size:13px;font-weight:640;color:var(--muted);margin:12px 0 4px;}input,select,"
    "textarea{background:var(--bg);color:var(--ink);border:1px solid var(--border-strong);border-radiu"
    "s:var(--r-sm);padding:9px 12px;font-family:inherit;font-size:15px;box-sizing:border-box;}input{wi"
    "dth:100%;}input:focus,select:focus,textarea:focus{outline:none;border-color:var(--ok);box-shadow:"
    "0 0 0 3px var(--ok-soft);}.btn,button.btn{display:inline-block;background:var(--ok);color:#07130d"
    ";padding:10px 22px;border-radius:var(--r-sm);border:none;font-weight:740;font-size:15px;font-fami"
    "ly:inherit;cursor:pointer;margin-top:12px;}.btn:hover{filter:brightness(1.1);text-decoration:none"
    ";}.btn.secondary{background:var(--panel);color:var(--ink);border:1px solid var(--border-strong);}"
    ".pager{display:flex;gap:10px;margin:16px 0;font-size:16px;}.pager a{background:var(--panel);paddi"
    "ng:9px 18px;border-radius:var(--r-sm);border:1px solid var(--border-strong);font-weight:640;}.pag"
    "er a:hover{background:var(--panel-2);text-decoration:none;}.io-box{background:var(--panel);border"
    ":1px solid var(--border);border-radius:var(--r);padding:14px 16px;margin:10px 0;}.io-row{display:"
    "flex;gap:14px;padding:9px 4px;font-size:15px;border-bottom:1px solid var(--border);align-items:ce"
    "nter;}.io-row:last-child{border-bottom:none;}.io-idx{color:var(--faint);min-width:36px;font-weigh"
    "t:640;}.io-addr{flex:1;word-break:break-all;font-family:var(--mono);font-size:14px;}.io-va";
static const char site_css_3[] =
    "l{color:var(--ok);min-width:140px;text-align:right;font-weight:700;font-size:16px;}.price{color:v"
    "ar(--ok);font-size:20px;font-weight:700;}.addr{background:var(--bg);border:1px solid var(--border"
    ");padding:10px 12px;border-radius:var(--r-sm);word-break:break-all;font-family:var(--mono);font-s"
    "ize:13px;margin:10px 0;}.toc{position:sticky;top:0;z-index:10;background:var(--bg-raise);border:1"
    "px solid var(--border);border-radius:var(--r);padding:12px 16px;margin:16px 0;}.toc h3{margin:0 0"
    " 8px;font-size:15px;color:var(--muted);}.toc a{display:inline-block;margin:3px 10px 3px 0;font-si"
    "ze:14px;white-space:nowrap;}.back-to-top{position:fixed;right:20px;bottom:20px;z-index:20;backgro"
    "und:var(--panel);color:var(--ok);border:1px solid var(--border-strong);border-radius:var(--r-sm);"
    "padding:9px 13px;font-weight:700;font-size:14px;}.back-to-top:hover{background:var(--panel-2);tex"
    "t-decoration:none;color:var(--ink);}.hero{padding:40px 0 28px;}.eyebrow{margin:0 0 10px;color:var"
    "(--accent);font-size:13px;font-weight:740;text-transform:uppercase;letter-spacing:0.12em;}.lede{m"
    "ax-width:640px;color:var(--ink-dim);font-size:18px;}.feed{display:grid;gap:12px;margin:18px 0;}.p"
    "ost-card{display:block;padding:20px 22px;border:1px solid var(--border);border-radius:var(--r-lg)"
    ";background:var(--panel);color:var(--ink);transition:border-color 0.15s ease,transform 0.15s ease"
    ";}.post-card:hover{border-color:var(--accent);transform:translateY(-2px);text-decoration:none;}.p"
    "ost-card h3{margin:4px 0 6px;font-size:20px;}.post-card .meta,.meta{color:var(--muted);font-size:"
    "13px;}.identity{color:var(--accent);font-size:13px;font-weight:700;}.article{border:1px solid var"
    "(--border);border-radius:var(--r-lg);background:var(--panel);padding:28px 32px;margin:24px 0;}.ar"
    "ticle-body{padding:20px 0 8px;font-size:17px;}.article-body pre{margin:0;white-space:pre-wrap;ove"
    "rflow-wrap:anywhere;font:inherit;color:var(--ink-dim);}.proof{margin-top:20px;padding:20px;border"
    ":1px solid var(--border-strong);border-radius:var(--r-lg);background:var(--panel-2);}.proof-grid{"
    "display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px;margin-top:14px;}.proof-item{"
    "min-width:0;padding:14px;border:1px solid var(--border);border-radius:var(--r);background:var(--p"
    "anel);}.proof-label{display:flex;align-items:center;gap:8px;margin-bottom:5px;font-size:12px;font"
    "-weight:740;text-transform:uppercase;letter-spacing:0.08em;}.status-dot{width:8px;height:8px;bord"
    "er-radius:50%;background:currentColor;box-shadow:0 0 8px currentColor;}.good{color:var(--ok);}.ba"
    "d{color:var(--bad);}.pending-label{color:var(--warn);}.chips{display:flex;flex-wrap:wrap;gap:8px;"
    "}.chip{display:inline-flex;align-items:center;gap:6px;border:1px solid var(--border);border-radiu"
    "s:999px;background:var(--panel);padding:5px 11px;color:var(--ink-dim);font-size:13px;}svg text{fo"
    "nt-family:inherit;}footer{text-align:center;color:var(--muted);font-size:14px;margin-top:48px;pad"
    "ding:18px 16px;border-top:1px solid var(--border);}@media (max-width:768px){body{padding:1";
static const char site_css_4[] =
    "2px 14px 32px;font-size:16px;}h1{font-size:26px;}h2{font-size:20px;margin:24px 0 12px;}.site-top{"
    "gap:4px 10px;}.nav{padding:8px 10px;}.nav a{font-size:14px;padding:7px 9px;}.nav .search{flex:1 1"
    " 100%;min-width:unset;}.stats-row{flex-wrap:wrap;gap:10px;}.stats-row .stat{flex:1 1 45%;min-widt"
    "h:140px;}.stat .num{font-size:27px;}.stat .lbl{font-size:12px;}.grid{grid-template-columns:1fr;ga"
    "p:3px 0;}.grid .label{font-size:13px;margin-top:8px;}.grid .val{font-size:15px;}.card,.panel,.pro"
    "duct{padding:14px 16px;}table{display:block;width:max-content;max-width:100%;overflow-x:auto;-web"
    "kit-overflow-scrolling:touch;font-size:15px;}.table-wrap table{display:table;width:100%;overflow-"
    "x:visible;}th{padding:8px 8px;font-size:12px;}td{padding:8px 8px;}.hash{font-size:13px;}.mono{fon"
    "t-size:13px;}.pager{flex-wrap:wrap;}.pager a{padding:8px 14px;font-size:15px;flex:1;text-align:ce"
    "nter;}.io-row{flex-wrap:wrap;gap:4px;padding:8px 4px;}.io-idx{min-width:24px;}.io-addr{font-size:"
    "13px;min-width:100%;}.io-val{min-width:unset;font-size:15px;text-align:left;}.proof-grid{grid-tem"
    "plate-columns:1fr;}.article{padding:20px;}}@media (max-width:600px){.chaincards{flex-direction:co"
    "lumn;gap:10px;}.chaincard{flex:1 1 100%;min-width:0;}.stats-row{flex-direction:column;}.stats-row"
    " .stat{flex:1 1 100%;}.toc{position:static;}.back-to-top{right:12px;bottom:12px;padding:8px 12px;"
    "}}@media (max-width:480px){body{padding:8px 10px 24px;font-size:15px;}.stat .num{font-size:24px;}"
    "table{font-size:14px;}td,th{padding:6px 5px;}}@media (prefers-reduced-motion:reduce){html{scroll-"
    "behavior:auto;}*{transition:none !important;}}";

static char _site_css_buf[13599];
__attribute__((unused))
static const char *site_css_get(void) {
    size_t off = 0;
    size_t l0 = __builtin_strlen(site_css_0);
    __builtin_memcpy(_site_css_buf + off, site_css_0, l0); off += l0;
    size_t l1 = __builtin_strlen(site_css_1);
    __builtin_memcpy(_site_css_buf + off, site_css_1, l1); off += l1;
    size_t l2 = __builtin_strlen(site_css_2);
    __builtin_memcpy(_site_css_buf + off, site_css_2, l2); off += l2;
    size_t l3 = __builtin_strlen(site_css_3);
    __builtin_memcpy(_site_css_buf + off, site_css_3, l3); off += l3;
    size_t l4 = __builtin_strlen(site_css_4);
    __builtin_memcpy(_site_css_buf + off, site_css_4, l4); off += l4;
    _site_css_buf[off] = 0;
    return _site_css_buf;
}
#define site_css (site_css_get())

#endif
