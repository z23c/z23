/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ZCL Names (ZNAM) HTML site views. See views/name_view.h for the contract.
 *
 * Rendering only — the controller (contexts/explorer/controllers/src/name_site_controller.c)
 * owns routing, CSRF, the PoW gate, and the register tx-compose. The in-browser
 * proof-of-work solver below mirrors the store's (contexts/explorer/views/src/store_view.c):
 * SHA3-256(peer_id || ts_LE64 || nonce_LE64) must have FAST_SYNC_POW_BITS
 * leading zero bits — the exact predicate fast_sync_verify_pow() checks
 * server-side, so a solution found here verifies there. */

#include "views/name_view.h"
#include "views/site_css.h"                 /* site_css (design system) */
#include "views/site_layout.h"              /* shared head/nav/footer */
#include "controllers/name_controller.h"   /* znam_type_name */
#include "net/fast_sync.h"                  /* FAST_SYNC_POW_BITS */
#include "util/template.h"                  /* html_escape */

#include <stdio.h>
#include <string.h>

/* The two-part in-browser SHA3-256 PoW solver. Split into two string
 * literals to stay under ISO C99's 4095-char minimum translation limit
 * (-Woverlength-strings under -Werror); concatenated at point of use via
 * adjacent %s substitutions. Part 1 is a from-scratch keccak-f[1600] +
 * sha3_256; part 2 is the chunked nonce search + form wiring. Identical
 * algorithm to store_view.c's solver — the form id / solver symbol are
 * names-specific so the two never collide if both ever load together. */
static const char NAME_REG_POW_JS_1[] =
    "(function(){\n"
    "'use strict';\n"
    "var RHO=[0,1,62,28,27,36,44,6,55,20,3,10,43,25,39,41,45,15,21,8,18,2,61,56,14];\n"
    "var PI=[0,10,20,5,15,16,1,11,21,6,7,17,2,12,22,23,8,18,3,13,14,24,9,19,4];\n"
    "var RCLO=[0x1,0x8082,0x808a,0x80008000,0x808b,0x80000001,0x80008081,0x8009,0x8a,0x88,0x80008009,0x8000000a,0x8000808b,0x8b,0x8089,0x8003,0x8002,0x80,0x800a,0x8000000a,0x80008081,0x8080,0x80000001,0x80008008];\n"
    "var RCHI=[0,0,0x80000000,0x80000000,0,0,0x80000000,0x80000000,0,0,0,0,0,0x80000000,0x80000000,0x80000000,0x80000000,0x80000000,0,0x80000000,0x80000000,0x80000000,0,0x80000000];\n"
    "function rotl(lo,hi,n){\n"
    "  if(n===0) return [lo,hi];\n"
    "  if(n<32) return [((lo<<n)|(hi>>>(32-n)))>>>0,((hi<<n)|(lo>>>(32-n)))>>>0];\n"
    "  if(n===32) return [hi,lo];\n"
    "  var m=n-32;\n"
    "  return [((hi<<m)|(lo>>>(32-m)))>>>0,((lo<<m)|(hi>>>(32-m)))>>>0];\n"
    "}\n"
    "function keccakF1600(lo,hi){\n"
    "  var Clo=new Uint32Array(5),Chi=new Uint32Array(5),Dlo=new Uint32Array(5),Dhi=new Uint32Array(5);\n"
    "  var Blo=new Uint32Array(25),Bhi=new Uint32Array(25);\n"
    "  for(var round=0;round<24;round++){\n"
    "    for(var x=0;x<5;x++){\n"
    "      Clo[x]=lo[x]^lo[x+5]^lo[x+10]^lo[x+15]^lo[x+20];\n"
    "      Chi[x]=hi[x]^hi[x+5]^hi[x+10]^hi[x+15]^hi[x+20];\n"
    "    }\n"
    "    for(x=0;x<5;x++){\n"
    "      var r=rotl(Clo[(x+1)%5],Chi[(x+1)%5],1);\n"
    "      Dlo[x]=Clo[(x+4)%5]^r[0];\n"
    "      Dhi[x]=Chi[(x+4)%5]^r[1];\n"
    "    }\n"
    "    var i;\n"
    "    for(i=0;i<25;i++){ lo[i]^=Dlo[i%5]; hi[i]^=Dhi[i%5]; }\n"
    "    for(i=0;i<25;i++){\n"
    "      var rr=rotl(lo[i],hi[i],RHO[i]);\n"
    "      Blo[PI[i]]=rr[0]; Bhi[PI[i]]=rr[1];\n"
    "    }\n"
    "    for(var y=0;y<5;y++){\n"
    "      var base=5*y;\n"
    "      for(x=0;x<5;x++){\n"
    "        lo[base+x]=Blo[base+x]^((~Blo[base+(x+1)%5])&Blo[base+(x+2)%5]);\n"
    "        hi[base+x]=Bhi[base+x]^((~Bhi[base+(x+1)%5])&Bhi[base+(x+2)%5]);\n"
    "      }\n"
    "    }\n"
    "    lo[0]^=RCLO[round]; hi[0]^=RCHI[round];\n"
    "  }\n"
    "}\n"
    "var RATE=136;\n"
    "function sha3_256(bytes){\n"
    "  var lo=new Uint32Array(25),hi=new Uint32Array(25);\n"
    "  var padLen=RATE-(bytes.length%RATE);\n"
    "  var full=new Uint8Array(bytes.length+padLen);\n"
    "  full.set(bytes,0);\n"
    "  full[bytes.length]=0x06;\n"
    "  full[full.length-1]|=0x80;\n"
    "  for(var off=0;off<full.length;off+=RATE){\n"
    "    var i;\n"
    "    for(i=0;i<RATE/8;i++){\n"
    "      var o=off+i*8;\n"
    "      lo[i]^=(full[o]|(full[o+1]<<8)|(full[o+2]<<16)|(full[o+3]<<24))>>>0;\n"
    "      hi[i]^=(full[o+4]|(full[o+5]<<8)|(full[o+6]<<16)|(full[o+7]<<24))>>>0;\n"
    "    }\n"
    "    keccakF1600(lo,hi);\n"
    "  }\n"
    "  var out=new Uint8Array(32);\n"
    "  for(var j=0;j<4;j++){\n"
    "    var oo=j*8;\n"
    "    out[oo]=lo[j]&0xff; out[oo+1]=(lo[j]>>>8)&0xff; out[oo+2]=(lo[j]>>>16)&0xff; out[oo+3]=(lo[j]>>>24)&0xff;\n"
    "    out[oo+4]=hi[j]&0xff; out[oo+5]=(hi[j]>>>8)&0xff; out[oo+6]=(hi[j]>>>16)&0xff; out[oo+7]=(hi[j]>>>24)&0xff;\n"
    "  }\n"
    "  return out;\n"
    "}\n";

static const char NAME_REG_POW_JS_2[] =
    "function hexToBytes(hex){\n"
    "  var out=new Uint8Array(hex.length/2);\n"
    "  for(var i=0;i<out.length;i++) out[i]=parseInt(hex.substr(i*2,2),16);\n"
    "  return out;\n"
    "}\n"
    "function numToBytesLE(num,n){\n"
    "  var out=new Uint8Array(n);\n"
    "  for(var i=0;i<n;i++){ out[i]=num%256; num=Math.floor(num/256); }\n"
    "  return out;\n"
    "}\n"
    "function leadingZeroBitsOk(hash,bits){\n"
    "  var fullBytes=Math.floor(bits/8);\n"
    "  for(var i=0;i<fullBytes;i++) if(hash[i]!==0) return false;\n"
    "  var rem=bits%8;\n"
    "  if(rem>0){\n"
    "    var mask=(0xff<<(8-rem))&0xff;\n"
    "    if(hash[fullBytes]&mask) return false;\n"
    "  }\n"
    "  return true;\n"
    "}\n"
    "function strBytes(s){\n"
    "  var o=new Uint8Array(s.length);\n"
    "  for(var i=0;i<s.length;i++) o[i]=s.charCodeAt(i)&0xff;\n"
    "  return o;\n"
    "}\n"
    "function namePowSolveChunked(nameVal,ts,bits,statusEl,onDone){\n"
    "  var peer=sha3_256(strBytes('znam:register:pow:'+nameVal));\n"
    "  var tsBytes=numToBytesLE(ts,8);\n"
    "  var buf=new Uint8Array(48);\n"
    "  buf.set(peer,0);\n"
    "  buf.set(tsBytes,32);\n"
    "  var nonce=0;\n"
    "  var startTime=Date.now();\n"
    "  function step(){\n"
    "    var chunkEnd=nonce+20000;\n"
    "    for(;nonce<chunkEnd;nonce++){\n"
    "      var nb=numToBytesLE(nonce,8);\n"
    "      buf.set(nb,40);\n"
    "      var h=sha3_256(buf);\n"
    "      if(leadingZeroBitsOk(h,bits)){\n"
    "        onDone(nonce);\n"
    "        return;\n"
    "      }\n"
    "    }\n"
    "    if(statusEl) statusEl.textContent='Solving proof-of-work... '+nonce+' tries, '+((Date.now()-startTime)/1000).toFixed(1)+'s';\n"
    "    setTimeout(step,0);\n"
    "  }\n"
    "  step();\n"
    "}\n"
    "document.addEventListener('DOMContentLoaded',function(){\n"
    "  var form=document.getElementById('nameRegForm');\n"
    "  if(!form) return;\n"
    "  form.addEventListener('submit',function(ev){\n"
    "    var nonceField=document.getElementById('pow_nonce_field');\n"
    "    if(nonceField.value) return;\n"
    "    ev.preventDefault();\n"
    "    var btn=document.getElementById('regBtn');\n"
    "    var status=document.getElementById('powStatus');\n"
    "    if(btn) btn.disabled=true;\n"
    "    var nameVal=(form.elements['name'].value||'').trim();\n"
    "    var ts=parseInt(form.getAttribute('data-pow-ts'),10);\n"
    "    var bits=parseInt(form.getAttribute('data-pow-bits'),10);\n"
    "    namePowSolveChunked(nameVal,ts,bits,status,function(nonce){\n"
    "      nonceField.value=String(nonce);\n"
    "      if(status) status.textContent='Proof-of-work solved ('+nonce+' tries). Submitting...';\n"
    "      form.submit();\n"
    "    });\n"
    "  });\n"
    "});\n"
    "})();\n";

/* ── HTTP wrappers ──────────────────────────────────────────────── */

static size_t name_wrap_response(const char *body, size_t body_len,
                                 const char *status, uint8_t *resp, size_t max)
{
    return (size_t)snprintf((char *)resp, max,
        "HTTP/1.1 %s\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n\r\n"
        "%.*s",
        status, body_len, (int)body_len, body);
}

size_t name_html_response(const char *body, size_t body_len,
                          uint8_t *resp, size_t max)
{
    return name_wrap_response(body, body_len, "200 OK", resp, max);
}

size_t name_error_response(const char *status_code,
                           const char *body, size_t body_len,
                           uint8_t *resp, size_t max)
{
    return name_wrap_response(body, body_len, status_code, resp, max);
}

/* ── Page shell ─────────────────────────────────────────────────── */

/* Shared document open: design-system head (site_css inlined — one round
 * trip over the onion) + global site nav + the Names section subnav.
 * Pages close with name_body_end(). */
static int name_body_start(char *buf, size_t max, const char *title)
{
    size_t off = site_emit_head(buf, max, title, site_css, "measure");
    off += site_emit_global_nav(buf + off, max - off, "names");
    SITE_APPEND(off, buf, max,
        "<nav class='nav' aria-label='Names sections'>"
        "<a href='/names'>Browse</a>"
        "<a href='/names/register'>Register</a>"
        "</nav>"
        "<main id='content'>");
    return (int)off;
}

static int name_body_end(char *buf, size_t max)
{
    size_t off = 0;
    SITE_APPEND(off, buf, max, "</main>");
    off += site_emit_footer(buf + off, max - off, NULL);
    return (int)off;
}

int name_view_body_end(char *buf, size_t max)
{
    return name_body_end(buf, max);
}

/* ── Index ──────────────────────────────────────────────────────── */

size_t name_view_index(const struct znam_entry *entries, int count,
                       int total, uint8_t *resp, size_t max)
{
    char body[36864];
    size_t off = 0;
    int n = name_body_start(body, sizeof(body), "ZCL Names");
    if (n > 0) off = (size_t)n;

    /* The headline states the registry's real size, not how many rows
     * this page chose to render — a wrong total here reads as fact. An
     * unreadable store keeps the number off the page entirely rather
     * than printing the window and implying it is everything. */
    int shown = 0;
    if (total < 0) {
        n = snprintf(body + off, sizeof(body) - off,
            "<h1>ZCL Names</h1>"
            "<p>A name is a sovereign identity for the "
            "sites this node hosts over onion + HTTPS. Visit "
            "<code>/n/&lt;name&gt;</code> to resolve one.</p>");
    } else {
        n = snprintf(body + off, sizeof(body) - off,
            "<h1>ZCL Names</h1>"
            "<p>%d registered name%s. A name is a sovereign identity for the "
            "sites this node hosts over onion + HTTPS. Visit "
            "<code>/n/&lt;name&gt;</code> to resolve one.</p>",
            total, total == 1 ? "" : "s");
    }
    if (n > 0) off += (size_t)n;

    for (int i = 0; i < count && off < sizeof(body) - 512; i++) {
        char safe_name[128], safe_owner[128], safe_val[280];
        html_escape(safe_name, sizeof(safe_name), entries[i].name);
        html_escape(safe_owner, sizeof(safe_owner), entries[i].owner_address);
        html_escape(safe_val, sizeof(safe_val), entries[i].target_value);
        n = snprintf(body + off, sizeof(body) - off,
            "<div class='card'>"
            "<h3><a href='/names/%s'>%s</a></h3>"
            "<div class='kv'><b>%s</b><span class='val mono'>%s</span></div>"
            "<div class='kv'><b>owner</b><span class='val mono'>%s</span></div>"
            "<div class='kv'><b>registered</b><span class='val'>h=%d</span></div>"
            "<a href='/n/%s'>open site &rarr;</a>"
            "</div>",
            safe_name, safe_name,
            znam_type_name(entries[i].target_type), safe_val,
            safe_owner, entries[i].reg_height, safe_name);
        if (n > 0) off += (size_t)n;
        shown++;
    }

    /* Same window honesty as the profile page: the listing is newest-
     * first and bounded, so say so when it stopped short of the total. */
    if (total >= 0 && total > shown) {
        n = snprintf(body + off, sizeof(body) - off,
            "<p class='muted'>Showing the %d most recently "
            "registered.</p>", shown);
        if (n > 0) off += (size_t)n;
    }

    n = name_body_end(body + off, sizeof(body) - off);
    if (n > 0) off += (size_t)n;
    return name_html_response(body, off, resp, max);
}

/* ── Profile / default site ─────────────────────────────────────── */

/* The "this name changed at height N" card — the argument that beats a
 * certificate authority. A CA can be quietly coerced into re-issuing and
 * nobody outside sees it; every line here is a transaction at a height
 * that anybody can go read for themselves, which is why each one links to
 * the explorer rather than asking the visitor to take this node's word. */
static size_t name_emit_history(char *buf, size_t max,
                                const struct name_history *h)
{
    size_t off = 0;
    if (!h) return 0;

    SITE_APPEND(off, buf, max,
        "<div class='card'><h2>On-chain history</h2>"
        "<p class='meta'>Every change to this name is a transaction in the "
        "ZClassic blockchain. A certificate authority can be quietly "
        "pressured into re-issuing and nobody outside ever sees it; this "
        "record cannot change without a new transaction at a new height, "
        "in public, forever.</p>"
        "<div class='kv'><b>registered</b><span class='val'>block %d &middot; "
        "<a class='mono' href='/explorer/tx/%s'>%s</a></span></div>",
        h->reg_height, h->reg_txid_hex, h->reg_txid_hex);

    if (!h->changed) {
        SITE_APPEND(off, buf, max,
            "<div class='kv'><b>changes since</b>"
            "<span class='val'>none — the registration is still the last "
            "word on this name</span></div>");
    } else if (h->last_change_height >= 0) {
        SITE_APPEND(off, buf, max,
            "<div class='kv'><b>last changed</b><span class='val'>block %d "
            "&middot; <a class='mono' href='/explorer/tx/%s'>%s</a>"
            "</span></div>",
            h->last_change_height, h->last_change_txid_hex,
            h->last_change_txid_hex);
    } else {
        /* Honest about the gap: this node knows WHICH transaction changed
         * the name but not what height it landed at, because that tx is
         * not in its transaction index. Never guess a height. */
        SITE_APPEND(off, buf, max,
            "<div class='kv'><b>last changed</b><span class='val'>"
            "<a class='mono' href='/explorer/tx/%s'>%s</a> &middot; height "
            "not known to this node (no transaction index)</span></div>",
            h->last_change_txid_hex, h->last_change_txid_hex);
    }

    if (h->expiry_height > 0)
        SITE_APPEND(off, buf, max,
            "<div class='kv'><b>registration term ends</b>"
            "<span class='val'>block %d</span></div>", h->expiry_height);
    SITE_APPEND(off, buf, max, "</div>");
    return off;
}

size_t name_view_profile(const struct znam_entry *e,
                         const struct znam_text_record *text, int ntext,
                         int total_text,
                         const struct znam_addr_record *addr, int naddr,
                         int total_addr,
                         const struct name_history *hist,
                         uint8_t *resp, size_t max)
{
    char body[24576];
    size_t off = 0;
    char safe_name[128];
    html_escape(safe_name, sizeof(safe_name), e->name);

    int n = name_body_start(body, sizeof(body), safe_name);
    if (n > 0) off = (size_t)n;

    char safe_owner[128], safe_val[280];
    html_escape(safe_owner, sizeof(safe_owner), e->owner_address);
    html_escape(safe_val, sizeof(safe_val), e->target_value);

    char expires[32];
    if (e->expiry_height > 0)
        snprintf(expires, sizeof(expires), "h=%d", e->expiry_height);
    else
        snprintf(expires, sizeof(expires), "never");

    n = snprintf(body + off, sizeof(body) - off,
        "<h1>%s</h1>"
        "<div class='card'>"
        "<div class='kv'><b>primary %s</b><span class='val mono'>%s</span></div>"
        "<div class='kv'><b>owner</b><span class='val mono'>%s</span></div>"
        "<div class='kv'><b>registered</b><span class='val'>h=%d</span></div>"
        "<div class='kv'><b>expires</b><span class='val'>%s</span></div>"
        "</div>",
        safe_name, znam_type_name(e->target_type), safe_val,
        safe_owner, e->reg_height, expires);
    if (n > 0) off += (size_t)n;

    if (ntext > 0 || naddr > 0) {
        n = snprintf(body + off, sizeof(body) - off,
            "<div class='card'><h2>Records</h2>");
        if (n > 0) off += (size_t)n;
        /* Count what actually rendered: the row loop also stops when the
         * body buffer runs short of headroom, so a page can show fewer
         * rows than even its own window arrays hold. The totals are what
         * the disclosure below is measured against. */
        int shown_text = 0, shown_addr = 0;
        for (int i = 0; i < ntext && off < sizeof(body) - 512; i++) {
            char sk[96], sv[280];
            html_escape(sk, sizeof(sk), text[i].key);
            html_escape(sv, sizeof(sv), text[i].value);
            n = snprintf(body + off, sizeof(body) - off,
                "<div class='kv'><b>%s</b><span class='val mono'>%s</span></div>",
                sk, sv);
            if (n > 0) off += (size_t)n;
            shown_text++;
        }
        for (int i = 0; i < naddr && off < sizeof(body) - 512; i++) {
            char sv[280];
            html_escape(sv, sizeof(sv), addr[i].address);
            n = snprintf(body + off, sizeof(body) - off,
                "<div class='kv'><b>%s</b><span class='val mono'>%s</span></div>",
                znam_type_name(addr[i].coin_type), sv);
            if (n > 0) off += (size_t)n;
            shown_addr++;
        }
        /* Window honesty: when fewer records rendered than the name
         * actually carries, say exactly how many were left out instead of
         * letting the page imply completeness. Both truncation causes
         * funnel through here — the listing window in the controller and
         * this buffer's own headroom guard. */
        if (total_text >= 0 && total_text > shown_text) {
            n = snprintf(body + off, sizeof(body) - off,
                "<p class='muted'>Showing the first %d of %d text "
                "records.</p>", shown_text, total_text);
            if (n > 0) off += (size_t)n;
        }
        if (total_addr >= 0 && total_addr > shown_addr) {
            n = snprintf(body + off, sizeof(body) - off,
                "<p class='muted'>Showing the first %d of %d address "
                "records.</p>", shown_addr, total_addr);
            if (n > 0) off += (size_t)n;
        }
        n = snprintf(body + off, sizeof(body) - off, "</div>");
        if (n > 0) off += (size_t)n;
    }

    off += name_emit_history(body + off, sizeof(body) - off, hist);

    n = snprintf(body + off, sizeof(body) - off,
        "<p><a href='/n/%s'>open site</a> &middot; "
        "<a href='/names'>&larr; all names</a></p>",
        safe_name);
    if (n > 0) off += (size_t)n;
    n = name_body_end(body + off, sizeof(body) - off);
    if (n > 0) off += (size_t)n;
    return name_html_response(body, off, resp, max);
}

/* ── Register form ──────────────────────────────────────────────── */

size_t name_view_register_form(const char *csrf_tok, int64_t pow_ts,
                               uint8_t *resp, size_t max)
{
    char body[32768];
    size_t off = 0;
    int n = name_body_start(body, sizeof(body), "Register a ZCL Name");
    if (n > 0) off = (size_t)n;

    n = snprintf(body + off, sizeof(body) - off,
        "<h1>Register a ZCL Name</h1>"
        "<div class='card'>"
        "<p>A name (1-63 chars, lowercase letters, digits and hyphens) is "
        "registered by an OP_RETURN transaction broadcast from this node's "
        "wallet. First-come-first-served. Solving a one-time proof-of-work "
        "puzzle in your browser gates the broadcast against floods.</p>"
        "<form id='nameRegForm' method='post' action='/names/register' "
        "data-pow-ts='%lld' data-pow-bits='%d'>"
        "<input type='hidden' name='csrf_token' value='%s'>"
        "<input type='hidden' name='pow_ts' value='%lld'>"
        "<input type='hidden' name='pow_nonce' id='pow_nonce_field' value=''>"
        "<label for='nameRegName'>Name</label>"
        "<input type='text' id='nameRegName' name='name' placeholder='alice' required>"
        "<label for='nameRegType'>Target type</label>"
        "<select id='nameRegType' name='type'>"
        "<option value='onion'>onion (.onion site)</option>"
        "<option value='taddr'>taddr (t-address)</option>"
        "<option value='zaddr'>zaddr (z-address)</option>"
        "<option value='btc'>btc</option>"
        "<option value='ltc'>ltc</option>"
        "<option value='doge'>doge</option>"
        "<option value='content'>content (file-market hash)</option>"
        "</select>"
        "<label for='nameRegValue'>Target value</label>"
        "<input type='text' id='nameRegValue' name='value' placeholder='abc123....onion' required>"
        "<br>"
        "<button type='submit' class='btn' id='regBtn'>Register</button>"
        "<p id='powStatus' class='meta'></p>"
        "<noscript><p class='pill pill-warn'>JavaScript is required to solve the "
        "anti-flood proof-of-work puzzle. Scripted clients may solve it "
        "directly: SHA3-256(peer_id || timestamp || nonce) must have %d "
        "leading zero bits, where peer_id=SHA3-256(\"znam:register:pow:\" || "
        "name) and timestamp is the pow_ts value; submit the winning nonce as "
        "pow_nonce.</p></noscript>"
        "</form></div>"
        "<script>%s%s</script>",
        (long long)pow_ts, FAST_SYNC_POW_BITS,
        csrf_tok, (long long)pow_ts,
        FAST_SYNC_POW_BITS,
        NAME_REG_POW_JS_1, NAME_REG_POW_JS_2);
    if (n > 0) off += (size_t)n;
    n = name_body_end(body + off, sizeof(body) - off);
    if (n > 0) off += (size_t)n;
    return name_html_response(body, off, resp, max);
}

size_t name_view_register_result(const char *name, const char *value,
                                 const char *txid, const char *err,
                                 uint8_t *resp, size_t max)
{
    char body[20480];
    size_t off = 0;
    int n = name_body_start(body, sizeof(body), "Registration");
    if (n > 0) off = (size_t)n;

    char safe_name[128], safe_val[280];
    html_escape(safe_name, sizeof(safe_name), name ? name : "");
    html_escape(safe_val, sizeof(safe_val), value ? value : "");

    if (txid && txid[0]) {
        char safe_txid[80];
        html_escape(safe_txid, sizeof(safe_txid), txid);
        n = snprintf(body + off, sizeof(body) - off,
            "<h1>Registration</h1>"
            "<div class='card'><h3>Broadcast <span class='pill pill-ok'>sent</span></h3>"
            "<div class='kv'><b>name</b><span class='val mono'>%s</span></div>"
            "<div class='kv'><b>value</b><span class='val mono'>%s</span></div>"
            "<div class='kv'><b>txid</b><span class='val mono'>%s</span></div>"
            "<p>The registration confirms when the transaction is mined and "
            "the ZNAM projection folds it. Then <a href='/names/%s'>its "
            "profile</a> and <code>/n/%s</code> resolve.</p></div>",
            safe_name, safe_val, safe_txid, safe_name, safe_name);
    } else {
        char safe_err[512];
        html_escape(safe_err, sizeof(safe_err), err ? err : "unknown error");
        n = snprintf(body + off, sizeof(body) - off,
            "<h1>Registration</h1>"
            "<div class='card'><h3>Not registered <span class='pill pill-bad'>failed</span></h3>"
            "<p class='bad'>%s</p>"
            "<p><a href='/names/register'>&larr; try again</a></p></div>",
            safe_err);
    }
    if (n > 0) off += (size_t)n;
    n = name_body_end(body + off, sizeof(body) - off);
    if (n > 0) off += (size_t)n;
    return name_html_response(body, off, resp, max);
}

/* ── Resolution failure (the error taxonomy) ────────────────────── */

/* Headline per verdict. "Name not found" is deliberately gone: it was the
 * one string that made three different situations look like one. */
static const char *name_error_headline(enum name_resolve_status s)
{
    switch (s) {
    case NAME_RESOLVE_MALFORMED:            return "That is not a name";
    case NAME_RESOLVE_ABSENT:               return "Nobody has claimed this name";
    case NAME_RESOLVE_NO_SUCH_TARGET:       return "Registered, but not for that";
    case NAME_RESOLVE_TYPE_UNKNOWN:         return "No such target type";
    case NAME_RESOLVE_REGISTRY_UNAVAILABLE: return "Cannot look that up right now";
    case NAME_RESOLVE_OK:                   break;
    }
    return "Name";
}

/* Response wrapper carrying the machine-readable verdict as a header, so a
 * scripted client never has to scrape the page to tell the cases apart. */
static size_t name_coded_error_response(const char *status_code,
                                        const char *code,
                                        const char *body, size_t body_len,
                                        uint8_t *resp, size_t max)
{
    int hn = snprintf((char *)resp, max,
        "HTTP/1.1 %s\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "Content-Length: %zu\r\n"
        "X-ZCL-Name-Error: %s\r\n"
        "Cache-Control: no-store\r\n"
        "Connection: close\r\n\r\n",
        status_code, body_len, code);
    if (hn <= 0 || (size_t)hn >= max) return 0;
    if ((size_t)hn + body_len > max) return 0;
    memcpy(resp + hn, body, body_len);
    return (size_t)hn + body_len;
}

size_t name_view_resolve_error(const char *name,
                               enum name_resolve_status status,
                               const char *requested_type,
                               const struct znam_entry *entry,
                               uint8_t *resp, size_t max)
{
    char body[20480];
    char safe_name[128], safe_type[64];
    size_t off = 0;
    int n;

    html_escape(safe_name, sizeof(safe_name), name ? name : "");
    html_escape(safe_type, sizeof(safe_type), requested_type ? requested_type : "");

    n = name_body_start(body, sizeof(body), name_error_headline(status));
    if (n > 0) off = (size_t)n;

    n = snprintf(body + off, sizeof(body) - off,
        "<h1>%s</h1>"
        "<div class='card'>"
        "<div class='kv'><b>name</b><span class='val mono'>%s</span></div>"
        "<div class='kv'><b>reason</b><span class='val mono'>%s</span></div>"
        "<p>%s</p>",
        name_error_headline(status), safe_name[0] ? safe_name : "(empty)",
        name_resolve_status_code(status), name_resolve_status_message(status));
    if (n > 0) off += (size_t)n;

    if (safe_type[0]) {
        n = snprintf(body + off, sizeof(body) - off,
            "<div class='kv'><b>asked for</b><span class='val mono'>%s</span>"
            "</div>", safe_type);
        if (n > 0) off += (size_t)n;
    }

    /* Registered-but-wrong-type is the case with somebody to go ask, so it
     * gets the owner and the record the name DOES carry. */
    if (status == NAME_RESOLVE_NO_SUCH_TARGET && entry) {
        char safe_owner[128], safe_val[280];
        html_escape(safe_owner, sizeof(safe_owner), entry->owner_address);
        html_escape(safe_val, sizeof(safe_val), entry->target_value);
        n = snprintf(body + off, sizeof(body) - off,
            "<div class='kv'><b>owner</b><span class='val mono'>%s</span></div>"
            "<div class='kv'><b>does have</b><span class='val mono'>%s: %s"
            "</span></div>"
            "<p><a href='/names/%s'>See everything this name publishes</a>"
            "</p>",
            safe_owner, znam_type_name(entry->target_type), safe_val,
            safe_name);
        if (n > 0) off += (size_t)n;
    } else if (status == NAME_RESOLVE_ABSENT) {
        n = snprintf(body + off, sizeof(body) - off,
            "<p><a href='/names/register'>Claim <b>%s</b></a> — it is "
            "first-come-first-served.</p>", safe_name);
        if (n > 0) off += (size_t)n;
    }

    n = snprintf(body + off, sizeof(body) - off,
        "<p><a href='/names'>&larr; all names</a></p></div>");
    if (n > 0) off += (size_t)n;
    n = name_body_end(body + off, sizeof(body) - off);
    if (n > 0) off += (size_t)n;

    return name_coded_error_response(name_resolve_status_http(status),
                                     name_resolve_status_code(status),
                                     body, off, resp, max);
}
