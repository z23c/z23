/* Auto-generated from .chtml and .css files -- do not edit.
 * Regenerate: make templates */

#ifndef ZCL_VIEWS_WALLET_TEMPLATES_GEN_H
#define ZCL_VIEWS_WALLET_TEMPLATES_GEN_H

static const char TMPL_BACK_TO_WALLET[] =
    "<div style='text-align:center;margin:16px'>\n<a href='/wallet' style='color:#60a5fa;font-size:16p"
    "x'>\nBack to Wallet</a></div>\n";

static const char TMPL_BACKUP_WARNING[] =
    "<div class='card' style='border-left-color:#f87171;margin:16px 0'>\n<div style='display:flex;alig"
    "n-items:center;gap:8px'>\n<span style='font-size:20px'>&#x26A0;</span>\n<div>\n<div style='color:"
    "#f87171;font-weight:700;font-size:14px'>\nBack Up Your Wallet</div>\n<div style='color:#888;font-"
    "size:14px'>\nPrivate keys are only on this device. Export to a safe location.</div>\n</div></div>"
    "\n<div style='margin-top:10px;font-size:13px;color:#555'>\nTerminal: <code>zcl-rpc dumpprivkey {{"
    "address}}</code></div>\n</div>\n";

static const char TMPL_BREADCRUMB[] =
    "<div style='margin-bottom:12px'>\n<a href='{{{parent_href}}}' style='color:#888;font-size:13px;\n"
    "text-decoration:none'>{{{parent_label}}} &#x2192;</a>\n<span style='color:#e2e2e2;font-size:13px;"
    "font-weight:600'>\n{{{current}}}</span></div>\n";

static const char TMPL_CHECKPOINT_ROW[] =
    "<tr><td><a href='/explorer/block/{{{height}}}'>{{{height}}}</a></td>\n<td>{{{time}}}</td>\n<td><c"
    "ode style='word-break:break-all'>{{{hash_short}}}...</code></td>\n<td><code>{{{receipt}}}</code><"
    "/td></tr>\n";

static const char TMPL_COINS_NO_NOTES[] =
    "<div class='card' style='border-left-color:#f59e0b'>\n<div class='label' style='color:#f59e0b'>\n"
    "No private notes found</div>\n<div style='color:#888;font-size:13px'>\n{{{sapling_keys}}} Sapling"
    " keys in wallet. \nRun <code style='color:#f59e0b'>rescanwallet</code> \nto scan the chain for no"
    "tes belonging to these keys.\n</div></div>\n";

static const char TMPL_COINS_NO_TOKENS[] =
    "<h3>ZSLP Tokens</h3>\n<div class='empty-state' style='padding:16px 0'>\nNo tokens held at wallet "
    "addresses</div>\n";

static const char TMPL_COINS_NOTES_TABLE[] =
    "<div class='overflow-x'>\n<table><tr><th>Amount</th>\n<th>Address</th><th>Count</th><th>Height Ra"
    "nge</th></tr>\n{{{note_rows}}}\n<tr class='total-row'>\n<td class='zcl'>{{{z_total}}}</td>\n<td><"
    "/td>\n<td>{{{z_notes}}} note{{{z_plural}}}</td>\n<td></td></tr></table></div>\n";

static const char TMPL_COINS_PAGE[] =
    "{{> breadcrumb}}\n\n<h2>Your Coins</h2>\n<div style='color:#6b7280;font-size:13px;margin-bottom:1"
    "6px'>\nEvery coin in your wallet, verified against the blockchain.</div>\n\n<h3>Public UTXOs (Cha"
    "in-Verified)</h3>\n<div class='overflow-x'>\n<table><tr><th>Transaction</th><th>Type</th>\n<th>Am"
    "ount</th><th>Height</th><th>Conf</th></tr>\n{{{utxo_rows}}}\n<tr class='total-row'>\n<td colspan="
    "'2'>Total ({{{t_count}}} UTXO{{{t_plural}}})</td>\n<td class='zcl'>{{{t_total}}}</td>\n<td></td><"
    "td></td></tr></table></div>\n\n<h3>Private Notes</h3>\n{{{notes_section}}}\n\n<div class='stats' "
    "style='margin-top:20px'>\n<div class='stat'>\n<div class='n'>{{{t_total}}}</div>\n<div class='l'>"
    "Public</div></div>\n<div class='stat' style='border-color:#a78bfa'>\n<div class='n' style='color:"
    "#a78bfa'>{{{z_total}}}</div>\n<div class='l'>Private</div></div>\n<div class='stat' style='border"
    "-color:#f59e0b'>\n<div class='n' style='color:#f59e0b'>{{{grand_total}}}</div>\n<div class='l'>To"
    "tal</div></div>\n</div>\n\n<details style='margin-top:16px'>\n<summary style='color:#999;font-siz"
    "e:13px;font-weight:600;\ntext-transform:uppercase;letter-spacing:.05em;cursor:pointer'>\nDiagnost"
    "ics &#x25BE;</summary>\n<div class='overflow-x'>\n<table><tr><th>Source</th><th>Balance</th>\n<th"
    ">UTXOs</th><th>Status</th></tr>\n<tr><td>Chain UTXO set (chain-verified)</td>\n<td class='zcl'>{{"
    "{t_total}}}</td><td>{{{t_count}}}</td>\n<td><span class='pill pill-t'>verified</span></td></tr>\n"
    "<tr><td>Cached balance</td>\n<td class='zcl'>{{{speed_bal}}}</td><td>{{{speed_utxos}}}</td>\n<td>"
    "{{{diag_status}}}</td></tr>\n</table></div></details>\n\n{{{token_section}}}\n\n<h3>Chain Supply<"
    "/h3>\n<div class='stats'>\n<div class='stat'>\n<div class='n'>{{{chain_supply}}}</div>\n<div clas"
    "s='l'>UTXO Supply (ZCL)</div></div>\n<div class='stat'>\n<div class='n'>{{{chain_utxos}}}</div>\n"
    "<div class='l'>Total UTXOs</div></div>\n</div>\n";

static const char TMPL_COINS_TOKENS[] =
    "<h3>ZSLP Tokens</h3>\n<div class='overflow-x'><table>\n<tr><th>Token</th><th>Name</th>\n<th>Balan"
    "ce</th></tr>\n{{{token_rows}}}\n</table></div>\n";

static const char TMPL_CONF_CONFIRMED[] =
    "<span class='tx-conf'>Block {{{block}}} &middot; {{{confs}}} confs</span>\n";

static const char TMPL_CONF_PENDING[] =
    "<span class='tx-conf pill pill-pending' style='font-size:13px'>Pending</span>\n";

static const char TMPL_DASHBOARD[] =
    "<div style='text-align:center;padding:24px 0 16px'>\n<span id='sync' class='pill {{{sync_class}}}"
    " sync-badge'>{{{sync_label}}}</span>\n<div id='bal' class='balance' style='margin-top:8px'>\n{{{b"
    "alance}}} ZCL</div>\n<div style='font-size:12px;color:#555;margin-top:2px'>\nYour node, your keys"
    ", your money</div>\n\n<div id='privacy-meter' style='margin:8px auto;max-width:280px'>\n<div styl"
    "e='display:flex;justify-content:space-between;\nfont-size:14px;margin-bottom:4px'>\n<span style='"
    "color:{{{pct_color}}}'>{{{pct}}}% private</span>\n{{{details_link}}}</div>\n<div style='height:6p"
    "x;background:#1e1e1e;border-radius:3px;\noverflow:hidden'>\n<div id='lock' style='height:100%;wid"
    "th:{{{pct}}}%;background:{{{pct_color}}};\nborder-radius:3px;transition:width .5s'></div>\n</div>"
    "</div>\n\n<div id='bal-details' style='text-align:center;margin:4px 0'>\n<span id='breakdown' cla"
    "ss='balance-sub' style='font-size:14px'>\n{{{breakdown}}}</span></div>\n</div>\n\n<div class='act"
    "ions'>\n<a href='/wallet/send' class='btn-secondary'\n style='display:flex;align-items:center;jus"
    "tify-content:center'>Send</a>\n<a href='/wallet/receive' class='btn-primary'\n style='display:fle"
    "x;align-items:center;justify-content:center'>Receive</a>\n</div>\n\n{{{privacy_card}}}\n\n{{{toke"
    "n_cards}}}\n\n<div class='section-header'>\n<span>Recent</span>\n<a href='/wallet/history'>View a"
    "ll</a></div>\n{{{recent_txs}}}\n\n<div style='display:grid;grid-template-columns:1fr 1fr;gap:8px;"
    "margin:12px 0'>\n<a href='/explorer' class='btn-secondary'\n style='text-align:center;padding:10p"
    "x;font-size:13px'>Block Explorer</a>\n<a href='/wallet/coins' class='btn-secondary'\n style='text"
    "-align:center;padding:10px;font-size:13px'>Coin Audit</a>\n</div>\n\n{{{backup_warning}}}\n\n{{{n"
    "ode_strip}}}\n";

static const char TMPL_EXPLORER_TX_ROW[] =
    "<tr><td>{{{index}}}</td>\n<td class='hash'><a href='/explorer/tx/{{{txid}}}'>{{{short_txid}}}</a>"
    "</td>\n<td>{{{type_tags}}}</td>\n<td>{{{inputs}}}</td><td>{{{outputs}}}</td>\n<td class='amount'>"
    "{{{value}}}</td></tr>\n";

static const char TMPL_HISTORY_CARD[] =
    "<a href='/wallet/tx/{{{txid}}}' style='text-decoration:none;color:inherit'>\n<div class='tx-card'"
    " style='border-left-color:{{{color}}}'>\n<div style='display:flex;justify-content:space-between;\n"
    "align-items:baseline'>\n<span class='tx-amount {{{amount_class}}}'>{{{sign}}}{{{amount}}} ZCL</sp"
    "an>\n<span class='pill {{{pill_class}}}'>{{{pill_label}}}</span></div>\n<div class='tx-meta'>\n<s"
    "pan class='tx-time' title='{{timestamp}}'>{{{rel_time}}}</span>\n</div></div></a>\n";

static const char TMPL_HISTORY_HEADER[] =
    "<h2>Transaction History</h2>\n<div class='filter-tabs'>\n<a href='/wallet/history?filter=all' cla"
    "ss='{{{all_active}}}'>All ({{{c_all}}})</a>\n<a href='/wallet/history?filter=sent' class='{{{sent"
    "_active}}}'>Sent ({{{c_sent}}})</a>\n<a href='/wallet/history?filter=recv' class='{{{recv_active}"
    "}}'>Received ({{{c_recv}}})</a>\n</div>\n<input class='search-input' type='text' id='tx-search' \n"
    "placeholder='Search by txid...' value='{{search}}' \naria-label='Search transactions'\nonkeydown="
    "'if(event.key===\"Enter\"){\nvar v=this.value.trim();\nwindow.location=\"/wallet/history?filter={"
    "{{filter}}}\"+\n(v?\"&amp;q=\"+v:\"\");}'>\n<div class='sub'>{{{count}}} transaction{{{count_plur"
    "al}}} \n(page {{{page}}} of {{{pages}}})</div>\n";

static const char TMPL_HISTORY_SHIELD[] =
    "<a href='/wallet/tx/{{{txid}}}' style='text-decoration:none;color:inherit'>\n<div class='tx-card'"
    " style='border-left-color:#a78bfa'>\n<div style='display:flex;justify-content:space-between;\nali"
    "gn-items:baseline'>\n<span style='color:#a78bfa;font-weight:700'>\n&#x1F512; Shielded</span>\n<sp"
    "an class='pill pill-private'>t &rarr; z</span></div>\n<div class='tx-meta'>\n<span class='tx-time"
    "' title='{{timestamp}}'>{{{rel_time}}}</span>\n</div></div></a>\n";

static const char TMPL_LOADING[] =
    "<div class='empty-state' style='padding:48px 0'>\n<div style='font-size:40px;margin-bottom:12px'>"
    "&#x23F3;</div>\n<div style='color:#e2e2e2;font-size:18px;font-weight:600'>\nWallet Loading</div>\n"
    "<div style='margin-top:8px'>\nThe database is not yet available.</div>\n</div>\n";

static const char TMPL_NODE_NO_TOR[] =
    "<h3>Tor Hidden Service</h3>\n<div style='background:#111;border:1px solid #1e1e1e;\nborder-radius"
    ":10px;padding:16px;margin:8px 0'>\n<div style='display:flex;align-items:center;gap:8px'>\n<div st"
    "yle='width:8px;height:8px;border-radius:50%;\nbackground:#666'></div>\n<span style='color:#666;fo"
    "nt-weight:700;font-size:14px'>\nNot configured</span></div>\n<div style='color:#555;font-size:13p"
    "x;margin-top:8px'>\nTor hidden service will start automatically when Tor is available.</div>\n</d"
    "iv>\n";

static const char TMPL_NODE_PAGE[] =
    "<h2 style='color:#34d399'>Command Center</h2>\n<div style='color:#888;font-size:14px;margin-botto"
    "m:16px'>\nYou are running a sovereign full node on the ZClassic network.</div>\n\n<div class='sta"
    "ts' style='margin-bottom:20px'>\n<div class='stat' style='border-left:3px solid #34d399'>\n<div c"
    "lass='n'>{{{height}}}</div>\n<div class='l'>Block Height</div></div>\n<div class='stat' style='bo"
    "rder-left:3px solid #a78bfa'>\n<div class='n' style='color:#a78bfa'>{{{peers}}}</div>\n<div class"
    "='l'>Connected Peers</div></div>\n<div class='stat' style='border-left:3px solid #fbbf24'>\n<div "
    "class='n' style='color:#fbbf24'>{{{mempool}}}</div>\n<div class='l'>Mempool TXs</div></div>\n<div"
    " class='stat' style='border-left:3px solid #60a5fa'>\n<div class='n' style='color:#60a5fa'>{{{dif"
    "ficulty}}}</div>\n<div class='l'>Difficulty</div></div>\n</div>\n\n<h3>Network Status</h3>\n<div "
    "class='detail-grid'>\n<div class='lbl'>Sync</div>\n<div class='val'><span class='pill {{{sync_cla"
    "ss}}}'>{{{sync_label}}}</span></div>\n<div class='lbl'>Chain</div>\n<div class='val'>ZClassic mai"
    "nnet (Equihash 192,7)</div>\n<div class='lbl'>Protocol</div>\n<div class='val'>NODE_NETWORK | NOD"
    "E_BLOOM | NODE_ZCL23</div>\n<div class='lbl'></div>\n<div class='val' style='color:#555;font-size"
    ":12px'>\nFull relay + validation. Every block verified independently.</div>\n<div class='lbl'>Ver"
    "sion</div>\n<div class='val' style='color:#34d399'>{{{version}}}</div>\n</div>\n\n{{{tor_section}"
    "}}\n\n<h3>Connected Peers</h3>\n{{{peer_table}}}\n\n<h3>Mempool</h3>\n<div class='detail-grid'>\n"
    "<div class='lbl'>Pending</div>\n<div class='val'>{{{mempool}}} transactions</div>\n<div class='lb"
    "l'>UTXO Set</div>\n<div class='val'>{{{utxo_count}}} outputs</div>\n<div class='lbl'>Supply</div>"
    "\n<div class='val'>{{{supply}}} ZCL</div>\n</div>\n\n<h3>Quick Actions</h3>\n<div style='display:"
    "grid;grid-template-columns:1fr 1fr;gap:8px;margin:8px 0'>\n<a href='/explorer' class='btn-seconda"
    "ry'\n style='text-align:center;padding:12px;font-size:14px'>Block Explorer</a>\n<a href='/wallet/"
    "coins' class='btn-secondary'\n style='text-align:center;padding:12px;font-size:14px'>Coin Audit</"
    "a>\n<a href='/explorer/tokens' class='btn-secondary'\n style='text-align:center;padding:12px;font"
    "-size:14px'>ZSLP Tokens</a>\n<a href='/explorer/stats' class='btn-secondary'\n style='text-align:"
    "center;padding:12px;font-size:14px'>Network Stats</a>\n</div>\n";

static const char TMPL_NODE_PEER_ROW[] =
    "<tr>\n<td class='hash' style='font-size:13px'>{{{addr}}}</td>\n<td><span class='pill {{{dir_class"
    "}}}'>{{{direction}}}</span></td>\n<td style='font-size:13px'>{{{subver}}}</td>\n<td style='font-s"
    "ize:13px;color:#888'>{{{height}}}</td>\n</tr>\n";

static const char TMPL_NODE_STATUS_STRIP[] =
    "<a href='/wallet/node' style='text-decoration:none;color:inherit'>\n<div style='display:flex;alig"
    "n-items:center;gap:10px;\nbackground:#111;border-radius:8px;padding:10px 14px;margin:4px 0;\nfont"
    "-size:13px;color:#888'>\n<span style='color:#34d399;font-weight:700'>Your Node</span>\n<span>{{{p"
    "eers}}} peers</span>\n<span>&middot;</span>\n<span>Block {{{height}}}</span>\n<span>&middot;</spa"
    "n>\n<span style='color:{{{status_color}}}'>{{{status}}}</span>\n<span style='margin-left:auto;col"
    "or:#60a5fa;font-size:12px'>\n&#x2192;</span>\n</div></a>\n";

static const char TMPL_NODE_TOR[] =
    "<h3>Tor Hidden Service</h3>\n<div style='background:linear-gradient(135deg,#0a1428,#1a0a28);\nbor"
    "der:1px solid #2a1a3a;border-radius:10px;padding:16px;margin:8px 0'>\n<div style='display:flex;al"
    "ign-items:center;gap:8px;margin-bottom:8px'>\n<div style='width:8px;height:8px;border-radius:50%;"
    "\nbackground:{{{tor_color}}}'></div>\n<span style='color:{{{tor_color}}};font-weight:700;font-siz"
    "e:14px'>\n{{{tor_status}}}</span></div>\n<div class='addr-display-sm' style='color:#a78bfa;font-s"
    "ize:12px'>\n{{{onion_addr}}}</div>\n<div style='color:#666;font-size:13px;margin-top:8px'>\nYour "
    "node serves blog, store, and web apps over Tor.\nOnly accessible via .onion address.</div>\n</div"
    ">\n";

static const char TMPL_PAGINATION[] =
    "<div class='page-controls'>\n{{{newer_link}}}\n{{{older_link}}}\n</div>\n";

static const char TMPL_PRIVACY_NUDGE[] =
    "<div class='privacy-card' style='display:flex;align-items:center;\ngap:12px;text-align:left'>\n<d"
    "iv style='flex:1'>\n<div class='title' style='margin:0'>{{{amount}}} ZCL in transparent addresses"
    "</div>\n<div class='desc' style='margin:0;margin-top:2px'>\nExposed to chain analysis. Shield to "
    "a z-address to break the link.</div></div>\n<a class='btn' href='/wallet/shield?all=1'\nstyle='wh"
    "ite-space:nowrap;padding:10px 16px'>Shield All</a>\n</div>\n";

static const char TMPL_RECEIVE_COPY_JS[] =
    "<script>\nfunction copyAddr(){\nvar el=document.getElementById('t-addr');\nif(!el)return;\nvar tx"
    "t=el.textContent.replace(/\\s+/g,'').trim();\nnavigator.clipboard.writeText(txt).then(function(){"
    "\nvar b=document.getElementById('copy-btn');\nif(b){b.textContent='Copied!';b.style.borderColor='"
    "#34d399';\nsetTimeout(function(){b.textContent='Copy Address';\nb.style.borderColor='';},1500);}\n"
    "}).catch(function(){\nvar ta=document.createElement('textarea');\nta.value=txt;ta.style.position="
    "'fixed';ta.style.left='-9999px';\ndocument.body.appendChild(ta);ta.select();\ndocument.execComman"
    "d('copy');document.body.removeChild(ta);\nvar b=document.getElementById('copy-btn');\nif(b)b.text"
    "Content='Copied!';});}\ndocument.querySelectorAll('.addr-display,.addr-display-sm,.addr-chunked')"
    "\n.forEach(function(el){\nel.style.cursor='pointer';\nel.addEventListener('click',function(){\nva"
    "r txt=this.textContent.replace(/\\s+/g,'').trim();\nnavigator.clipboard.writeText(txt).then(funct"
    "ion(){\nel.style.borderColor='#34d399';\nvar msg=document.getElementById('copy-msg')||\ndocument."
    "getElementById('copy-msg-z');\nvar pz=document.getElementById('pane-z');\nif(pz&&pz.style.display"
    "!=='none')\nmsg=document.getElementById('copy-msg-z');\nif(msg)msg.textContent='Copied!';\nsetTim"
    "eout(function(){el.style.borderColor='';\nif(msg)msg.textContent='';},1500);}\n).catch(function()"
    "{\nvar ta=document.createElement('textarea');\nta.value=txt;ta.style.position='fixed';ta.style.le"
    "ft='-9999px';\ndocument.body.appendChild(ta);ta.select();\ndocument.execCommand('copy');document."
    "body.removeChild(ta);\nvar msg=document.getElementById('copy-msg')||\ndocument.getElementById('co"
    "py-msg-z');\nif(msg)msg.textContent='Copied!';});\n});});\n</script>\n";

static const char TMPL_RECEIVE_JS[] =
    "<script>\nfunction showTab(t){\ndocument.getElementById('pane-t').style.display=t==='t'?'':'none'"
    ";\ndocument.getElementById('pane-z').style.display=t==='z'?'':'none';\ndocument.getElementById('t"
    "ab-t').className=t==='t'?'active':'';\ndocument.getElementById('tab-z').className=t==='z'?'active"
    "-z':'';}\n</script>\n";

static const char TMPL_RECEIVE_NO_ZADDR[] =
    "<div class='empty-state'>\n<div style='color:#a78bfa;font-size:14px'>\nNo private addresses yet</"
    "div>\n<div style='color:#888;font-size:14px;margin-top:4px'>\nGenerate one: <code>zcl-rpc z_getne"
    "waddress</code></div>\n</div>\n";

static const char TMPL_RECEIVE_TABS[] =
    "<div class='tab-toggle'>\n<a id='tab-z' class='active-z' onclick='showTab(\"z\")'>Private (recomm"
    "ended)</a>\n<a id='tab-t' onclick='showTab(\"t\")'>Public</a>\n</div>\n";

static const char TMPL_RECEIVE_TPANE[] =
    "<div id='pane-t' style='display:none;text-align:center;padding:16px 0'>\n<div class='balance-sub'"
    " style='margin-bottom:4px'>\nTransparent t-address</div>\n<div style='color:#fbbf24;font-size:12p"
    "x;margin-bottom:12px'>\nBalance and transactions visible on-chain. Use when sender\ndoes not supp"
    "ort shielded addresses.</div>\n{{{qr_svg}}}\n{{{chunked_addr}}}\n<button onclick='copyAddr()' cla"
    "ss='btn-secondary'\n style='margin:12px auto;padding:10px 24px;width:auto;font-size:14px'\n id='c"
    "opy-btn'>Copy Address</button>\n<div id='copy-msg' style='color:#888;font-size:13px;\nmargin-top:"
    "4px;height:16px'></div>\n</div>\n";

static const char TMPL_RECEIVE_ZPANE_CLOSE[] =
    "<div id='copy-msg-z' style='color:#888;font-size:14px;\nmargin-top:4px;height:16px'>Click to copy"
    "</div>\n</div>\n";

static const char TMPL_RECEIVE_ZPANE_OPEN[] =
    "<div id='pane-z' style='text-align:center;padding:16px 0'>\n<div class='balance-sub' style='margi"
    "n-bottom:4px'>\nSapling z-address (shielded)</div>\n<div style='color:#34d399;font-size:12px;marg"
    "in-bottom:12px'>\nAmount, sender, and recipient hidden by zero-knowledge proof</div>\n";

static const char TMPL_SEND_CONFIRM_BUTTONS[] =
    "<div style='display:flex;gap:10px;margin:20px 0'>\n<a href='/wallet/send' class='btn-secondary'\n"
    "style='flex:1;text-align:center;text-decoration:none;\ndisplay:flex;align-items:center;justify-co"
    "ntent:center'>Cancel</a>\n<form method='POST' action='zcl://node/wallet/send/confirm'\nstyle='fle"
    "x:2;margin:0'>\n<input type='hidden' name='address' value='{{address}}'>\n<input type='hidden' na"
    "me='amount' value='{{{amount}}}'>\n<button type='submit' class='btn-primary'\n style='background:"
    "{{{btn_color}}};color:{{{btn_text}}}'\n id='confirm-btn'>\nConfirm Send</button></form></div>\n<d"
    "iv id='send-loading' class='loading-overlay' style='display:none'>\n<div class='spinner'></div>\n"
    "<p>Sending transaction...</p></div>\n<script>\ndocument.getElementById('confirm-btn').addEventLis"
    "tener('click',\nfunction(e){e.preventDefault();this.disabled=true;\ndocument.getElementById('send"
    "-loading').style.display='flex';\nthis.form.submit();});\n</script>\n";

static const char TMPL_SEND_ERROR[] =
    "<div class='result-error'>\n<div class='icon'>&#x2717;</div>\n<h2>{{{heading}}}</h2>\n<p>{{messag"
    "e}}</p>\n<div style='margin-top:16px;display:flex;gap:16px;justify-content:center'>\n<a href='/wa"
    "llet' style='color:#999'>Back to Wallet</a>\n<a href='/wallet/send' style='color:#34d399'>Try Aga"
    "in</a>\n</div></div>\n";

static const char TMPL_SEND_REVIEW[] =
    "{{> breadcrumb}}\n\n<div style='text-align:center;margin-bottom:16px'>\n<span class='form-label'>"
    "Review Transaction</span></div>\n<table class='review-table'>\n<tr><td>To</td>\n<td style='color:"
    "#60a5fa;font-family:\"JetBrains Mono\",monospace;\nfont-size:14px;word-break:break-all'>{{address"
    "}}</td></tr>\n<tr><td>Amount</td>\n<td style='color:#34d399;font-size:18px;font-weight:700'>\n{{{"
    "amount}}} ZCL</td></tr>\n<tr><td>Fee</td>\n<td style='color:#999'>{{{fee}}} ZCL</td></tr>\n<tr><t"
    "d style='font-weight:700'>Total</td>\n<td style='color:#e2e2e2;font-weight:700'>\n{{{total}}} ZCL"
    "</td></tr>\n<tr><td>Remaining</td>\n<td style='color:#999'>{{{remaining}}} ZCL</td></tr>\n<tr><td"
    ">Privacy</td>\n<td><span class='pill {{{privacy_pill}}}'>{{{privacy_label}}}</span>\n{{{privacy_w"
    "arning}}}</td></tr>\n<tr><td>Est. Time</td>\n<td style='color:#999'>~2.5 min (1 confirmation)</td"
    "></tr>\n</table>\n";

static const char TMPL_SEND_SUCCESS[] =
    "<div class='result-success'>\n<div class='icon'>&#x2713;</div>\n<h2>{{{heading}}}</h2>\n<p>{{{amo"
    "unt}}} ZCL to {{address}}</p>\n<div style='color:#555;font-size:14px;margin-top:8px'>\nBroadcast "
    "to network. Pending 1 confirmation (~2.5 min).</div>\n{{{txid_html}}}\n<div style='margin-top:24p"
    "x'>\n<a href='/wallet' style='color:#34d399;font-size:16px'>\nBack to Wallet</a></div></div>\n";

static const char TMPL_SEND[] =
    "<div style='text-align:center;padding:16px 0'>\n<div style='color:#34d399;font-size:24px;font-wei"
    "ght:700'>\n{{{spendable}}} ZCL</div>\n<div style='color:#888;font-size:14px;margin-top:2px'>\nSpe"
    "ndable balance</div>\n{{{shielded_note}}}\n</div>\n\n<form id='send-form' method='POST' action='z"
    "cl://node/wallet/send/review' \nonsubmit='return validateSend()' autocomplete='off'>\n<div class="
    "'form-group'>\n<label class='form-label' for='addr'>To</label>\n<input class='form-input' type='t"
    "ext' id='addr' name='address' \nplaceholder='Recipient address (t1... or zs1...)' required \nlist"
    "='contacts'>\n<div id='addr-err' class='form-error'></div>\n<div id='privacy-hint' style='font-si"
    "ze:14px;margin-top:4px;\nheight:16px'></div></div>\n\n{{{currency_selector}}}\n\n<div class='form"
    "-group'>\n<label class='form-label' for='amt'>Amount</label>\n<div style='display:flex;gap:8px;al"
    "ign-items:center'>\n<input class='form-input' type='text' id='amt' name='amount' \ninputmode='dec"
    "imal' style='flex:1' placeholder='0.00' required \noninput='updateRemaining()'>\n<button type='bu"
    "tton' class='send-max' \nonclick='document.getElementById(\\\"amt\\\").value=\n(BAL-{{{fee}}}).to"
    "Fixed(8);updateRemaining()'>Max</button></div>\n<div id='remaining' class='remaining' \nstyle='co"
    "lor:#888;font-size:14px;margin:4px 0'></div>\n<div id='amt-err' class='form-error'></div>\n<div s"
    "tyle='color:#888;font-size:14px;margin:4px 0'>\nNetwork fee: <span style='color:#f59e0b'>{{{fee}}"
    "} ZCL</span>\n</div></div>\n<button type='submit' class='btn-primary' style='margin-top:16px' \ni"
    "d='review-btn'>Review Send</button>\n</form>\n{{{contacts_datalist}}}\n";

static const char TMPL_SHIELD_AMOUNT_FORM[] =
    "{{> breadcrumb}}\n\n<div style='text-align:center;padding:16px 0'>\n<div class='balance-sub'>Shie"
    "ld transparent ZCL to a z-address.\nBreaks the on-chain link to your public address.</div></div>\n"
    "<form method='GET' action='/wallet/shield'>\n<div class='form-group'>\n<label class='form-label' "
    "for='shield-amt'>Amount to Secure</label>\n<div style='display:flex;gap:8px;align-items:center'>\n"
    "<input class='form-input' type='text' id='shield-amt'\ninputmode='decimal' name='amount' placehol"
    "der='0.00' required>\n<button type='button' class='send-max'\nonclick='document.getElementById(\""
    "shield-amt\").value=\"{{{max_amount}}}\"'>Max</button>\n</div>\n<div style='color:#888;font-size:"
    "14px;margin-top:6px'>\nAvailable: <span style='color:#34d399'>{{{available}}} ZCL</span>\n</div><"
    "/div>\n<div id='shield-err' class='form-error'></div>\n<button type='submit' class='btn-primary'\n"
    "style='background:#a78bfa;color:#fff;margin-top:8px'\nonclick='var a=parseFloat(document.getEleme"
    "ntById(\"shield-amt\").value);if(isNaN(a)||a<=0){document.getElementById(\"shield-err\").textCont"
    "ent=\"Enter a valid amount\";return false;}if(a>{{{max_amount}}}){document.getElementById(\"shiel"
    "d-err\").textContent=\"Insufficient funds\";return false;}'>\nReview</button>\n</form>\n<div styl"
    "e='text-align:center;margin-top:16px'>\n<a href='/wallet' style='color:#888'>Cancel</a></div>\n";

static const char TMPL_SHIELD_BALANCE_CARD[] =
    "<div style='margin-top:16px;padding:12px;background:#0a1f14;\nborder-radius:8px'>\n<div style='co"
    "lor:#34d399;font-size:18px;font-weight:700'>\n{{{total}}} ZCL</div>\n<div style='color:#888;font-"
    "size:14px;margin-top:4px'>\n{{{transparent}}} public + {{{shielded}}} private</div>\n</div>\n";

static const char TMPL_SHIELD_CONFIRM[] =
    "<div class='card' style='border-left-color:#a78bfa;padding:20px;\nbackground:linear-gradient(135d"
    "eg,#141414,#1a1a2a)'>\n<div style='text-align:center'>\n<div style='font-size:14px;color:#888;mar"
    "gin-bottom:8px'>\n&#x1F512; Securing</div>\n<div style='font-size:40px;color:#a78bfa;font-weight:"
    "800'>\n{{{amount}}} ZCL</div>\n<div style='color:#888;font-size:14px;margin-top:8px'>\nFee: {{{fe"
    "e}}} ZCL &middot; Total: {{{total}}} ZCL</div>\n</div></div>\n\n<div class='card'>\n<div style='c"
    "olor:#888;font-size:14px;line-height:1.6'>\n<div style='margin-bottom:8px'>\n<span style='color:#"
    "34d399;font-weight:700'>Step 1:</span> \nYour public ZCL moves to a private address (~2.5 min).</"
    "div>\n<div style='margin-bottom:8px'>\n<span style='color:#a78bfa;font-weight:700'>Step 2:</span>"
    " \nFunds are spendable immediately. For maximum privacy, wait ~6 hours \nso timing analysis canno"
    "t link back to the public source.</div>\n<div>\n<span style='color:#60a5fa;font-weight:700'>Step "
    "3:</span> \nSpend from your private balance with no on-chain link to your identity.</div>\n</div>"
    "</div>\n\n<div style='display:flex;gap:10px;margin:16px 0'>\n<a href='/wallet' class='btn-seconda"
    "ry' \nstyle='flex:1;text-align:center;text-decoration:none;\ndisplay:flex;align-items:center;just"
    "ify-content:center'>Cancel</a>\n<form method='POST' action='zcl://node/wallet/shield/confirm' \ns"
    "tyle='flex:2;margin:0'>\n<input type='hidden' name='amount' value='{{{amount}}}'>\n<button type='"
    "submit' class='btn-primary' \nstyle='background:#a78bfa;color:#fff'\n id='shield-btn'>Confirm</bu"
    "tton></form></div>\n<div id='shield-loading' class='loading-overlay' style='display:none'>\n<div "
    "class='spinner'></div>\n<p>Securing funds...</p></div>\n<script>\ndocument.getElementById('shield"
    "-btn').addEventListener('click',\nfunction(e){e.preventDefault();this.disabled=true;\ndocument.ge"
    "tElementById('shield-loading').style.display='flex';\nthis.form.submit();});\n</script>\n";

static const char TMPL_SHIELD_DONE[] =
    "<div class='privacy-card' style='display:flex;align-items:center;\ngap:12px;text-align:left;borde"
    "r-color:#34d399'>\n<div style='font-size:24px;flex-shrink:0'>&#x2705;</div>\n<div style='flex:1'>"
    "\n<div class='title' style='margin:0;color:#34d399'>\n{{{amount}}} ZCL shielded</div>\n<div class"
    "='desc' style='margin:0;margin-top:2px'>\n{{{message}}}</div></div></div>\n";

static const char TMPL_SHIELD_ERROR[] =
    "<div class='result-error'>\n<div class='icon'>&#x26A0;</div>\n<h2>Shield Failed</h2>\n<p>{{messag"
    "e}}</p>\n<div style='margin-top:12px'>\n<a href='/wallet/shield' style='color:#34d399'>Try Again<"
    "/a>\n<span style='color:#555;margin:0 8px'>|</span>\n<a href='/wallet' style='color:#888'>Back to"
    " Wallet</a>\n</div></div>\n";

static const char TMPL_SHIELD_INVALID[] =
    "<div class='card' style='border-left-color:#f87171'>\n<div class='label' style='color:#f87171'>In"
    "valid amount</div>\n<a href='/wallet'>Back to Wallet</a></div>\n";

static const char TMPL_SHIELD_PENDING[] =
    "<div class='privacy-card' style='display:flex;align-items:center;\ngap:12px;text-align:left;borde"
    "r-color:#a78bfa'>\n<div class='spinner' style='width:24px;height:24px;\nborder:3px solid #333;bor"
    "der-top-color:#a78bfa;\nborder-radius:50%;flex-shrink:0'></div>\n<div style='flex:1'>\n<div class"
    "='title' style='margin:0;color:#a78bfa'>\n&#x1F512; Securing funds...</div>\n<div class='desc' st"
    "yle='margin:0;margin-top:2px'>\nYour funds are being made private ({{{elapsed}}} sec ago). \nConf"
    "irms in ~2.5 min.</div></div></div>\n";

static const char TMPL_SHIELD_SUCCESS[] =
    "<div class='card' style='border-left-color:#34d399;padding:20px'>\n<div style='text-align:center'"
    ">\n<div style='font-size:40px;margin-bottom:8px'>&#x2705;</div>\n<div style='font-size:20px;color"
    ":#34d399;font-weight:700'>\n&#x1F512; Shielding {{{amount}}} ZCL</div>\n<div style='color:#888;fo"
    "nt-size:14px;margin-top:8px'>\nz_sendmany initiated. Funds moving from t-address to z-address.\nT"
    "he link between your transparent and shielded balance is broken on-chain.</div>\n<div style='colo"
    "r:#888;font-size:14px;margin-top:12px;\nfont-family:monospace;word-break:break-all'>{{opid}}</div"
    ">\n<div style='color:#555;font-size:14px;margin-top:12px'>\nSpendable immediately. For maximum pr"
    "ivacy, wait ~6 hours\nbefore spending so timing analysis can't link back.</div>\n{{{balance_card}"
    "}}\n</div></div>\n";

static const char TMPL_TX_DETAIL[] =
    "{{> breadcrumb}}\n\n<div style='text-align:center;padding:16px 0'>\n<span class='pill {{{pill_cla"
    "ss}}}' style='font-size:13px;padding:4px 12px'>\n{{{direction}}}</span>\n<h2 style='margin:12px 0"
    " 4px;color:{{{color}}}'>{{{heading}}}</h2>\n<div class='balance-sub'>{{{rel_time}}} &middot; {{{a"
    "bs_time}}}</div>\n</div>\n\n<div style='margin:0 0 16px'>\n<div style='display:flex;justify-conte"
    "nt:space-between;\nfont-size:13px;color:#888;margin-bottom:4px'>\n<span>{{{confs}}} confirmation{"
    "{{conf_plural}}}</span>\n<span>{{{conf_status}}}</span></div>\n<div class='conf-meter'>\n<div cla"
    "ss='fill' style='width:{{{conf_pct}}}%;background:{{{conf_color}}}'></div>\n</div></div>\n\n<div "
    "class='detail-grid'>\n<div class='lbl'>TxID</div>\n<div class='val'><a href='/explorer/tx/{{{txid"
    "}}}' class='hash'\nstyle='font-size:13px'>{{{txid}}}</a></div>\n<div class='lbl'>Block</div>\n<di"
    "v class='val'>{{{block_height}}}</div>\n<div class='lbl'>Direction</div>\n<div class='val'>{{{dir"
    "ection}}}</div>\n{{{fee_row}}}\n</div>\n\n{{{outputs_section}}}\n\n<div style='text-align:center;"
    "margin:24px 0'>\n<a href='/explorer/tx/{{{txid}}}' style='color:#60a5fa;font-size:13px'>\nView in"
    " Explorer &#x2192;</a></div>\n";

static const char TMPL_TX_INVALID[] =
    "<div class='result-error'>\n<div class='icon'>&#x2717;</div>\n<h2>Invalid Transaction ID</h2>\n<a"
    " href='/wallet/history' style='color:#34d399'>Back to History</a>\n</div>\n";

static const char TMPL_TX_NOT_FOUND[] =
    "<div class='result-warning'>\n<div class='icon'>&#x1F50D;</div>\n<h2>Transaction Not Found</h2>\n"
    "<p>This transaction is not in your wallet.</p>\n<a href='/wallet/history' style='color:#34d399'>B"
    "ack to History</a>\n</div>\n";

static const char TMPL_TX_ROW[] =
    "<a href='{{{link}}}' style='text-decoration:none;\ncolor:inherit;display:block'>\n<div class='tx-"
    "row'>\n<div>\n<span class='tx-amount {{{direction_class}}}'>{{{sign}}}{{{amount}}}</span>\n<span "
    "style='color:#888;font-size:14px;\nmargin-left:6px'>ZCL</span></div>\n<div class='tx-meta'>\n<spa"
    "n class='tx-time'{{{time_style}}}>{{{time_label}}}</span>\n<span class='tx-conf'>{{{conf_label}}}"
    "</span>\n</div></div></a>\n";

static const char TMPL_VALIDATION_ERROR[] =
    "<div class='result-error'>\n<div class='icon'>&#x2717;</div>\n<h2>{{heading}}</h2>\n<p>{{message}"
    "}</p>\n<div style='margin-top:16px;display:flex;gap:16px;justify-content:center'>\n<a href='{{{ba"
    "ck_url}}}' style='color:#999'>{{back_label}}</a>\n<a href='{{{retry_url}}}' style='color:#34d399'"
    ">Try Again</a>\n</div></div>\n";

static const char CSS_WALLET_0[] =
    "*{box-sizing:border-box;margin:0;padding:0}body{font-family:Inter,-apple-system,'Segoe UI',system"
    "-ui,sans-serif;background:#0c0c0c;color:#e2e2e2;max-width:520px;margin:0 auto;padding:20px;font-s"
    "ize:20px;line-height:1.6;padding-bottom:40px;}a{color:#60a5fa;text-decoration:none;transition:col"
    "or .15s ease}a:hover{color:#93c5fd}a:focus-visible{outline:2px solid #34d399;outline-offset:2px}c"
    "ode{font-family:'JetBrains Mono','SF Mono','Fira Code','Cascadia Code',monospace;font-size:12px;c"
    "olor:#f59e0b;}.nav,nav.nav{display:flex;gap:4px;margin:0 0 16px;padding:4px;background:#111;borde"
    "r-radius:10px;}.nav a{flex:1;text-align:center;padding:12px 4px;border-radius:8px;font-size:15px;"
    "font-weight:600;color:#999;transition:all .15s ease;min-height:48px;text-decoration:none;touch-ac"
    "tion:manipulation;}.nav a:hover{color:#e2e2e2;background:#161616}.nav a.active{color:#34d399;back"
    "ground:#0a1f14}.nav a:focus-visible{outline:2px solid #34d399;outline-offset:-2px}.balance{text-a"
    "lign:center;font-size:56px;font-weight:800;color:#34d399;letter-spacing:-1px;line-height:1.1;}.ba"
    "lance-sub{text-align:center;color:#bbb;font-size:16px;margin-top:8px}.sync-badge{display:inline-b"
    "lock;font-size:12px;font-weight:600;letter-spacing:.08em;text-transform:uppercase;}@keyframes pul"
    "se{0%,100%{opacity:1}50%{opacity:.4}}.pill{display:inline-block;padding:2px 8px;border-radius:10p"
    "x;font-size:13px;font-weight:700;letter-spacing:.03em;}.pill-synced,.pill-confirmed,.pill-t{backg"
    "round:#0a1f14;color:#34d399}.pill-ready{background:#0f1a2e;color:#60a5fa}.pill-syncing{background"
    ":#1a1510;color:#fbbf24;animation:pulse 1.5s ease infinite}.pill-pending{background:#1a1510;color:"
    "#fbbf24}.pill-private,.pill-z{background:#1a1428;color:#a78bfa}.pill-send{background:#1f1010;colo"
    "r:#f87171}.actions{display:flex;gap:12px;margin:16px 0}.actions a{flex:1;text-align:center;paddin"
    "g:16px 8px;border-radius:10px;font-size:18px;font-weight:700;text-decoration:none;min-height:52px"
    ";transition:all .15s ease;touch-action:manipulation;}.actions a:focus-visible{outline:2px solid #"
    "34d399;outline-offset:2px}.btn-primary{display:block;width:100%;background:#34d399;color:#0c0c0c;"
    "border:none;padding:16px;font-size:18px;font-weight:700;border-radius:10px;cursor:pointer;font-fa"
    "mily:inherit;transition:background .15s ease;touch-action:manipulation;}.btn-primary:hover{backgr"
    "ound:#4ade80}.btn-primary:focus-visible{outline:2px solid #34d399;outline-offset:2px}.btn-primary"
    ":disabled{opacity:.5;cursor:not-allowed}.btn-primary:active{transform:scale(.98);opacity:.9}.btn-"
    "secondary{display:block;width:100%;background:transparent;color:#e2e2e2;border:1px solid #333;pad"
    "ding:16px;font-size:18px;font-weight:700;border-radius:10px;cursor:pointer;font-family:inherit;tr"
    "ansition:all .15s ease;touch-action:manipulation;}.btn-secondary:hover{border-color:#999}.btn-sec"
    "ondary:focus-visible{outline:2px solid #34d399;outline-offset:2px}.btn-secondary:active{transform"
    ":scale(.98);opacity:.9}.send-max{background:#1e1e1e;color:#34d399;border:none;padding:10px";
static const char CSS_WALLET_1[] =
    " 14px;font-size:12px;font-weight:700;border-radius:6px;cursor:pointer;min-height:36px;font-family"
    ":inherit;white-space:nowrap;transition:background .15s ease;touch-action:manipulation;}.send-max:"
    "hover{background:#333}.send-max:focus-visible{outline:2px solid #34d399;outline-offset:2px}.send-"
    "max:active{transform:scale(.96)}.form-group{margin-bottom:16px}.form-label{display:block;font-siz"
    "e:13px;font-weight:600;text-transform:uppercase;letter-spacing:.08em;color:#bbb;margin-bottom:6px"
    ";}.form-input{display:block;width:100%;background:#111;color:#e2e2e2;border:1px solid #1e1e1e;pad"
    "ding:14px 16px;font-family:inherit;font-size:18px;border-radius:8px;transition:border-color .15s "
    "ease;}.form-input:focus{border-color:#333;outline:none;box-shadow:0 0 0 3px rgba(52,211,153,.12);"
    "}.form-input::placeholder{color:#777}.form-error{color:#f87171;font-size:12px;margin-top:4px}.sec"
    "tion-header{display:flex;justify-content:space-between;align-items:baseline;margin:24px 0 8px;}.s"
    "ection-header span{font-size:13px;font-weight:600;text-transform:uppercase;letter-spacing:.08em;c"
    "olor:#aaa;}.section-header a{font-size:12px;color:#aaa}.section-header a:hover{color:#ccc}.tx-row"
    "{display:flex;justify-content:space-between;align-items:center;padding:12px 0;border-bottom:1px s"
    "olid #1e1e1e;}.tx-row:last-child{border-bottom:none}.tx-amount{font-size:20px;font-weight:700;fon"
    "t-family:'JetBrains Mono','SF Mono','Fira Code',monospace;}.tx-amount.recv{color:#34d399}.tx-amou"
    "nt.send{color:#f87171}.tx-meta{font-size:14px;color:#aaa;text-align:right}.tx-meta a{color:#60a5f"
    "a;font-family:'JetBrains Mono','SF Mono',monospace;font-size:12px;}.tx-time{display:block;margin-"
    "bottom:2px}.tx-conf{font-size:13px;color:#999}.tx-card{background:#111;padding:14px 16px;border-r"
    "adius:8px;margin:6px 0;border-left:3px solid #333;}.tx-card:hover{background:#161616}.utxo-row{di"
    "splay:flex;justify-content:space-between;align-items:center;padding:10px 0;border-bottom:1px soli"
    "d #1e1e1e;}.utxo-row:last-child{border-bottom:none}.addr-display{background:#111;padding:16px;bor"
    "der-radius:8px;font-family:'JetBrains Mono','SF Mono','Fira Code',monospace;font-size:16px;color:"
    "#60a5fa;word-break:break-all;text-align:center;margin:12px 0;user-select:all;cursor:pointer;borde"
    "r:1px solid #1e1e1e;transition:border-color .15s ease;}.addr-display:hover{border-color:#333}.add"
    "r-display-sm{background:#111;padding:12px;border-radius:8px;font-family:'JetBrains Mono','SF Mono"
    "','Fira Code',monospace;font-size:13px;color:#a78bfa;word-break:break-all;text-align:center;margi"
    "n:8px 0;user-select:all;cursor:pointer;border:1px solid #1e1e1e;transition:border-color .15s ease"
    ";}.addr-display-sm:hover{border-color:#333}.addr-chunked{font-family:'JetBrains Mono','SF Mono','"
    "Fira Code',monospace;font-size:15px;letter-spacing:.5px;line-height:1.8;word-break:break-all;text"
    "-align:center;}.addr-chunked .sep{color:#333;margin:0 1px}.addr-chunked .hi{color:#34d399;font-we"
    "ight:700}.review-table{width:100%}.review-table td{padding:10px 0;font-size:14px}.review-t";
static const char CSS_WALLET_2[] =
    "able td:first-child{color:#aaa}.review-table td:last-child{text-align:right}.review-table tr+tr{b"
    "order-top:1px solid #1e1e1e}.result-success,.result-error,.result-warning{text-align:center;paddi"
    "ng:32px 0;}.result-success .icon,.result-error .icon,.result-warning .icon{font-size:48px;margin-"
    "bottom:12px;}.result-success h2{color:#34d399;font-size:20px;font-weight:700;margin-bottom:8px}.r"
    "esult-error h2{color:#f87171;font-size:20px;font-weight:700;margin-bottom:8px}.result-warning h2{"
    "color:#fbbf24;font-size:20px;font-weight:700;margin-bottom:8px}.result-success p,.result-error p,"
    ".result-warning p{color:#999;font-size:14px;margin:4px 0;}.status-bar{position:fixed;bottom:0;lef"
    "t:0;right:0;background:#111;border-top:1px solid #1e1e1e;padding:6px 16px;display:flex;justify-co"
    "ntent:center;gap:16px;font-size:12px;color:#999;font-family:'JetBrains Mono','SF Mono',monospace;"
    "z-index:100;}.status-bar span{white-space:nowrap}.empty-state{text-align:center;padding:40px 0;co"
    "lor:#999;font-size:14px}.remaining{color:#666;font-size:12px;margin-top:6px}.sync-note{color:#60a"
    "5fa;font-size:12px;margin-top:6px;text-align:center}.qr-wrap{text-align:center;margin:16px 0}.dis"
    "crepancy{background:#1a1510;border:1px solid #4a3520;border-radius:8px;padding:12px;font-size:12p"
    "x;margin:12px 0;}.discrepancy .title{color:#f59e0b;font-weight:700;margin-bottom:4px}.discrepancy"
    " .detail{color:#92712a}.page-controls{display:flex;justify-content:center;gap:16px;margin:20px 0;"
    "font-size:14px;}.page-controls a{color:#60a5fa}table{width:100%;border-collapse:collapse;font-siz"
    "e:16px}th{text-align:left;color:#666;padding:8px 6px;border-bottom:1px solid #1e1e1e;font-size:13"
    "px;text-transform:uppercase;letter-spacing:.05em;font-weight:600;}td{padding:8px 6px;border-botto"
    "m:1px solid #1e1e1e;color:#e2e2e2}tr:hover{background:#111}.hash{color:#60a5fa;font-family:'JetBr"
    "ains Mono','SF Mono','Fira Code',monospace;font-size:14px;}.zcl{color:#34d399;font-weight:700;fon"
    "t-family:'JetBrains Mono','SF Mono',monospace;font-size:16px;text-align:right;}.mono{font-family:"
    "'JetBrains Mono','SF Mono','Fira Code',monospace;font-size:13px;}.total-row{font-weight:700;backg"
    "round:#0a1f14}.overflow-x{overflow-x:auto;-webkit-overflow-scrolling:touch}.stats{display:flex;ga"
    "p:10px;margin:12px 0;flex-wrap:wrap}.stat{flex:1;min-width:120px;background:#111;padding:14px;bor"
    "der-radius:8px;text-align:center;}.stat .n{font-size:24px;color:#34d399;font-weight:800;line-heig"
    "ht:1.2;font-family:'JetBrains Mono','SF Mono',monospace;}.stat .l{font-size:13px;color:#666;text-"
    "transform:uppercase;letter-spacing:.08em;margin-top:4px;font-weight:600;}h2{color:#e2e2e2;font-si"
    "ze:22px;margin:24px 0 8px;font-weight:700}h3{color:#999;font-size:15px;font-weight:600;margin:20p"
    "x 0 8px;text-transform:uppercase;letter-spacing:.05em;}.sub{color:#666;font-size:13px;margin-bott"
    "om:12px}.card{background:#111;padding:14px 16px;border-radius:8px;margin:8px 0;border-left:3px so"
    "lid #34d399;}.card .label{color:#666;font-size:13px;font-weight:600;text-transform:upperca";
static const char CSS_WALLET_3[] =
    "se;letter-spacing:.05em;}.card .value{font-size:22px;color:#34d399;font-weight:700}.loading-overl"
    "ay{position:fixed;inset:0;background:rgba(12,12,12,.85);display:flex;align-items:center;justify-c"
    "ontent:center;flex-direction:column;z-index:200;}.loading-overlay .spinner{width:40px;height:40px"
    ";border:3px solid #222;border-top-color:#34d399;border-radius:50%;animation:spin .8s linear infin"
    "ite;}@keyframes spin{to{transform:rotate(360deg)}}.loading-overlay p{color:#a1a1a1;font-size:14px"
    ";margin-top:16px}.filter-tabs{display:flex;gap:0;margin:12px 0;background:#111;border-radius:8px;"
    "overflow:hidden;border:1px solid #1e1e1e;}.filter-tabs a{flex:1;text-align:center;padding:8px;fon"
    "t-size:12px;font-weight:600;color:#888;text-decoration:none;transition:all .15s ease;}.filter-tab"
    "s a:hover{color:#e2e2e2;background:#161616}.filter-tabs a.active{color:#34d399;background:#0a1f14"
    "}.privacy-card{background:linear-gradient(135deg,#0a1428,#1a1428);border:1px solid #2a1a3a;border"
    "-radius:10px;padding:16px;margin:16px 0;text-align:center;}.privacy-card .title{color:#a78bfa;fon"
    "t-size:13px;font-weight:600;margin-bottom:4px}.privacy-card .desc{color:#888;font-size:12px;margi"
    "n-bottom:12px}.privacy-card .btn{display:inline-block;background:#a78bfa;color:#0c0c0c;padding:10"
    "px 24px;border-radius:8px;font-weight:700;font-size:13px;text-decoration:none;transition:backgrou"
    "nd .15s ease;}.privacy-card .btn:hover{background:#c4b5fd}.search-input{display:block;width:100%;"
    "background:#111;color:#e2e2e2;border:1px solid #1e1e1e;padding:10px 14px;font-size:13px;border-ra"
    "dius:8px;font-family:inherit;margin:8px 0;}.search-input:focus{border-color:#333;outline:none;box"
    "-shadow:0 0 0 3px rgba(52,211,153,.12);}.search-input::placeholder{color:#777}.tab-toggle{display"
    ":flex;gap:0;margin:12px 0;background:#111;border-radius:10px;overflow:hidden;border:1px solid #1e"
    "1e1e;}.tab-toggle button,.tab-toggle a{flex:1;text-align:center;padding:10px;font-size:13px;font-"
    "weight:700;border:none;cursor:pointer;color:#888;background:transparent;font-family:inherit;trans"
    "ition:all .15s ease;text-decoration:none;}.tab-toggle .active{color:#34d399;background:#0a1f14}.t"
    "ab-toggle .active-z{color:#a78bfa;background:#1a1428}.detail-grid{display:grid;grid-template-colu"
    "mns:100px 1fr;gap:8px 12px;font-size:14px;margin:12px 0;}.detail-grid .lbl{color:#aaa;font-weight"
    ":600;font-size:12px;text-transform:uppercase;letter-spacing:.05em;}.detail-grid .val{color:#e2e2e"
    "2;word-break:break-all}.conf-meter{height:4px;background:#1e1e1e;border-radius:2px;margin:8px 0}."
    "conf-meter .fill{height:100%;border-radius:2px;transition:width .3s ease}@media (max-width:360px)"
    "{body{padding:12px;font-size:14px}.balance{font-size:36px}.nav a{font-size:13px;padding:8px 4px}."
    "actions a{padding:12px 4px;font-size:14px}.stat .n{font-size:18px}table{font-size:12px}td,th{padd"
    "ing:5px 4px}.detail-grid{grid-template-columns:1fr;gap:2px 0}.detail-grid .lbl{margin-top:8px}}@m"
    "edia (prefers-reduced-motion:reduce){*{animation:none !important;transition:none !importan";
static const char CSS_WALLET_4[] =
    "t}}@media print{.nav,.status-bar,.actions{display:none}body{background:#fff;color:#000;max-width:"
    "none}}";
static char _CSS_WALLET_buf[12104];
__attribute__((unused))
static const char *CSS_WALLET_get(void) {
    size_t off = 0;
    size_t l0 = __builtin_strlen(CSS_WALLET_0);
    __builtin_memcpy(_CSS_WALLET_buf + off, CSS_WALLET_0, l0); off += l0;
    size_t l1 = __builtin_strlen(CSS_WALLET_1);
    __builtin_memcpy(_CSS_WALLET_buf + off, CSS_WALLET_1, l1); off += l1;
    size_t l2 = __builtin_strlen(CSS_WALLET_2);
    __builtin_memcpy(_CSS_WALLET_buf + off, CSS_WALLET_2, l2); off += l2;
    size_t l3 = __builtin_strlen(CSS_WALLET_3);
    __builtin_memcpy(_CSS_WALLET_buf + off, CSS_WALLET_3, l3); off += l3;
    size_t l4 = __builtin_strlen(CSS_WALLET_4);
    __builtin_memcpy(_CSS_WALLET_buf + off, CSS_WALLET_4, l4); off += l4;
    _CSS_WALLET_buf[off] = 0;
    return _CSS_WALLET_buf;
}
#define CSS_WALLET (CSS_WALLET_get())

#include "util/template.h"

static const struct template_partial _tmpl_partials[] = {
    { "back-to-wallet", TMPL_BACK_TO_WALLET },
    { "backup-warning", TMPL_BACKUP_WARNING },
    { "breadcrumb", TMPL_BREADCRUMB },
    { "checkpoint-row", TMPL_CHECKPOINT_ROW },
    { "coins-no-notes", TMPL_COINS_NO_NOTES },
    { "coins-no-tokens", TMPL_COINS_NO_TOKENS },
    { "coins-notes-table", TMPL_COINS_NOTES_TABLE },
    { "coins-page", TMPL_COINS_PAGE },
    { "coins-tokens", TMPL_COINS_TOKENS },
    { "conf-confirmed", TMPL_CONF_CONFIRMED },
    { "conf-pending", TMPL_CONF_PENDING },
    { "dashboard", TMPL_DASHBOARD },
    { "explorer-tx-row", TMPL_EXPLORER_TX_ROW },
    { "history-card", TMPL_HISTORY_CARD },
    { "history-header", TMPL_HISTORY_HEADER },
    { "history-shield", TMPL_HISTORY_SHIELD },
    { "loading", TMPL_LOADING },
    { "node-no-tor", TMPL_NODE_NO_TOR },
    { "node-page", TMPL_NODE_PAGE },
    { "node-peer-row", TMPL_NODE_PEER_ROW },
    { "node-status-strip", TMPL_NODE_STATUS_STRIP },
    { "node-tor", TMPL_NODE_TOR },
    { "pagination", TMPL_PAGINATION },
    { "privacy-nudge", TMPL_PRIVACY_NUDGE },
    { "receive-copy-js", TMPL_RECEIVE_COPY_JS },
    { "receive-js", TMPL_RECEIVE_JS },
    { "receive-no-zaddr", TMPL_RECEIVE_NO_ZADDR },
    { "receive-tabs", TMPL_RECEIVE_TABS },
    { "receive-tpane", TMPL_RECEIVE_TPANE },
    { "receive-zpane-close", TMPL_RECEIVE_ZPANE_CLOSE },
    { "receive-zpane-open", TMPL_RECEIVE_ZPANE_OPEN },
    { "send-confirm-buttons", TMPL_SEND_CONFIRM_BUTTONS },
    { "send-error", TMPL_SEND_ERROR },
    { "send-review", TMPL_SEND_REVIEW },
    { "send-success", TMPL_SEND_SUCCESS },
    { "send", TMPL_SEND },
    { "shield-amount-form", TMPL_SHIELD_AMOUNT_FORM },
    { "shield-balance-card", TMPL_SHIELD_BALANCE_CARD },
    { "shield-confirm", TMPL_SHIELD_CONFIRM },
    { "shield-done", TMPL_SHIELD_DONE },
    { "shield-error", TMPL_SHIELD_ERROR },
    { "shield-invalid", TMPL_SHIELD_INVALID },
    { "shield-pending", TMPL_SHIELD_PENDING },
    { "shield-success", TMPL_SHIELD_SUCCESS },
    { "tx-detail", TMPL_TX_DETAIL },
    { "tx-invalid", TMPL_TX_INVALID },
    { "tx-not-found", TMPL_TX_NOT_FOUND },
    { "tx-row", TMPL_TX_ROW },
    { "validation-error", TMPL_VALIDATION_ERROR },
};

#define TMPL_PARTIAL_COUNT 49

__attribute__((unused))
static void tmpl_init_partials(void) {
    template_register_partials(_tmpl_partials, TMPL_PARTIAL_COUNT);
}

#endif
