/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 *
 * test_agent_guard - table regressions for z23-agent-guard
 * (tools/agent_guard.c, built as build/bin/z23-agent-guard).
 *
 * The guard is a PreToolUse hook that refuses the never-do list. Each row
 * runs the real binary in --bash or --path check mode and pins the exact
 * verdict. Precision rows (ALLOW) matter as much as the refusals: a false
 * refusal stalls every worker. */

#include "test/test_core.h"
#include "test/host_tool_capture.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#define AG_BIN "build/bin/z23-agent-guard"
#define A "ALLOW"
#define DD "REFUSE guard.datadir"
#define RF "REFUSE guard.reindex_flag"
#define PY "REFUSE guard.python"
#define ID "REFUSE guard.git_identity"
#define SP "REFUSE guard.spend_or_key_export"
#define HC "REFUSE guard.host_config"
#define GP "REFUSE guard.git_push"
#define DH "REFUSE guard.devbuild_help"

struct ag_case {
    char mode; /* 'b' bash, 'p' path (tool in arg1, path in arg2) */
    const char *arg1;
    const char *arg2;
    const char *content;
    const char *want;
};

static const struct ag_case ag_cases[] = {
    /* ---- required ALLOW rows ---- */
    {'b', "tail -n 50 ~/.zclassic-c23/node.log", 0, 0, A},
    {'b', "ls ~/.zclassic-c23*/auto_reindex_request", 0, 0, A},
    {'b', "test -e $HOME/.zclassic-c23/auto_reindex_request && echo present", 0, 0, A},
    {'b', "git grep -n sendtoaddress", 0, 0, A},
    {'b', "grep -rn python docs/", 0, 0, A},
    {'b', "echo \"no python here\"", 0, 0, A},
    {'b', "sed -n 1,20p tools/x.py", 0, 0, A},
    {'b', "git commit -q -m \"fix: explain why git push is the land queue's job\"", 0, 0, A},
    {'b', "git config user.email", 0, 0, A},
    {'b', "git log --author=Alice", 0, 0, A},
    {'b', "devbuild --wait make agent-verify ONLY=@changed", 0, 0, A},
    {'b', "sysctl -a", 0, 0, A},
    {'b', "cat /etc/sysctl.conf", 0, 0, A},
    {'b', "ssh host2 'tail -n 5 ~/.zclassic-c23/node.log'", 0, 0, A},
    {'b', "cat > brief.md <<'EOF'\nrm -rf ~/.zclassic-c23\nEOF\n", 0, 0, A},
    /* ---- required REFUSE rows ---- */
    {'b', "ssh r5 'rm -rf ~/.zclassic-c23/blocks'", 0, 0, DD},
    {'b', "ssh host2 sh -s <<'EOF'\nmv ~/.zclassic-c23/auto_reindex_request /srv/w/\nEOF\n", 0, 0, RF},
    {'b', "env python3 -c 1", 0, 0, PY},
    {'b', "/usr/bin/python3 x", 0, 0, PY},
    {'b', "GIT_AUTHOR_EMAIL=a@b git commit -m x", 0, 0, ID},
    {'b', "git -c user.email=a@b commit", 0, 0, ID},
    {'b', "curl -s --data '{\"method\":\"z_sendmany\"}' http://127.0.0.1:8232", 0, 0, SP},
    {'b', "build/bin/z23 rpc dumpprivkey t1x", 0, 0, SP},
    {'b', "sudo sysctl -w kernel.x=1", 0, 0, HC},
    {'b', "echo 1 | sudo tee /etc/sysctl.d/99-x.conf", 0, 0, HC},
    {'b', "git push origin HEAD", 0, 0, GP},
    {'b', "devbuild --help", 0, 0, DH},
    /* ---- rule 1: datadir ---- */
    {'b', "rm -rf ~/.zclassic-c23/blocks", 0, 0, DD},
    {'b', "rm -rf $HOME/.zclassic-c23/", 0, 0, DD},
    {'b', "rm -rf $HOME/.zclassic/", 0, 0, DD},
    {'b', "rm -rf \"$HOME/.zclassic-c23-pq/chainstate\"", 0, 0, DD},
    {'b', "mv ~/wallet_backups /srv/w/x", 0, 0, DD},
    {'b', "cp x ~/.zclassic-c23/node.conf", 0, 0, DD},
    {'b', "echo hi > ~/.zclassic-c23/notes.txt", 0, 0, DD},
    {'b', "echo hi >> $HOME/.zclassic-c23/notes.txt", 0, 0, DD},
    {'b', "echo hi 2>/dev/null >~/.zclassic-c23/n", 0, 0, DD},
    {'b', "touch ~/.zclassic-c23/x", 0, 0, DD},
    {'b', "echo x | tee ~/.zclassic-c23/log", 0, 0, DD},
    {'b', "sed -i s/a/b/ ~/.zclassic-c23/node.conf", 0, 0, DD},
    {'b', "find ~/.zclassic-c23 -name '*.tmp' -delete", 0, 0, DD},
    {'b', "sqlq ~/.zclassic-c23/node.db 'insert into t values (1)'", 0, 0, DD},
    {'b', "cd /srv/w && chmod 700 ~/.zclassic-c23/", 0, 0, DD},
    {'b', "bash -c 'rm -rf ~/.zclassic-c23/x'", 0, 0, DD},
    {'b', "ssh host2 \"cd /srv/w; rm -rf ~/.zclassic-c23/x\"", 0, 0, DD},
    {'b', "ls build && rm -rf ~/.zclassic-c23/x", 0, 0, DD},
    {'p', "Edit", "$HOME/.zclassic-c23/node.conf", 0, DD},
    {'p', "Write", "~/.zclassic-c23/notes.md", "x", DD},
    {'p', "MultiEdit", "$HOME/wallet_backups/a", 0, DD},
    {'p', "NotebookEdit", "$HOME/.zclassic/a.ipynb", 0, DD},
    {'b', "cat ~/.zclassic-c23/node.log", 0, 0, A},
    {'b', "head -n 3 ~/.zclassic-c23/debug.log", 0, 0, A},
    {'b', "grep -c ERROR ~/.zclassic-c23/node.log", 0, 0, A},
    {'b', "du -sh ~/.zclassic-c23 ~/wallet_backups", 0, 0, A},
    {'b', "wc -l ~/.zclassic-c23/node.log", 0, 0, A},
    {'b', "stat ~/.zclassic-c23/node.db", 0, 0, A},
    {'b', "find ~/.zclassic-c23 -maxdepth 1 -name '*.log'", 0, 0, A},
    {'b', "journalctl -u z23-node -n 20", 0, 0, A},
    {'b', "git commit -m \"docs: rm -rf ~/.zclassic-c23 is forbidden\"", 0, 0, A},
    {'b', "echo \"mv ~/.zclassic-c23 x\" > build/scratch/note.txt", 0, 0, A},
    {'b', "rm -rf build/scratch/srv/w", 0, 0, A},
    {'b', "cp tools/a.c tools/b.c", 0, 0, A},
    {'p', "Edit", "work/tools/a.c", 0, A},
    {'p', "Write", "/srv/w/x/brief.md", "# hi", A},
    /* ---- rule 2: reindex flag ---- */
    {'b', "touch ~/.zclassic-c23/auto_reindex_request", 0, 0, RF},
    {'b', "rm -f ~/.zclassic-c23-pq/auto_reindex_request", 0, 0, RF},
    {'b', "mv auto_reindex_request /srv/w/", 0, 0, RF},
    {'b', "echo 1 > auto_reindex_request", 0, 0, RF},
    {'b', "z23 -reindex", 0, 0, RF},
    {'b', "build/bin/zclassicd --reindex -daemon", 0, 0, RF},
    {'b', "zcashd -reindex=1", 0, 0, RF},
    {'b', "z23-node reindex=1", 0, 0, RF},
    {'p', "Write", "$HOME/.zclassic-c23/auto_reindex_request", "", RF},
    {'b', "cat ~/.zclassic-c23/auto_reindex_request", 0, 0, A},
    {'b', "[ -e ~/.zclassic-c23/auto_reindex_request ] && echo yes", 0, 0, A},
    {'b', "grep -rn auto_reindex_request src/", 0, 0, A},
    {'b', "z23 rpc getblockcount", 0, 0, A},
    {'b', "echo \"pass -reindex to z23\"", 0, 0, A},
    /* ---- rule 3: python ---- */
    {'b', "python3 script", 0, 0, PY},
    {'b', "python -V", 0, 0, PY},
    {'b', "python2 x", 0, 0, PY},
    {'b', "python3.12 -c 1", 0, 0, PY},
    {'b', "pip install requests", 0, 0, PY},
    {'b', "pip3 list", 0, 0, PY},
    {'b', "pipx run x", 0, 0, PY},
    {'b', "sudo -u nobody python3 x", 0, 0, PY},
    {'b', "timeout 30 python3 x", 0, 0, PY},
    {'b', "cd tools && python3 gen", 0, 0, PY},
    {'b', "ls | python3 -c 1", 0, 0, PY},
    {'b', "FOO=1 nice -n 5 python3 x", 0, 0, PY},
    {'b', "for f in a b; do python3 $f; done", 0, 0, PY},
    {'p', "Write", "/srv/w/x.py", "print(1)", PY},
    {'p', "Edit", "tools/gen.py", 0, PY},
    {'p', "Write", "/srv/w/runner", "#!/usr/bin/env python3\nprint(1)\n", PY},
    {'p', "Write", "/srv/w/runner", "#!/bin/sh\necho python\n", A},
    {'p', "Write", "/srv/w/notes.md", "run python3 here", A},
    {'b', "command -v python3", 0, 0, A},
    {'b', "which python3", 0, 0, A},
    {'b', "echo python3 | wc -c", 0, 0, A},
    {'b', "git commit -m \"remove python3 usage\"", 0, 0, A},
    {'b', "cat tools/x.py", 0, 0, A},
    /* ---- rule 4: git identity ---- */
    {'b', "git config user.name Bob", 0, 0, ID},
    {'b', "git config --global user.email a@b", 0, 0, ID},
    {'b', "git config --unset user.email", 0, 0, ID},
    {'b', "git config --global --unset-all user.name", 0, 0, ID},
    {'b', "git config --replace-all author.name x", 0, 0, ID},
    {'b', "git config committer.email x@y", 0, 0, ID},
    {'b', "git config set user.name x", 0, 0, ID},
    {'b', "git -c user.name=x commit -m m", 0, 0, ID},
    {'b', "git -C repo -c user.email=a@b log", 0, 0, ID},
    {'b', "git commit --author=\"A <a@b>\" -m x", 0, 0, ID},
    {'b', "git commit --author 'A <a@b>' -m x", 0, 0, ID},
    {'b', "GIT_AUTHOR_NAME=x git commit -m x", 0, 0, ID},
    {'b', "GIT_COMMITTER_EMAIL=a@b GIT_COMMITTER_NAME=x git commit", 0, 0, ID},
    {'b', "env GIT_COMMITTER_NAME=x git commit -m m", 0, 0, ID},
    {'b', "export GIT_AUTHOR_EMAIL=a@b", 0, 0, ID},
    {'b', "git config user.name", 0, 0, A},
    {'b', "git config --get user.email", 0, 0, A},
    {'b', "git config --global --get user.name", 0, 0, A},
    {'b', "git config --list", 0, 0, A},
    {'b', "git config core.editor vim", 0, 0, A},
    {'b', "git config get user.email", 0, 0, A},
    {'b', "git -c core.pager=cat log -1", 0, 0, A},
    {'b', "git commit -S -m \"set GIT_AUTHOR_NAME=x is banned\"", 0, 0, A},
    {'b', "git log --author=Alice --oneline", 0, 0, A},
    {'b', "echo GIT_AUTHOR_NAME=x", 0, 0, A},
    /* ---- rule 5: spend or key export ---- */
    {'b', "z23-cli sendtoaddress t1x 1", 0, 0, SP},
    {'b', "zclassic-cli z_sendmany t1x '[]'", 0, 0, SP},
    {'b', "zcash-cli dumpwallet /srv/w/w", 0, 0, SP},
    {'b', "zcl-rpc z_exportkey zs1x", 0, 0, SP},
    {'b', "z23 rpc sendrawtransaction 00", 0, 0, SP},
    {'b', "wget -qO- --post-data='{\"method\": \"dumpprivkey\"}' http://localhost:8232", 0, 0, SP},
    {'b', "curl -d @- http://localhost:8232 <<'EOF'\n{\"method\":\"z_exportwallet\"}\nEOF\n", 0, 0, SP},
    {'b', "sudo curl localhost:8232 -d z_shieldcoinbase", 0, 0, SP},
    {'b', "z23-cli z_exportviewingkey zs1x", 0, 0, SP},
    {'b', "z23-cli z_mergetoaddress x y", 0, 0, SP},
    {'b', "grep -n z_sendmany src/rpc.c", 0, 0, A},
    {'b', "z23-cli getblockcount", 0, 0, A},
    {'b', "curl -s http://localhost:8232 -d '{\"method\":\"getinfo\"}'", 0, 0, A},
    {'b', "build/bin/z23 rpc getinfo", 0, 0, A},
    {'b', "curl -s https://example.org/sendtoaddressing", 0, 0, A},
    {'b', "echo sendtoaddress", 0, 0, A},
    /* ---- rule 6: host config ---- */
    {'b', "sysctl -w vm.swappiness=1", 0, 0, HC},
    {'b', "sysctl kernel.x=1", 0, 0, HC},
    {'b', "sudo apparmor_parser -r /etc/apparmor.d/x", 0, 0, HC},
    {'b', "aa-complain /usr/bin/x", 0, 0, HC},
    {'b', "sudo aa-enforce x", 0, 0, HC},
    {'b', "aa-disable x", 0, 0, HC},
    {'b', "sudo visudo", 0, 0, HC},
    {'b', "echo x > /etc/sudoers.d/90-x", 0, 0, HC},
    {'b', "sudo sed -i s/a/b/ /etc/sysctl.conf", 0, 0, HC},
    {'b', "sudo cp x /etc/apparmor.d/x", 0, 0, HC},
    {'p', "Write", "/etc/sysctl.d/99-x.conf", "x", HC},
    {'p', "Edit", "/etc/apparmor.d/usr.bin.x", 0, HC},
    {'p', "Edit", "/etc/sudoers.d/x", 0, HC},
    {'b', "sysctl vm.swappiness", 0, 0, A},
    {'b', "sysctl -n kernel.osrelease", 0, 0, A},
    {'b', "cat /etc/apparmor.d/x", 0, 0, A},
    {'b', "ls /etc/sudoers.d", 0, 0, A},
    {'b', "aa-status", 0, 0, A},
    {'p', "Write", "/etc/hostname-notes", "x", A},
    /* ---- rule 7: git push ---- */
    {'b', "git push", 0, 0, GP},
    {'b', "git push --force origin main", 0, 0, GP},
    {'b', "cd x && git push origin lane/y", 0, 0, GP},
    {'b', "git -C /srv/w/repo push", 0, 0, GP},
    {'b', "ssh r1 'cd repo; git push'", 0, 0, GP},
    {'b', "bash -c \"git push origin HEAD\"", 0, 0, GP},
    {'b', "make lint || git push", 0, 0, GP},
    {'b', "echo done; (git push)", 0, 0, GP},
    {'b', "echo $(git push)", 0, 0, GP},
    {'b', "git pull", 0, 0, A},
    {'b', "git status && git log -1", 0, 0, A},
    {'b', "git remote -v", 0, 0, A},
    {'b', "echo git push", 0, 0, A},
    {'b', "gh pr create --body 'run git push later'", 0, 0, A},
    {'b', "git commit -m 'x' # git push", 0, 0, A},
    /* ---- rule 8: devbuild help ---- */
    {'b', "devbuild -h", 0, 0, DH},
    {'b', "devbuild --wait --help", 0, 0, DH},
    {'b', "devbuild --wait make lint-land lint-preflight", 0, 0, A},
    {'b', "env -u GIT_EDITOR devbuild --wait --project z23 make t-fast ONLY=x", 0, 0, A},
    /* ---- review fixes: false positives that must stay ALLOW ---- */
    {'b', "sqlq ~/.zclassic-c23/consensus.db \"select 1\"", 0, 0, A},
    {'b', "sqlq -readonly ~/.zclassic-c23/consensus.db 'select 1'", 0, 0, A},
    {'b', "sqlite3 ~/.zclassic-c23/consensus.db 'select count(*) from blocks'", 0, 0, A},
    {'b', "sqlq ~/.zclassic-c23/c.db 'pragma table_info(x)'", 0, 0, A},
    {'b', "sed -i 's#~/.zclassic-c23#$HOME/x#' docs/a.md", 0, 0, A},
    {'b', "sed -i 's/.zclassic/.z/' docs/a.md", 0, 0, A},
    {'b', "sed -i s/auto_reindex_request/x/ docs/a.md", 0, 0, A},
    {'b', "sed -i -e 's/a/~\\/.zclassic-c23/' docs/a.md", 0, 0, A},
    {'b', "sed -ni -e 's/a/auto_reindex_request/p' docs/a.md", 0, 0, A},
    {'b', "rm docs/auto_reindex_request.md", 0, 0, A},
    {'b', "cp ~/.zclassic-c23-lab/debug.log /tmp/d.log", 0, 0, A},
    {'b', "rsync -a ~/.zclassic-c23-lab/ /tmp/b", 0, 0, A},
    {'b', "scp host:~/.zclassic-c23-lab/debug.log .", 0, 0, A},
    {'b', "curl -s https://example.com/sendmany-docs", 0, 0, A},
    {'b', "git push --help", 0, 0, A},
    {'b', "git push -h", 0, 0, A},
    {'b', "echo '$(git push)'", 0, 0, A},
    {'b', "echo \"plain text\" '`git push`'", 0, 0, A},
    {'b', "cd ~/.zclassic-c23 && ls && tail -n 5 debug.log", 0, 0, A},
    {'b', "cd ~/.zclassic-c23 && echo hi 2>&1", 0, 0, A},
    {'b', "cd ~/.zclassic-c23; cd /srv/w; rm x", 0, 0, A},
    {'b', "tar czf a.tgz -C ~/.zclassic-c23 .", 0, 0, A},
    {'b', "curl -o /srv/w/x https://example.com/a", 0, 0, A},
    {'b', "find ~/.zclassic-c23 -name '*.log' -print", 0, 0, A},
    {'b', "cat x.py", 0, 0, A},
    {'b', "grep -n foo tools/a.py", 0, 0, A},
    {'b', "rm tools/a.py", 0, 0, A},
    {'b', "git add tools/a.py", 0, 0, A},
    {'b', "z23-cli importprivkey a", 0, 0, A},
    {'b', "systemctl status apparmor", 0, 0, A},
    {'b', "systemctl restart z23-node", 0, 0, A},
    {'b', "git commit -m \"$(cat <<'EOF'\nuse `git push` never\nEOF\n)\"", 0, 0, A},
    {'b', "ssh h 'cd ~/.zclassic-c23-lab/pm; zcat a.gz | tar -xO log.txt | grep -a x'", 0, 0, A},
    {'b', "tar tf a.tar -C ~/.zclassic-c23 blocks", 0, 0, A},
    /* ---- review fixes: false negatives that must REFUSE ---- */
    {'b', "sqlq ~/.zclassic-c23/consensus.db \"delete from x\"", 0, 0, DD},
    {'b', "sqlq ~/.zclassic-c23/c.db 'PRAGMA journal_mode=wal'", 0, 0, DD},
    {'b', "sqlite3 ~/.zclassic-c23/c.db 'Drop table x'", 0, 0, DD},
    {'b', "sed -i -e s/a/b/ ~/.zclassic-c23/x.conf", 0, 0, DD},
    {'b', "rm ~/.zclassic-c23/auto_reindex_request", 0, 0, RF},
    {'b', "mv ~/.zclassic-c23/auto_reindex_request x", 0, 0, RF},
    {'b', "cp x ~/.zclassic-c23-lab/", 0, 0, DD},
    {'b', "cp -t ~/.zclassic-c23-lab x y", 0, 0, DD},
    {'b', "rsync -a /srv/w/ ~/.zclassic-c23-lab/", 0, 0, DD},
    {'b', "scp x host:~/.zclassic-c23-lab/", 0, 0, DD},
    {'b', "install -m 600 x ~/.zclassic-c23/node.conf", 0, 0, DD},
    {'b', "ln -s x ~/.zclassic-c23/y", 0, 0, DD},
    {'b', "echo \"$(git push)\"", 0, 0, GP},
    {'b', "out=\"$(git push 2>&1)\"", 0, 0, GP},
    {'b', "out=\"$(python3 -c 1)\"", 0, 0, PY},
    {'b', "echo \"`git push`\"", 0, 0, GP},
    {'b', "cd ~/.zclassic-c23-lab && rm -f x", 0, 0, DD},
    {'b', "cd ~/.zclassic-c23 && mv a b", 0, 0, DD},
    {'b', "cd ~/.zclassic-c23 && chmod 600 f", 0, 0, DD},
    {'b', "cd ~/.zclassic-c23 && tee f", 0, 0, DD},
    {'b', "cd ~/.zclassic-c23 && truncate -s 0 f", 0, 0, DD},
    {'b', "cd ~/.zclassic-c23 && echo hi > f", 0, 0, DD},
    {'b', "ssh host \"cd ~/.zclassic-c23-lab && rm -f x\"", 0, 0, DD},
    {'b', "ssh host \"echo hi > ~/.zclassic-c23-lab/x\"", 0, 0, DD},
    {'b', "tar xf a.tar -C ~/.zclassic-c23 blocks", 0, 0, DD},
    {'b', "tar -xzf a.tgz -C ~/.zclassic-c23 blocks", 0, 0, DD},
    {'b', "curl -o ~/.zclassic-c23/x https://example.com/a", 0, 0, DD},
    {'b', "curl -sSLo ~/.zclassic-c23/x https://example.com/a", 0, 0, DD},
    {'b', "curl --output=~/.zclassic-c23/x https://example.com/a", 0, 0, DD},
    {'b', "wget -O ~/.zclassic-c23/x https://example.com/a", 0, 0, DD},
    {'b', "find ~/.zclassic-c23 -delete", 0, 0, DD},
    {'b', "find ~/.zclassic-c23 -exec rm {} +", 0, 0, DD},
    {'b', "z23 --reindex-chainstate", 0, 0, RF},
    {'b', "zclassicd -reindex-chainstate", 0, 0, RF},
    {'b', "z23 -reindex-chainstate=1", 0, 0, RF},
    {'b', "xargs python3", 0, 0, PY},
    {'b', "eval \"python3 x\"", 0, 0, PY},
    {'b', "uv run x", 0, 0, PY},
    {'b', "pipx run tool", 0, 0, PY},
    {'b', "./x.py", 0, 0, PY},
    {'b', "x.py", 0, 0, PY},
    {'b', "env x.py", 0, 0, PY},
    {'b', "xargs ./x.py", 0, 0, PY},
    {'b', "Z=z23-cli; $Z dumpprivkey a", 0, 0, SP},
    {'b', "Z=z23-cli; ${Z} z_exportkey a", 0, 0, SP},
    {'b', "z23-cli backupwallet /srv/w/b", 0, 0, SP},
    {'b', "z23-cli walletpassphrase pw 60", 0, 0, SP},
    {'b', "z23-cli -rpcport=1 z_sendmany a b", 0, 0, SP},
    {'b', "z23 rpc z_exportviewingkey zs1x", 0, 0, SP},
    {'b', "curl -d '{\"method\":\"sendtoaddress\"}' http://localhost:8232", 0, 0, SP},
    {'b', "sudo vi /etc/sudoers", 0, 0, HC},
    {'b', "sudo nano /etc/sysctl.conf", 0, 0, HC},
    {'b', "sudo emacs /etc/apparmor.d/x", 0, 0, HC},
    {'b', "sudo tee /etc/sudoers.d/x", 0, 0, HC},
    {'b', "sudo sysctl --system", 0, 0, HC},
    {'b', "sudo systemctl stop apparmor", 0, 0, HC},
    {'b', "sudo systemctl disable apparmor.service", 0, 0, HC},
    {'b', "systemctl mask apparmor", 0, 0, HC},
    /* ---- shell structure ---- */
    {'b', "cat <<'EOF'\ngit push\nEOF\ngit status\n", 0, 0, A},
    {'b', "git commit -m \"$(cat <<'EOF'\nfix: say \"git push\" and don't python3\nEOF\n)\"", 0, 0, A},
    {'b', "ssh h sh -s <<'EOF'\ngit push\nEOF\n", 0, 0, GP},
    {'b', "echo ok\ngit push", 0, 0, GP},
    {'b', "ssh h \"cat > unit.service\" <<EOF\nExecStart=rm -rf ~/.zclassic-c23\nEOF\n", 0, 0, A},
    {'b', "bash -c 'echo hi' <<'EOF'\ngit push\nEOF\n", 0, 0, A},
    {'b', "bash <<'EOF'\ngit push\nEOF\n", 0, 0, GP},
    {'b', "ssh h <<'EOF'\ngit push\nEOF\n", 0, 0, GP},
    {'b', "echo ok \\\n  && echo more", 0, 0, A},
    {'b', "nohup rm -rf ~/.zclassic-c23/x &", 0, 0, DD},
    {'b', "git status 2>&1 | head", 0, 0, A},
    {'b', "make x &> build/scratch/log", 0, 0, A},
    {'b', "make x &> ~/.zclassic-c23/log", 0, 0, DD},
    {'b', "echo hi # python3 rm", 0, 0, A},
    {'b', "if true; then git push; fi", 0, 0, GP},
    {'b', "", 0, 0, A},
};

static int ag_run(const struct ag_case *c, char *buf, size_t cap)
{
    if (c->mode == 'b') {
        const char *argv[] = {AG_BIN, "--bash", c->arg1, NULL};
        return test_host_tool_capture(argv, buf, cap, 5000);
    }
    if (c->content) {
        const char *argv[] = {AG_BIN, "--path", c->arg1, c->arg2, c->content, NULL};
        return test_host_tool_capture(argv, buf, cap, 5000);
    }
    const char *argv[] = {AG_BIN, "--path", c->arg1, c->arg2, NULL};
    return test_host_tool_capture(argv, buf, cap, 5000);
}

static int test_agent_guard_table(void)
{
    int failures = 0;
    size_t n = sizeof ag_cases / sizeof ag_cases[0];
    size_t bad = 0;
    TEST("agent_guard: >= 280 table rows, each verdict exact") {
        ASSERT(n >= 280);
        for (size_t i = 0; i < n; i++) {
            char buf[256] = {0}, want[128];
            int rc;
            snprintf(want, sizeof want, "%s\n", ag_cases[i].want);
            rc = ag_run(&ag_cases[i], buf, sizeof buf);
            if (rc == 0 && strcmp(buf, want) == 0) continue;
            bad++;
            fprintf(stderr, "agent_guard row %zu: rc=%d got '%s' want '%s' for '%s'\n", i,
                    rc, buf, ag_cases[i].want, ag_cases[i].arg1);
        }
        ASSERT(bad == 0);
        PASS();
    } _test_next:;
    return failures;
}

/* Hook mode result: 1 refused (exit 2 plus the rule line on stderr), 0
 * allowed (exit 0, silent), -1 anything else. */
static int ag_hook(const char *json)
{
    char cmd[2048], buf[1024] = {0};
    const char *argv[] = {"sh", "-c", cmd, NULL};
    snprintf(cmd, sizeof cmd,
             "printf '%%s' '%s' | " AG_BIN " 2>&1 >/dev/null; echo rc=$?", json);
    if (test_host_tool_capture(argv, buf, sizeof buf, 5000) != 0) return -1;
    if (strstr(buf, "refused (") == NULL && strstr(buf, "rc=0\n") != NULL) return 0;
    if (strncmp(buf, "z23-agent-guard refused (guard.", 31) == 0 &&
        strstr(buf, "rc=2\n") != NULL)
        return 1;
    return -1;
}

static int test_agent_guard_hook(void)
{
    int failures = 0;
    TEST("agent_guard: hook exit codes (refuse 2, allow 0, garbage fails open)") {
        ASSERT(ag_hook("{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"git push origin HEAD\"}}") == 1);
        ASSERT(ag_hook("{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"git status\"}}") == 0);
        ASSERT(ag_hook("{\"tool_name\":\"Write\",\"tool_input\":{\"file_path\":\"/srv/w/x.md\",\"content\":\"hi\"}}") == 0);
        ASSERT(ag_hook("{\"tool_name\":\"Write\",\"tool_input\":{\"file_path\":\"/srv/w/x.py\",\"content\":\"1\"}}") == 1);
        ASSERT(ag_hook("not json") == 0);
        PASS();
    } _test_next:;
    return failures;
}

int test_agent_guard(void)
{
    int failures = 0;
    struct stat st;
    if (stat(AG_BIN, &st) != 0 || (st.st_mode & S_IXUSR) == 0) {
        fprintf(stderr, "agent_guard: required " AG_BIN " missing (run: make z23-agent-guard)\n");
        return 1;
    }
    failures += test_agent_guard_table();
    failures += test_agent_guard_hook();
    return failures;
}
