# EnvGuardian demo video. Records a real terminal session with VHS.
#
#   GOOS=linux GOARCH=amd64 go build -o docs/demo/envguardian ./cmd/envguardian
#   docker build -t envguardian-vhs docs/demo
#   docker run --rm -v "$PWD/docs/demo:/vhs" envguardian-vhs demo.tape
#
# Output: docs/demo/envguardian-demo.mp4. README GIF: ffmpeg from the MP4 (see below).
# The "# ..." lines are the captions: LinkedIn autoplays muted.

Output envguardian-demo.mp4

Set Shell bash
Set FontSize 24
Set Width 1920
Set Height 1080
Set Padding 48
Set Theme "Catppuccin Mocha"
Set WindowBar Colorful
Set TypingSpeed 40ms

Hide
Type "source /demo/setup.sh && as alice && clear" Enter
Sleep 2s
Show

# ── Scene 1: Alice shares the team's .env, without Slack ──────────────
Type "# Every team has a .env. Usually someone pastes it into Slack." Enter
Sleep 1.5s
Type "cat .env" Enter
Sleep 2s
Type "envguardian init --name alice" Enter
Sleep 2.5s
Type "envguardian encrypt" Enter
Sleep 1.5s
Type "envguardian add-recipient --name bob --ssh ../keys/bob.pub" Enter
Sleep 2s
Type "git add -A && git commit -qm 'add encrypted env' && git push -q" Enter
Sleep 2s

Hide
Type "clear && git clone -q $DEMO/origin.git $DEMO/bob && as bob && clear" Enter
Sleep 1s
Show

# ── Scene 2: Bob joins the team ───────────────────────────────────────
Type "# Bob just cloned the repo. Only the encrypted file is there." Enter
Sleep 1.5s
Type "ls -A" Enter
Sleep 1.5s
Type "envguardian decrypt --accept-changes" Enter
Sleep 2s
Type "cat .env" Enter
Sleep 2.5s

Hide
Type "clear && git clone -q $DEMO/origin.git $DEMO/mallory && as mallory && git checkout -qb tidy-config && clear" Enter
Sleep 1s
Show

# ── Scene 3: Mallory is not on the team ───────────────────────────────
Type "# Mallory isn't a recipient, so she can't read the secrets." Enter
Sleep 1.5s
Type "envguardian decrypt --accept-changes" Enter
Sleep 2.5s
Type "# So she adds herself to recipients.toml and re-seals by force..." Enter
Sleep 1s
Type "add_mallory_to_recipients" Enter
Sleep 1s
Type "envguardian encrypt --force" Enter
Sleep 2s
Type "git commit -qam 'chore: tidy config'" Enter
Sleep 1s
Type "# ...and opens a PR. CI checks it against main:" Enter
Sleep 1.5s
Type "envguardian check --base origin/main" Enter
Sleep 5s

Type "clear" Enter
Type "# Commit your .env to git. Encrypted.  github.com/YehiaGewily/EnvGuardian" Enter
Sleep 4s
