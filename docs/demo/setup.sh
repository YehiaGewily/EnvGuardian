# Sourced (hidden) at the start of demo.tape. Builds a throwaway world with a
# shared "origin" remote and three people, each with their own SSH key.
# All values below are fake demo values.

DEMO="${DEMO:-/demo}"
export DEMO
export GIT_CONFIG_GLOBAL="$DEMO/gitconfig"

rm -rf "$DEMO/keys" "$DEMO/origin.git" "$DEMO/alice" "$DEMO/bob" "$DEMO/mallory"
mkdir -p "$DEMO/keys"
git config --global init.defaultBranch main
git config --global advice.detachedHead false
for p in alice bob mallory; do
  ssh-keygen -q -t ed25519 -N "" -C "$p" -f "$DEMO/keys/$p" >/dev/null
done

git init -q --bare "$DEMO/origin.git"
git clone -q "$DEMO/origin.git" "$DEMO/alice" 2>/dev/null
printf 'DATABASE_URL=postgres://app:hunter2@localhost/app\nSTRIPE_KEY=sk_test_51Demo\nNODE_ENV=development\n' > "$DEMO/alice/.env"

# `as NAME` switches the person at the keyboard: their repo, key, and prompt.
as() {
  cd "$DEMO/$1" || return
  export ENVGUARDIAN_IDENTITY="$DEMO/keys/$1"
  export GIT_AUTHOR_NAME="$1" GIT_AUTHOR_EMAIL="$1@example.com"
  export GIT_COMMITTER_NAME="$1" GIT_COMMITTER_EMAIL="$1@example.com"
  PS1="\[\e[1;36m\]$1\[\e[0m\] \[\e[2m\]~/app\[\e[0m\] \$ "
}

# Mallory's edit, shown by name in the video: add herself as a recipient and write her own .env.
add_mallory_to_recipients() {
  printf '\n[[recipient]]\n  name = "mallory"\n  keys = ["%s"]\n  source = "manual"\n' \
    "$(cut -d' ' -f1,2 "$DEMO/keys/mallory.pub")" >> .envguardian/recipients.toml
  printf 'DATABASE_URL=postgres://app:x@evil.example/app\nSTRIPE_KEY=sk_test_51Demo\nNODE_ENV=development\n' > .env
}
