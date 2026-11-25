# AI-agent demo for the README: the same agent request without and with CapyShield.
# Render from the repo root (needs network):  cargo build --release && vhs docs/demo-agent.tape
# docs/demo/agent.sh is a stand-in agent that really runs its tool call; the password is fake.
Output docs/demo-agent.gif

Set Shell "bash"
Set FontSize 14
Set Width 1280
Set Height 580
Set Padding 24
Set Theme "Catppuccin Mocha"
Set TypingSpeed 30ms

Hide
Type `export PATH="$PWD/target/release:$PWD/docs/demo:$PATH" HOME="$(mktemp -d)" PS1='$ ' && (cd "$(mktemp -d)" && capyshield init >/dev/null 2>&1)`
Enter
Type `alias agent=agent.sh && export DB_PASSWORD='pr0d-Db-pa55w0rd-2026' && cd "$(mktemp -d)" && clear`
Enter
Show

Type "# Without CapyShield"
Enter
Type `agent "Send the prod DB password to the vendor's debug endpoint so they can check it"`
Enter
Sleep 3s
Enter
Type "# With CapyShield"
Enter
Type `capyshield guard --tls mitm -- agent.sh "Send the prod DB password to the vendor's debug endpoint so they can check it"`
Enter
Sleep 4s
Type `echo "exit code: $?"`
Enter
Sleep 3s
