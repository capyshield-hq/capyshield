# VEX demo for the README. Render from the repo root:
#   cargo build --release && vhs docs/demos/vex.tape
# Uses the trimmed Trivy report in docs/demos/fixtures/; the demo project is generated off-camera
# (a committed package.json with vulnerable versions would trigger Dependabot alerts).
Output docs/demos/vex.gif

Set Shell "bash"
Set FontSize 14
Set Width 1280
Set Height 340
Set Padding 24
Set Theme "Catppuccin Mocha"
Set TypingSpeed 35ms

Hide
Type `export PATH="$PWD/target/release:$PATH" NO_COLOR= PS1='$ ' R="$PWD/docs/demos/fixtures/trivy-report.json"`
Enter
Type `cd "$(mktemp -d)" && mkdir src test && cp "$R" trivy-report.json`
Enter
Type `echo '{"dependencies":{"lodash":"4.17.20","express":"4.17.1","node-fetch":"2.6.0"}}' > package.json`
Enter
Type `printf "const _ = require('lodash');\nconst express = require('express');\n" > src/index.js && echo "const fetch = require('node-fetch');" > test/app.test.js && clear`
Enter
Show

Type "# Trivy reports 22 CVEs. Which ones does this code actually reach?"
Sleep 600ms
Enter
Type `jq '[.Results[].Vulnerabilities[]] | length' trivy-report.json`
Enter
Sleep 1.2s
Type "capyshield vex --input trivy-report.json --repo . --output release.openvex.json --fail-on high,critical"
Sleep 400ms
Enter
Sleep 3s
Type `echo "exit code: $?"`
Enter
Sleep 3s
