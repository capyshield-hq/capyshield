use capyshield_reach::*;
use std::path::PathBuf;

fn fixture(name: &str, files: &[(&str, &str)]) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("capyshield-reach-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    for (path, body) in files {
        let p = dir.join(path);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, body).unwrap();
    }
    dir
}

#[test]
fn node_facts() {
    let dir = fixture(
        "node",
        &[
            (
                "package.json",
                r#"{"dependencies":{"lodash":"^4","@scope/ui":"1"},"devDependencies":{"jest":"29","unused-dev":"1"}}"#,
            ),
            (
                "package-lock.json",
                r#"{"lockfileVersion":3,"packages":{"":{},"node_modules/lodash":{},"node_modules/@scope/ui":{},"node_modules/jest":{"dev":true},"node_modules/minimist":{},"node_modules/jest/node_modules/chalk":{"dev":true}}}"#,
            ),
            (
                "src/index.ts",
                "import _ from 'lodash/fp';\nimport { Button } from \"@scope/ui/button\";\nconst x = require('./local');",
            ),
            ("test/a.test.js", "const minimist = require('minimist');"),
            ("src/b.spec.ts", "import jest from 'jest';"),
            ("docs/example.js", "require('chalk')"),
        ],
    );
    let repo = analyze(&dir, &["docs/**".into()], &["node".into()]).unwrap();
    let f = repo.facts(Ecosystem::Node, "lodash");
    assert_eq!(
        (f.dependency_scope, f.in_lockfile, f.imported_in_prod, f.matched_files_count),
        (Scope::Direct, true, true, 1)
    );
    assert!(repo.facts(Ecosystem::Node, "@scope/ui").imported_in_prod);
    let jest = repo.facts(Ecosystem::Node, "jest");
    assert_eq!((jest.dependency_scope, jest.imported_in_prod), (Scope::DevOnly, false));
    let chalk = repo.facts(Ecosystem::Node, "chalk");
    assert_eq!((chalk.dependency_scope, chalk.imported_in_prod), (Scope::DevOnly, false));
    let minimist = repo.facts(Ecosystem::Node, "minimist");
    assert_eq!((minimist.dependency_scope, minimist.imported_in_prod), (Scope::Transitive, false));
    assert_eq!(repo.facts(Ecosystem::Node, "left-pad").dependency_scope, Scope::NotFound);
}

#[test]
fn python_facts() {
    let dir = fixture(
        "python",
        &[
            (
                "pyproject.toml",
                "[project]\nname='app'\ndependencies=['PyYAML>=6', 'requests[socks]~=2.31', 'Pillow']\n[dependency-groups]\ndev=['pytest>=8']\n",
            ),
            (
                "uv.lock",
                "version = 1\n[[package]]\nname = \"pyyaml\"\n[[package]]\nname = \"urllib3\"\n[[package]]\nname = \"pytest\"\n",
            ),
            ("app/main.py", "import os, yaml\nfrom PIL import Image\nfrom . import util\n"),
            ("tests/test_main.py", "import requests\nimport pytest\n"),
        ],
    );
    let repo = analyze(&dir, &[], &["python".into()]).unwrap();
    let y = repo.facts(Ecosystem::Python, "PyYAML");
    assert_eq!((y.dependency_scope, y.in_lockfile, y.imported_in_prod), (Scope::Direct, true, true));
    assert!(repo.facts(Ecosystem::Python, "pillow").imported_in_prod);
    let r = repo.facts(Ecosystem::Python, "requests");
    assert_eq!((r.dependency_scope, r.imported_in_prod), (Scope::Direct, false));
    assert_eq!(repo.facts(Ecosystem::Python, "pytest").dependency_scope, Scope::DevOnly);
    assert_eq!(repo.facts(Ecosystem::Python, "urllib3").dependency_scope, Scope::Transitive);
}

#[test]
fn lockfile_name_parsing() {
    let node = ["node".to_string()];
    let dir = fixture(
        "pnpm",
        &[(
            "pnpm-lock.yaml",
            "packages:\n  /@babel/core@7.0.0:\n    dev: true\n  lodash@4.17.21: {}\n  /react/18.2.0: {}\n  '@x/y@1.0.0(react@18.2.0)': {}\n",
        )],
    );
    let repo = analyze(&dir, &[], &node).unwrap();
    assert_eq!(repo.facts(Ecosystem::Node, "@babel/core").dependency_scope, Scope::DevOnly);
    for p in ["lodash", "react", "@x/y"] {
        assert_eq!(repo.facts(Ecosystem::Node, p).dependency_scope, Scope::Transitive, "{p}");
    }
    let dir = fixture(
        "yarn",
        &[(
            "yarn.lock",
            "__metadata:\n  version: 6\n\"@types/node@^20\", \"@types/node@npm:^20\":\n  version 20\nleft-pad@^1.0.0:\n",
        )],
    );
    let repo = analyze(&dir, &[], &node).unwrap();
    for p in ["@types/node", "left-pad"] {
        assert_eq!(repo.facts(Ecosystem::Node, p).dependency_scope, Scope::Transitive, "{p}");
    }
    assert!(!repo.facts(Ecosystem::Node, "__metadata").in_lockfile);
}
