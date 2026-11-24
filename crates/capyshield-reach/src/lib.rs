//! Deterministic reachability facts for Node.js/TypeScript and Python packages:
//! manifests + lockfiles give the dependency scope, import statements in production code
//! (tests and excluded paths skipped) give `imported_in_prod`.

use globset::{Glob, GlobSetBuilder};
use regex::Regex;
use serde::Serialize;
use serde_json::Value as Json;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Ecosystem {
    Node,
    Python,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    Direct,
    Transitive,
    DevOnly,
    NotFound,
}

#[derive(Debug, Clone, Serialize)]
pub struct Facts {
    pub in_lockfile: bool,
    pub dependency_scope: Scope,
    pub imported_in_prod: bool,
    pub matched_files_count: usize,
    #[serde(skip)]
    pub matched_files: Vec<String>,
}

#[derive(Default, Debug)]
struct Eco {
    prod: HashSet<String>,
    dev: HashSet<String>,
    locked_prod: HashSet<String>,
    locked_dev: HashSet<String>,
    /// Imported package/module name -> production files importing it.
    imports: BTreeMap<String, BTreeSet<String>>,
}

#[derive(Debug, Default)]
pub struct Repo {
    node: Eco,
    python: Eco,
    pub files_scanned: usize,
}

const SKIP_DIRS: &[&str] = &[
    "node_modules",
    "__pycache__",
    "venv",
    "site-packages",
    "target",
    "bower_components",
    "jspm_packages",
];
const TEST_DIRS: &[&str] = &["test", "tests", "__tests__", "__mocks__", "spec", "e2e"];
const NODE_EXT: &[&str] = &["js", "mjs", "cjs", "jsx", "ts", "tsx", "mts", "cts", "vue", "svelte"];

static JS_IMPORT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?:\bfrom|\bimport|\brequire(?:\.resolve)?)\s*\(?\s*['"]([^'"\s]+)['"]"#).unwrap());

pub fn analyze(root: &Path, exclude: &[String], ecosystems: &[String]) -> Result<Repo, String> {
    let mut gs = GlobSetBuilder::new();
    for pattern in exclude {
        gs.add(Glob::new(pattern).map_err(|e| format!("exclude_paths {pattern:?}: {e}"))?);
    }
    let excluded = gs.build().map_err(|e| e.to_string())?;
    let (want_node, want_py) = (ecosystems.iter().any(|e| e == "node"), ecosystems.iter().any(|e| e == "python"));

    let mut files = vec![];
    walk(root, &mut files).map_err(|e| format!("{}: {e}", root.display()))?;
    let mut repo = Repo::default();
    for path in files {
        let rel = path.strip_prefix(root).unwrap_or(&path).to_string_lossy().replace('\\', "/");
        if excluded.is_match(&rel) || is_test_path(&rel) {
            continue;
        }
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or_default();
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or_default();
        let is_manifest = matches!(
            name,
            "package.json"
                | "package-lock.json"
                | "npm-shrinkwrap.json"
                | "pnpm-lock.yaml"
                | "yarn.lock"
                | "poetry.lock"
                | "uv.lock"
                | "pyproject.toml"
        ) || (name.starts_with("requirements") && ext == "txt");
        let is_source = (want_node && NODE_EXT.contains(&ext)) || (want_py && ext == "py");
        if !is_manifest && !is_source {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else { continue };
        let res = match name {
            "package.json" if want_node => node_manifest(&mut repo.node, &text),
            "package-lock.json" | "npm-shrinkwrap.json" if want_node => npm_lock(&mut repo.node, &text),
            "pnpm-lock.yaml" if want_node => pnpm_lock(&mut repo.node, &text),
            "yarn.lock" if want_node => {
                yarn_lock(&mut repo.node, &text);
                Ok(())
            }
            "poetry.lock" | "uv.lock" if want_py => python_lock(&mut repo.python, &text),
            "pyproject.toml" if want_py => pyproject(&mut repo.python, &text),
            _ if name.starts_with("requirements") && ext == "txt" && want_py => {
                requirements(&mut repo.python, &text, name.contains("dev") || name.contains("test"));
                Ok(())
            }
            _ if ext == "py" => {
                repo.files_scanned += 1;
                for m in python_imports(&text) {
                    repo.python.imports.entry(m).or_default().insert(rel.clone());
                }
                Ok(())
            }
            _ if is_source => {
                repo.files_scanned += 1;
                for m in JS_IMPORT.captures_iter(&text).filter_map(|c| node_package(&c[1])) {
                    repo.node.imports.entry(m).or_default().insert(rel.clone());
                }
                Ok(())
            }
            _ => Ok(()),
        };
        res.map_err(|e| format!("{rel}: {e}"))?;
    }
    Ok(repo)
}

impl Repo {
    pub fn facts(&self, eco: Ecosystem, package: &str) -> Facts {
        let (e, key) = match eco {
            Ecosystem::Node => (&self.node, package.to_ascii_lowercase()),
            Ecosystem::Python => (&self.python, pep503(package)),
        };
        let dependency_scope = if e.prod.contains(&key) {
            Scope::Direct
        } else if e.dev.contains(&key) {
            Scope::DevOnly
        } else if e.locked_prod.contains(&key) {
            Scope::Transitive
        } else if e.locked_dev.contains(&key) {
            Scope::DevOnly
        } else {
            Scope::NotFound
        };
        let names = match eco {
            Ecosystem::Node => vec![key.clone()],
            Ecosystem::Python => module_candidates(&key),
        };
        let matched: BTreeSet<&String> = names.iter().filter_map(|n| e.imports.get(n)).flatten().collect();
        Facts {
            in_lockfile: e.locked_prod.contains(&key) || e.locked_dev.contains(&key),
            dependency_scope,
            imported_in_prod: !matched.is_empty(),
            matched_files_count: matched.len(),
            matched_files: matched.into_iter().cloned().collect(),
        }
    }
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let ty = entry.file_type()?;
        if ty.is_dir() {
            if !name.starts_with('.') && !SKIP_DIRS.contains(&name.as_ref()) {
                walk(&entry.path(), out)?;
            }
        } else if ty.is_file() {
            out.push(entry.path());
        }
    }
    Ok(())
}

fn is_test_path(rel: &str) -> bool {
    let mut parts = rel.split('/').collect::<Vec<_>>();
    let file = parts.pop().unwrap_or_default();
    parts.iter().any(|p| TEST_DIRS.contains(p))
        || file.contains(".spec.")
        || file.contains(".test.")
        || (file.ends_with(".py") && (file.starts_with("test_") || file.ends_with("_test.py") || file == "conftest.py"))
}

// ---- Node.js ----

fn node_manifest(e: &mut Eco, text: &str) -> Result<(), String> {
    let v: Json = serde_json::from_str(text).map_err(|e| e.to_string())?;
    let keys = |field: &str| {
        v.get(field)
            .and_then(Json::as_object)
            .into_iter()
            .flat_map(|o| o.keys().map(|k| k.to_ascii_lowercase()))
    };
    e.prod.extend(
        keys("dependencies")
            .chain(keys("optionalDependencies"))
            .chain(keys("peerDependencies")),
    );
    e.dev.extend(keys("devDependencies"));
    // Packages executed through npm scripts (`next build`) run in prod without being imported.
    // ponytail: matches bin name == package name only; map package.json "bin" fields if that misses.
    let scripts = v.get("scripts").and_then(Json::as_object).into_iter().flatten();
    let prod_scripts = scripts.filter(|(name, _)| {
        !["test", "lint", "format", "pretest", "posttest"]
            .iter()
            .any(|p| name.starts_with(p))
    });
    for script in prod_scripts.filter_map(|(_, s)| s.as_str()) {
        for word in script
            .split(|c: char| c.is_whitespace() || ";&|()".contains(c))
            .filter(|w| !w.is_empty())
        {
            e.imports
                .entry(word.to_ascii_lowercase())
                .or_default()
                .insert("package.json#scripts".into());
        }
    }
    Ok(())
}

fn npm_lock(e: &mut Eco, text: &str) -> Result<(), String> {
    let v: Json = serde_json::from_str(text).map_err(|e| e.to_string())?;
    let is_dev =
        |p: &Json| p.get("dev").and_then(Json::as_bool).unwrap_or(false) || p.get("devOptional").and_then(Json::as_bool).unwrap_or(false);
    if let Some(pkgs) = v.get("packages").and_then(Json::as_object) {
        for (path, p) in pkgs {
            if let Some((_, name)) = path.rsplit_once("node_modules/") {
                let set = if is_dev(p) { &mut e.locked_dev } else { &mut e.locked_prod };
                set.insert(name.to_ascii_lowercase());
            }
        }
    } else {
        // lockfileVersion 1: nested "dependencies" trees.
        let mut stack = vec![&v];
        while let Some(node) = stack.pop() {
            for (name, p) in node.get("dependencies").and_then(Json::as_object).into_iter().flatten() {
                let set = if is_dev(p) { &mut e.locked_dev } else { &mut e.locked_prod };
                set.insert(name.to_ascii_lowercase());
                stack.push(p);
            }
        }
    }
    Ok(())
}

fn pnpm_lock(e: &mut Eco, text: &str) -> Result<(), String> {
    let v: serde_yaml::Value = serde_yaml::from_str(text).map_err(|e| e.to_string())?;
    for (key, p) in v.get("packages").and_then(|p| p.as_mapping()).into_iter().flatten() {
        let Some(key) = key.as_str() else { continue };
        let k = key.trim_start_matches('/');
        let k = k.split('(').next().unwrap_or(k);
        // v6+/v9: name@version, v5: name/version
        let name = match k.get(1..).and_then(|r| r.find('@')) {
            Some(i) => &k[..=i],
            None => k.rsplit_once('/').map_or(k, |(n, _)| n),
        };
        let dev = p.get("dev").and_then(|d| d.as_bool()).unwrap_or(false);
        (if dev { &mut e.locked_dev } else { &mut e.locked_prod }).insert(name.to_ascii_lowercase());
    }
    Ok(())
}

fn yarn_lock(e: &mut Eco, text: &str) {
    for line in text.lines().filter(|l| !l.starts_with([' ', '\t', '#']) && l.ends_with(':')) {
        for spec in line.trim_end_matches(':').split(", ") {
            let spec = spec.trim_matches('"');
            if let Some(i) = spec
                .get(1..)
                .and_then(|r| r.find('@'))
                .map(|i| i + 1)
                .filter(|_| !spec.starts_with("__"))
            {
                e.locked_prod.insert(spec[..i].to_ascii_lowercase());
            }
        }
    }
}

/// `lodash/fp` -> `lodash`, `@scope/pkg/x` -> `@scope/pkg`; relative paths, URLs and `node:` builtins -> None.
fn node_package(spec: &str) -> Option<String> {
    if spec.starts_with(['.', '/', '#', '~']) || spec.starts_with("node:") || spec.contains("://") {
        return None;
    }
    let mut parts = spec.split('/');
    let first = parts.next()?;
    let name = if first.starts_with('@') {
        format!("{first}/{}", parts.next()?)
    } else {
        first.to_string()
    };
    Some(name.to_ascii_lowercase())
}

// ---- Python ----

/// PEP 503 normalized distribution name.
pub fn pep503(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for c in name.trim().chars() {
        if matches!(c, '-' | '_' | '.') {
            if !out.ends_with('-') {
                out.push('-');
            }
        } else {
            out.push(c.to_ascii_lowercase());
        }
    }
    out
}

fn pep508_name(req: &str) -> Option<String> {
    let end = req
        .trim()
        .find(|c: char| !(c.is_ascii_alphanumeric() || "-_.".contains(c)))
        .unwrap_or(req.trim().len());
    let name = &req.trim()[..end];
    (!name.is_empty()).then(|| pep503(name))
}

fn requirements(e: &mut Eco, text: &str, dev: bool) {
    for line in text.lines().map(|l| l.split(" #").next().unwrap_or("").trim()) {
        if line.is_empty() || line.starts_with(['#', '-']) {
            continue;
        }
        if let Some(name) = pep508_name(line) {
            let (direct, locked) = if dev {
                (&mut e.dev, &mut e.locked_dev)
            } else {
                (&mut e.prod, &mut e.locked_prod)
            };
            direct.insert(name.clone());
            locked.insert(name);
        }
    }
}

fn python_lock(e: &mut Eco, text: &str) -> Result<(), String> {
    let v: toml::Value = toml::from_str(text).map_err(|e| e.to_string())?;
    for p in v.get("package").and_then(|p| p.as_array()).into_iter().flatten() {
        let Some(name) = p.get("name").and_then(|n| n.as_str()) else {
            continue;
        };
        let category_dev = p.get("category").and_then(|c| c.as_str()) == Some("dev");
        let groups_dev = p
            .get("groups")
            .and_then(|g| g.as_array())
            .is_some_and(|g| !g.iter().any(|x| x.as_str() == Some("main")));
        (if category_dev || groups_dev {
            &mut e.locked_dev
        } else {
            &mut e.locked_prod
        })
        .insert(pep503(name));
    }
    Ok(())
}

fn pyproject(e: &mut Eco, text: &str) -> Result<(), String> {
    let v: toml::Value = toml::from_str(text).map_err(|e| e.to_string())?;
    let get = |path: &[&str]| path.iter().try_fold(&v, |cur, k| cur.get(k));
    let strings = |x: Option<&toml::Value>| -> Vec<String> {
        x.and_then(|a| a.as_array())
            .into_iter()
            .flatten()
            .filter_map(|s| s.as_str())
            .filter_map(pep508_name)
            .collect()
    };
    let keys = |x: Option<&toml::Value>| -> Vec<String> {
        x.and_then(|t| t.as_table())
            .into_iter()
            .flat_map(|t| t.keys())
            .filter(|k| *k != "python")
            .map(|k| pep503(k))
            .collect()
    };
    e.prod.extend(strings(get(&["project", "dependencies"])));
    for extra in get(&["project", "optional-dependencies"])
        .and_then(|t| t.as_table())
        .into_iter()
        .flat_map(|t| t.values())
    {
        e.prod.extend(strings(Some(extra)));
    }
    for group in get(&["dependency-groups"])
        .and_then(|t| t.as_table())
        .into_iter()
        .flat_map(|t| t.values())
    {
        e.dev.extend(strings(Some(group)));
    }
    e.dev.extend(strings(get(&["tool", "uv", "dev-dependencies"])));
    e.prod.extend(keys(get(&["tool", "poetry", "dependencies"])));
    e.dev.extend(keys(get(&["tool", "poetry", "dev-dependencies"])));
    for (name, group) in get(&["tool", "poetry", "group"]).and_then(|t| t.as_table()).into_iter().flatten() {
        let deps = keys(group.get("dependencies"));
        if name == "main" { e.prod.extend(deps) } else { e.dev.extend(deps) }
    }
    Ok(())
}

/// Top-level module names from `import a.b, c` / `from a.b import c` lines (relative imports skipped).
fn python_imports(text: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for line in text.lines().map(str::trim_start) {
        let modules: Vec<&str> = if let Some(rest) = line.strip_prefix("import ") {
            rest.split(',').filter_map(|m| m.split_whitespace().next()).collect()
        } else if let Some(rest) = line.strip_prefix("from ") {
            rest.split_whitespace().next().into_iter().collect()
        } else {
            continue;
        };
        for m in modules.into_iter().filter(|m| !m.starts_with('.')) {
            let top = m.split('.').next().unwrap_or(m).trim_end_matches(['(', ';']);
            if !top.is_empty() {
                out.insert(top.to_ascii_lowercase());
            }
        }
    }
    out
}

/// Import names a distribution may be imported as.
// ponytail: name heuristics + a small table; read site-packages top_level.txt if this misses too often.
fn module_candidates(dist: &str) -> Vec<String> {
    const TABLE: &[(&str, &str)] = &[
        ("beautifulsoup4", "bs4"),
        ("pillow", "pil"),
        ("opencv-python", "cv2"),
        ("opencv-python-headless", "cv2"),
        ("opencv-contrib-python", "cv2"),
        ("scikit-learn", "sklearn"),
        ("scikit-image", "skimage"),
        ("pycryptodome", "crypto"),
        ("pycryptodomex", "cryptodome"),
        ("attrs", "attr"),
        ("gitpython", "git"),
        ("protobuf", "google"),
        ("grpcio", "grpc"),
        ("mysqlclient", "mysqldb"),
        ("pyzmq", "zmq"),
        ("pywin32", "win32api"),
        ("setuptools", "pkg_resources"),
        ("ruamel-yaml", "ruamel"),
        ("faiss-cpu", "faiss"),
        ("opensearch-py", "opensearchpy"),
        ("discord-py", "discord"),
        ("python-telegram-bot", "telegram"),
        ("pymupdf", "fitz"),
        ("pdfminer-six", "pdfminer"),
        ("google-api-python-client", "googleapiclient"),
        ("pymongo", "bson"),
        ("msgpack-python", "msgpack"),
        ("tensorflow-gpu", "tensorflow"),
        ("pyyaml", "yaml"),
    ];
    let mut out = vec![dist.replace('-', "_")];
    for (prefix_or_suffix, is_prefix) in [
        ("python-", true),
        ("py", true),
        ("-python", false),
        ("-binary", false),
        ("-py", false),
    ] {
        let stripped = if is_prefix {
            dist.strip_prefix(prefix_or_suffix)
        } else {
            dist.strip_suffix(prefix_or_suffix)
        };
        out.extend(stripped.filter(|s| !s.is_empty()).map(|s| s.replace('-', "_")));
    }
    for ns in ["google", "azure", "zope", "jaraco"] {
        if dist.starts_with(&format!("{ns}-")) {
            out.push(ns.into());
        }
    }
    out.extend(TABLE.iter().filter(|(d, _)| *d == dist).map(|(_, m)| m.to_string()));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(files: &[(&str, &str)]) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("capyshield-reach-{}-{}", std::process::id(), files.len()));
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
        let dir = fixture(&[
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
        ]);
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
        let dir = fixture(&[
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
        ]);
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
        let mut e = Eco::default();
        pnpm_lock(&mut e, "packages:\n  /@babel/core@7.0.0:\n    dev: true\n  lodash@4.17.21: {}\n  /react/18.2.0: {}\n  '@x/y@1.0.0(react@18.2.0)': {}\n").unwrap();
        assert!(e.locked_dev.contains("@babel/core"));
        assert!(e.locked_prod.contains("lodash") && e.locked_prod.contains("react") && e.locked_prod.contains("@x/y"));
        yarn_lock(
            &mut e,
            "__metadata:\n  version: 6\n\"@types/node@^20\", \"@types/node@npm:^20\":\n  version 20\nleft-pad@^1.0.0:\n",
        );
        assert!(e.locked_prod.contains("@types/node") && e.locked_prod.contains("left-pad"));
        assert!(!e.locked_prod.iter().any(|n| n.starts_with("__")));
    }
}
