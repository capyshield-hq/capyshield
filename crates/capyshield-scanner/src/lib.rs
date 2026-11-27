//! Deterministic outbound-payload scanner: builtin credential patterns (Aho-Corasick prefilter +
//! regex), runtime ENV value fingerprints, Shannon entropy and basic PII.
//! ENV values only live in memory; findings carry the variable *name*, never the value.

mod patterns;

use aho_corasick::{AhoCorasick, AhoCorasickBuilder};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use capyshield_policy::{Pii, Scan};
use regex::bytes::{Regex, RegexBuilder};
use std::collections::BTreeSet;

pub use patterns::RULES;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Finding {
    /// `secret_leak` or `pii_detected`.
    pub category: &'static str,
    /// Builtin pattern id, `env:NAME`, `high_entropy`, or PII kind.
    pub id: String,
}

impl Finding {
    pub fn rule_id(&self) -> String {
        format!("{}:{}", self.category, self.id)
    }
}

pub struct Scanner {
    prefilter: Option<AhoCorasick>,
    /// Prefilter pattern index -> rule index.
    keyword_rule: Vec<usize>,
    rules: Vec<(&'static str, Regex)>,
    env: Option<AhoCorasick>,
    env_names: Vec<String>,
    pii: Vec<(Pii, Regex)>,
    entropy_threshold: Option<f64>,
}

const SENSITIVE_NAME_PARTS: &[&str] = &[
    "KEY",
    "SECRET",
    "TOKEN",
    "PASSWORD",
    "PASSWD",
    "CREDENTIAL",
    "PRIVATE",
    "AUTH",
    "DSN",
];
const DEFAULT_ENV_EXCLUDE: &[&str] = &[
    "PATH",
    "HOME",
    "PWD",
    "OLDPWD",
    "LANG",
    "SHELL",
    "USER",
    "TERM",
    "TMPDIR",
    "SSH_AUTH_SOCK",
    "XAUTHORITY",
];
const MIN_ENV_VALUE_LEN: usize = 8;

fn bytes_regex(re: &str) -> Regex {
    RegexBuilder::new(re)
        .unicode(false)
        .build()
        .unwrap_or_else(|e| panic!("bad builtin regex {re}: {e}"))
}

fn ac(patterns: &[impl AsRef<[u8]>]) -> Option<AhoCorasick> {
    (!patterns.is_empty()).then(|| {
        AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .build(patterns)
            .expect("aho-corasick build")
    })
}

impl Scanner {
    /// `env` is the process environment to fingerprint (normally `std::env::vars()`).
    pub fn new(cfg: &Scan, env: impl IntoIterator<Item = (String, String)>) -> Scanner {
        let (mut keywords, mut keyword_rule, mut rules) = (vec![], vec![], vec![]);
        if cfg.builtin_secret_patterns {
            for (i, (id, kws, re)) in RULES.iter().enumerate() {
                rules.push((*id, bytes_regex(re)));
                for kw in *kws {
                    keywords.push(*kw);
                    keyword_rule.push(i);
                }
            }
        }

        let (mut env_values, mut env_names) = (vec![], vec![]);
        if cfg.runtime_env_fingerprints {
            for (name, value) in env {
                let upper = name.to_ascii_uppercase();
                let sensitive = SENSITIVE_NAME_PARTS.iter().any(|p| upper.contains(p)) || cfg.env_include.iter().any(|n| n == &name);
                let excluded = DEFAULT_ENV_EXCLUDE.contains(&upper.as_str()) || cfg.env_exclude.iter().any(|n| n == &name);
                if !sensitive || excluded || value.len() < MIN_ENV_VALUE_LEN {
                    continue;
                }
                // ponytail: base64 variants only catch the value when it starts on a 3-byte boundary of
                // the encoded blob; add the two shifted encodings if that ever matters.
                let variants: BTreeSet<String> = [
                    value.clone(),
                    STANDARD.encode(&value),
                    STANDARD_NO_PAD.encode(&value),
                    URL_SAFE_NO_PAD.encode(&value),
                    url_encode(&value),
                    hex::encode(&value),
                    hex::encode_upper(&value),
                ]
                .into();
                for v in variants {
                    env_values.push(v);
                    env_names.push(name.clone());
                }
            }
        }

        let pii = cfg
            .pii_patterns
            .iter()
            .map(|p| {
                let re = match p {
                    Pii::Email => r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b",
                    Pii::CreditCard => r"\b(?:\d[ -]?){12,18}\d\b",
                    Pii::Ssn => r"\b(?:00[1-9]|0[1-9]\d|[1-578]\d{2}|6[0-57-9]\d|66[0-57-9])-(?:0[1-9]|[1-9]\d)-(?:000[1-9]|00[1-9]\d|0[1-9]\d{2}|[1-9]\d{3})\b",
                    // Indonesian NIK: province(2) regency(2) district(2) DDMMYY (+40 on DD for women) serial(4).
                    Pii::Nik => r"\b[1-9]\d{5}(?:[0-6]\d|7[01])(?:0[1-9]|1[0-2])\d{2}\d{4}\b",
                    Pii::PrivateKey => r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----",
                };
                (*p, bytes_regex(re))
            })
            .collect();

        Scanner {
            prefilter: ac(&keywords),
            keyword_rule,
            rules,
            env: ac(&env_values),
            env_names,
            pii,
            entropy_threshold: cfg.high_entropy.then_some(cfg.entropy_threshold),
        }
    }

    pub fn env_fingerprint_count(&self) -> usize {
        self.env_names.iter().collect::<BTreeSet<_>>().len()
    }

    /// Credential patterns, ENV fingerprints and PII in arbitrary bytes. Sorted and deduplicated.
    pub fn scan(&self, data: &[u8]) -> Vec<Finding> {
        let mut out = BTreeSet::new();
        if let Some(pf) = &self.prefilter {
            let candidates: BTreeSet<usize> = pf
                .find_overlapping_iter(data)
                .map(|m| self.keyword_rule[m.pattern().as_usize()])
                .collect();
            for i in candidates {
                let (id, re) = &self.rules[i];
                if re.is_match(data) {
                    out.insert(Finding {
                        category: "secret_leak",
                        id: id.to_string(),
                    });
                }
            }
        }
        if let Some(env) = &self.env {
            for m in env.find_overlapping_iter(data) {
                out.insert(Finding {
                    category: "secret_leak",
                    id: format!("env:{}", self.env_names[m.pattern().as_usize()]),
                });
            }
        }
        for (kind, re) in &self.pii {
            let hit = match kind {
                Pii::CreditCard => re.find_iter(data).any(|m| luhn(m.as_bytes())),
                _ => re.is_match(data),
            };
            if hit {
                out.insert(Finding {
                    category: "pii_detected",
                    id: pii_name(*kind).into(),
                });
            }
        }
        out.into_iter().collect()
    }

    /// High-entropy token check for a header value or query parameter value.
    pub fn scan_entropy(&self, value: &str) -> Option<Finding> {
        let threshold = self.entropy_threshold?;
        value
            .split(|c: char| !(c.is_ascii_alphanumeric() || "+/=_-".contains(c)))
            // Subresource-integrity hashes (`sha512-...`) are high-entropy by design.
            .filter(|tok| !["sha1-", "sha256-", "sha384-", "sha512-"].iter().any(|p| tok.starts_with(p)))
            .any(|tok| tok.len() >= 24 && shannon(tok.as_bytes()) >= threshold)
            .then(|| Finding {
                category: "secret_leak",
                id: "high_entropy".into(),
            })
    }
}

pub fn pii_name(p: Pii) -> &'static str {
    match p {
        Pii::Email => "email",
        Pii::CreditCard => "credit_card",
        Pii::Ssn => "ssn",
        Pii::Nik => "nik",
        Pii::PrivateKey => "private_key",
    }
}

/// Shannon entropy in bits per byte.
pub fn shannon(data: &[u8]) -> f64 {
    let mut counts = [0usize; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let n = data.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| c as f64 / n)
        .map(|p| -p * p.log2())
        .sum()
}

fn luhn(raw: &[u8]) -> bool {
    let digits: Vec<u32> = raw.iter().filter(|b| b.is_ascii_digit()).map(|b| (b - b'0') as u32).collect();
    if !(13..=19).contains(&digits.len()) || digits.iter().all(|&d| d == digits[0]) {
        return false;
    }
    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &d)| if i % 2 == 1 { if d * 2 > 9 { d * 2 - 9 } else { d * 2 } } else { d })
        .sum();
    sum.is_multiple_of(10)
}

fn url_encode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}
