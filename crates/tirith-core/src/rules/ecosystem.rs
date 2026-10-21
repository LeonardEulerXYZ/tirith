use once_cell::sync::Lazy;
use regex::Regex;

use crate::parse::UrlLike;
use crate::util::levenshtein;
use crate::verdict::{Evidence, Finding, RuleId, Severity};

/// Conservative command evidence for Python package sources. This is not a
/// shell validator: quoted, wrapped, malformed and embedded invocations must
/// not become an exemption merely because we cannot fully resolve them.
#[derive(Clone, Copy)]
pub struct PythonPackageContext {
    package_source: bool,
    ambiguous_install: bool,
}

static PYTHON_PACKAGE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:^|[^a-z0-9_])(?:pip(?:[0-9]+(?:\.[0-9]+)*)?(?:\.exe)?|uv(?:\.exe)?)(?:$|[^a-z0-9_])|(?:^|\s)-mpip(?:$|\s)|(?:PIP|UV)_(?:EXTRA_)?INDEX(?:_URL)?\s*=|--(?:extra-)?index(?:-url)?(?:[=\s]|$)|--find-links(?:[=\s]|$)").unwrap()
});
static INSTALL_ACTION_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b(?:install|add|sync|download|wheel)\b").unwrap()
});

impl PythonPackageContext {
    pub fn from_command(input: &str, urls: &[crate::extract::ExtractedUrl]) -> Self {
        // URL paths, hosts and query values are operands, not installer evidence.
        // Use the same extraction as the engine rather than a second URL grammar.
        // Longest first handles a URL that is a prefix of another one. Keep
        // expansions inside URLs conservative: they can contain executable code.
        // Bare DockerRef names (e.g. "pip") are not URL literals: replacing them
        // globally could erase a real installer token in a different segment.
        let mut literals: Vec<&str> = urls
            .iter()
            .filter(|url| matches!(url.parsed, UrlLike::Standard { .. }))
            .map(|url| url.raw.as_str())
            .collect();
        literals.sort_by_key(|raw| std::cmp::Reverse(raw.len()));
        let mut command = input.to_string();
        for raw in literals {
            if !raw.is_empty() && !raw.contains(['$', '`']) {
                command = command.replace(raw, " ");
            }
        }
        // Keep both raw and a conservative dequoted spelling. This recognizes
        // p''ip / pi\p / line continuations without evaluating any shell code.
        // False positives on quoted installer examples are preferable to
        // silently trusting an unresolved install. No hostname is exempted.
        let joined = command.replace("\\\r\n", "").replace("\\\n", "");
        let dequoted: String = joined
            .chars()
            .filter(|c| !matches!(c, '\'' | '"' | '\\'))
            .collect();
        Self {
            package_source: PYTHON_PACKAGE_RE.is_match(&command)
                || PYTHON_PACKAGE_RE.is_match(&dequoted),
            // Preserve the old /simple/ signal for unresolved/dynamic installs.
            // These hints do not classify unrelated non-/simple/ URLs as pip.
            ambiguous_install: INSTALL_ACTION_RE.is_match(&dequoted)
                || command.contains(['$', '`', '%']),
        }
    }
}

/// Run ecosystem-specific rules, retaining command context for package URLs.
pub fn check(url: &UrlLike, python: PythonPackageContext) -> Vec<Finding> {
    let mut findings = Vec::new();

    check_docker_untrusted_registry(url, &mut findings);
    check_pip_url_install(url, python, &mut findings);
    check_npm_url_install(url, &mut findings);
    check_web3_rpc(url, &mut findings);
    check_web3_address_in_url(url, &mut findings);
    check_git_typosquat(url, &mut findings);

    findings
}

fn check_docker_untrusted_registry(url: &UrlLike, findings: &mut Vec<Finding>) {
    if let UrlLike::DockerRef {
        registry: Some(reg),
        image,
        ..
    } = url
    {
        let trusted = [
            "docker.io",
            "ghcr.io",
            "gcr.io",
            "quay.io",
            "registry.k8s.io",
            "mcr.microsoft.com",
            "public.ecr.aws",
        ];
        let reg_lower = reg.to_lowercase();
        if !trusted
            .iter()
            .any(|t| reg_lower == *t || reg_lower.ends_with(&format!(".{t}")))
        {
            findings.push(Finding {
                rule_id: RuleId::DockerUntrustedRegistry,
                severity: Severity::Medium,
                title: "Docker image from untrusted registry".to_string(),
                description: format!("Image '{image}' pulled from non-standard registry '{reg}'"),
                evidence: vec![Evidence::Url { raw: url.raw_str() }],
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
            });
        }
    }
}

fn check_pip_url_install(
    url: &UrlLike,
    context: PythonPackageContext,
    findings: &mut Vec<Finding>,
) {
    if let Some(path) = url.path() {
        if context.package_source || (context.ambiguous_install && path.contains("/simple/")) {
            if let Some(host) = url.host() {
                if host != "pypi.org"
                    && host != "files.pythonhosted.org"
                    && !host.ends_with(".pypi.org")
                {
                    findings.push(Finding {
                        rule_id: RuleId::PipUrlInstall,
                        severity: Severity::Medium,
                        title: "Python package from non-PyPI source".to_string(),
                        description: format!("Package URL points to '{host}' instead of PyPI"),
                        evidence: vec![Evidence::Url { raw: url.raw_str() }],
                        human_view: None,
                        agent_view: None,
                        mitre_id: None,
                        custom_rule_id: None,
                    });
                }
            }
        }
    }
}

fn check_npm_url_install(url: &UrlLike, findings: &mut Vec<Finding>) {
    if let Some(path) = url.path() {
        if path.ends_with(".tgz") || path.contains("/npm/") {
            if let Some(host) = url.host() {
                if host != "registry.npmjs.org"
                    && host != "npmjs.com"
                    && !host.ends_with(".npmjs.org")
                {
                    findings.push(Finding {
                        rule_id: RuleId::NpmUrlInstall,
                        severity: Severity::Medium,
                        title: "npm package from non-registry source".to_string(),
                        description: format!(
                            "Package URL points to '{host}' instead of npm registry"
                        ),
                        evidence: vec![Evidence::Url { raw: url.raw_str() }],
                        human_view: None,
                        agent_view: None,
                        mitre_id: None,
                        custom_rule_id: None,
                    });
                }
            }
        }
    }
}

fn check_web3_rpc(url: &UrlLike, findings: &mut Vec<Finding>) {
    if let Some(path) = url.path() {
        if path.contains("/v1/") || path.contains("/rpc") || path.contains("/jsonrpc") {
            if let Some(host) = url.host() {
                let web3_indicators = [
                    "infura.io",
                    "alchemy.com",
                    "moralis.io",
                    "chainstack.com",
                    "getblock.io",
                ];
                if web3_indicators.iter().any(|ind| host.contains(ind)) {
                    findings.push(Finding {
                        rule_id: RuleId::Web3RpcEndpoint,
                        severity: Severity::Low,
                        title: "Web3 RPC endpoint detected".to_string(),
                        description: format!("URL appears to be a Web3 RPC endpoint on '{host}'"),
                        evidence: vec![Evidence::Url { raw: url.raw_str() }],
                        human_view: None,
                        agent_view: None,
                        mitre_id: None,
                        custom_rule_id: None,
                    });
                }
            }
        }
    }
}

static ETH_ADDRESS_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"0x[0-9a-fA-F]{40}").unwrap());

fn check_web3_address_in_url(url: &UrlLike, findings: &mut Vec<Finding>) {
    let raw = url.raw_str();
    if ETH_ADDRESS_RE.is_match(&raw) {
        findings.push(Finding {
            rule_id: RuleId::Web3AddressInUrl,
            severity: Severity::Low,
            title: "Ethereum address found in URL".to_string(),
            description: "URL contains what appears to be an Ethereum wallet address. This may indicate a cryptocurrency-related operation.".to_string(),
            evidence: vec![Evidence::Url { raw }],
            human_view: None,
            agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
        });
    }
}

fn check_git_typosquat(url: &UrlLike, findings: &mut Vec<Finding>) {
    if let Some(path) = url.path() {
        if let Some(host) = url.host() {
            let host_lower = host.to_lowercase();
            if !(host_lower == "github.com"
                || host_lower == "gitlab.com"
                || host_lower == "bitbucket.org")
            {
                return;
            }
            let segments: Vec<&str> = path
                .trim_start_matches('/')
                .trim_end_matches(".git")
                .split('/')
                .collect();
            if segments.len() >= 2 {
                let owner = segments[0].to_lowercase();
                let repo = segments[1].to_lowercase();
                for &(pop_owner, pop_repo) in crate::data::POPULAR_REPOS {
                    let po = pop_owner.to_lowercase();
                    let pr = pop_repo.to_lowercase();
                    // Single-edit typosquat: one half is one edit off, the other verbatim.
                    if (owner == po && levenshtein(&repo, &pr) == 1)
                        || (repo == pr && levenshtein(&owner, &po) == 1)
                    {
                        findings.push(Finding {
                            rule_id: RuleId::GitTyposquat,
                            severity: Severity::Medium,
                            title: "Possible git repository typosquat".to_string(),
                            description: format!(
                                "Repository '{}/{}' is one edit from popular repo '{}/{}'",
                                segments[0], segments[1], pop_owner, pop_repo
                            ),
                            evidence: vec![Evidence::Url { raw: url.raw_str() }],
                            human_view: None,
                            agent_view: None,
                            mitre_id: None,
                            custom_rule_id: None,
                        });
                        return;
                    }
                }
            }
        }
    }
}
