use std::collections::HashSet;

pub struct GrammarContext<'a> {
    pub matched: &'a str,
    pub count: usize,
    pub occ_index: usize,
    pub neighbor: Option<usize>,
    pub call_sites: usize,
    pub span: Option<usize>,
    pub density: usize,
    pub signals: &'a [String],
    pub confidence: u8,
    pub nearest_call: Option<(usize, usize, usize)>,
    pub id_hint: &'a str,
    pub source_label: &'a str,
}

fn has<S: AsRef<str>>(signals: &[String], key: S) -> bool {
    signals.iter().any(|s| s == key.as_ref())
}

/// Very small rule-driven generator that composes a human-friendly paragraph
/// from the provided context. This intentionally stays deterministic and
/// conservative to avoid hallucinations while producing readable English.
pub fn generate_story(ctx: &GrammarContext<'_>) -> String {
    let mut parts: Vec<String> = Vec::new();

    // Opening clause
    if ctx.count <= 1 {
        parts.push(format!("Story: {} was observed once in {}.", ctx.matched, ctx.source_label));
    } else {
        parts.push(format!("Story: {} appears {} times in {}.", ctx.matched, ctx.count, ctx.source_label));
    }

    // Locality and density
    if let Some(span) = ctx.span {
        let density_word = if ctx.density > 60 { "concentrated" } else { "scattered" };
        parts.push(format!("Occurrences span ~{} bytes and are {}.", span, density_word));
    }
    if let Some(n) = ctx.neighbor {
        parts.push(format!("A nearby similar instance is approximately {} bytes away.", n));
    }

    // Call sites
    if ctx.call_sites > 0 {
        if let Some((l, c, d)) = ctx.nearest_call {
            parts.push(format!("There are {} call-site(s); closest at L{} C{} (~{} bytes).", ctx.call_sites, l, c, d));
        } else {
            parts.push(format!("There are {} call-site(s) referencing this token in the file.", ctx.call_sites));
        }
    } else {
        parts.push("No direct call-sites were detected nearby.".to_string());
    }

    // Signals-driven phrasing
    let sigs: HashSet<&str> = ctx.signals.iter().map(|s| s.as_str()).collect();
    let mut ctx_phrases: Vec<String> = Vec::new();
    if has(ctx.signals, "auth-header") { ctx_phrases.push("authentication header-like structure".to_string()); }
    if has(ctx.signals, "header") { ctx_phrases.push("header-like structure".to_string()); }
    if has(ctx.signals, "keyword-hint") { ctx_phrases.push("the token name resembles a secret".to_string()); }
    if has(ctx.signals, "id-hint") { ctx_phrases.push("nearby identifier looks like a secret name".to_string()); }
    if has(ctx.signals, "url-param") { ctx_phrases.push("appears in a URL or parameter".to_string()); }
    if has(ctx.signals, "doc-context") { ctx_phrases.push("located in documentation/examples".to_string()); }
    if has(ctx.signals, "infra-context") { ctx_phrases.push("found in infra/config paths".to_string()); }

    if !ctx_phrases.is_empty() {
        parts.push(format!("Context hints: {}.", ctx_phrases.join(", ")));
    }

    if !ctx.id_hint.is_empty() {
        parts.push(format!("Identifier hint: {}.", ctx.id_hint.trim_start_matches("; ")));
    }

    // Confidence and guidance (short, actionable)
    let guidance = if ctx.confidence >= 8 || sigs.contains("high-risk-keyword") || sigs.contains("id-hint") {
        "High confidence — prioritize this finding for immediate review"
    } else if ctx.confidence >= 5 || sigs.contains("keyword-hint") {
        "Medium confidence — flag for manual review"
    } else {
        "Low confidence — informational"
    };
    parts.push(format!("{} (confidence {}/10).", guidance, ctx.confidence));

    // Join into a single paragraph
    let paragraph = parts.join(" ");

    format!("{}\n", paragraph)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grammar_generates_story_with_markers() {
        let ctx = GrammarContext {
            matched: "token",
            count: 3,
            occ_index: 1,
            neighbor: Some(12),
            call_sites: 2,
            span: Some(200),
            density: 30,
            signals: &vec!["keyword-hint".to_string(), "auth-header".to_string()],
            confidence: 6,
            nearest_call: Some((10, 2, 50)),
            id_hint: "apiKey",
            source_label: "src/app.js",
        };
        let out = generate_story(&ctx);
        assert!(out.contains("Story:"));
        assert!(!out.contains("Source:"));
        assert!(out.contains("Medium confidence"));
    }
}
