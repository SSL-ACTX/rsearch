pub fn render_story_markdown(
    matched: &str,
    count: usize,
    occ_index: usize,
    neighbor: Option<usize>,
    call_sites: usize,
    span: Option<usize>,
    density: usize,
    signals: &[String],
    confidence: u8,
    nearest_call: Option<(usize, usize, usize)>,
    id_hint: &str,
    source_label: &str,
) -> String {
    // Use the grammar engine for human-friendly prose while preserving
    // compatibility markers expected by downstream consumers/tests.
    let ctx = crate::grammar::GrammarContext {
        matched,
        count,
        occ_index,
        neighbor,
        call_sites,
        span,
        density,
        signals,
        confidence,
        nearest_call,
        id_hint,
        source_label,
    };

    crate::grammar::generate_story(&ctx)
}
