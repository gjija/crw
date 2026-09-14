//! `/v1/crawl`'s robots.txt gate must match on path *and* query.
//!
//! This cannot be a unit test on `RobotsTxt`: `robots_tests.rs` already proves
//! `is_allowed(url.path())` and `is_url_allowed(&url)` disagree on a `?`
//! pattern. What was untested is which of the two the *crawl loop* calls, and
//! that is only observable by driving `run_crawl` against a real origin.

use std::sync::Arc;

use crw_core::config::{RendererConfig, RendererMode, StealthConfig};
use crw_core::types::{CrawlRequest, CrawlState, CrawlStatus, OutputFormat};
use crw_crawl::crawl::{CrawlOptions, run_crawl};
use crw_renderer::FallbackRenderer;
use uuid::Uuid;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// wiremock binds to loopback, which the SSRF guard rejects by default.
fn allow_loopback() {
    // SAFETY: `set_var` is not thread-safe, and libtest runs the tests in this
    // binary concurrently. Every test here sets the same value and nothing
    // unsets it, so the racing writes are all identical; the variable is only
    // ever read afterwards by the SSRF guard.
    unsafe {
        std::env::set_var("CRW_ALLOW_LOOPBACK_FOR_TESTS", "1");
    }
}

async fn renderer() -> Arc<FallbackRenderer> {
    allow_loopback();
    let cfg = RendererConfig {
        mode: RendererMode::None,
        ..Default::default()
    };
    Arc::new(
        FallbackRenderer::new(&cfg, "crw-test", None, &StealthConfig::default())
            .expect("renderer builds in http-only mode"),
    )
}

fn request(url: String) -> CrawlRequest {
    CrawlRequest {
        url,
        max_depth: Some(0),
        max_pages: Some(1),
        formats: vec![OutputFormat::Markdown],
        only_main_content: false,
        json_schema: None,
        render_js: Some(false),
        wait_for: None,
        renderer: None,
        country: None,
        proxy_list: Vec::new(),
        proxy_rotation: None,
        headers: std::collections::HashMap::new(),
    }
}

async fn run_respecting_robots(req: CrawlRequest) -> CrawlState {
    let id = Uuid::new_v4();
    let (state_tx, state_rx) = tokio::sync::watch::channel(CrawlState {
        id,
        success: false,
        status: CrawlStatus::InProgress,
        total: 0,
        completed: 0,
        blocked: 0,
        data: Vec::new(),
        error: None,
    });
    run_crawl(CrawlOptions {
        id,
        req,
        renderer: renderer().await,
        max_concurrency: 1,
        respect_robots: true,
        requests_per_second: 100.0,
        user_agent: "crw-test-default-ua",
        state_tx,
        llm_config: None,
        proxy: None,
        jitter_factor: 0.0,
        deadline_ms_per_page: 15_000,
        per_host_max_concurrent: 1,
        normalize_tables: false,
        http_retry_threshold_bytes: 0,
    })
    .await;
    state_rx.borrow().clone()
}

/// `Disallow: /vote?` mounted at `/robots.txt`, with `.expect(1)` so a crawl
/// that bails before ever fetching robots.txt fails instead of passing
/// vacuously.
async fn mock_with_vote_rule() -> MockServer {
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/robots.txt"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string("User-agent: *\nDisallow: /vote?\n"),
        )
        .expect(1)
        .mount(&mock)
        .await;
    mock
}

/// The crawl loop gated with `robots.is_allowed(parsed.path())`, which throws
/// the query away. `Disallow: /vote?` then matched nothing, because
/// `"/vote".starts_with("/vote?")` is false — so the crawler fetched exactly
/// the state-changing endpoints the site forbade. Hacker News is the canonical
/// example and is named in `is_url_allowed`'s own doc comment.
#[tokio::test]
async fn crawl_honors_a_robots_rule_that_keys_on_the_query_string() {
    let mock = mock_with_vote_rule().await;

    // Must never be hit. wiremock verifies expectations on drop.
    Mock::given(method("GET"))
        .and(path("/vote"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/html")
                .set_body_string("<html><body>voted</body></html>"),
        )
        .expect(0)
        .mount(&mock)
        .await;

    let state = run_respecting_robots(request(format!("{}/vote?id=1&how=up", mock.uri()))).await;

    // Pin that the crawl actually ran and reached the gate, rather than bailing
    // early (invalid URL, SSRF rejection) — `send_failed` also produces an
    // empty `data`, so asserting emptiness alone would pass in that world too.
    assert_eq!(
        state.status,
        CrawlStatus::Completed,
        "crawl should complete, not fail: {:?}",
        state.error
    );
    assert!(state.error.is_none(), "unexpected error: {:?}", state.error);
    assert!(
        state.data.is_empty(),
        "a URL disallowed by a `?` robots pattern must not be crawled"
    );
}

/// The counterpart. The allowed URL **carries a query**, which is what makes
/// this a real over-blocking guard: with no query, `is_url_allowed(&u)` and
/// `is_allowed(u.path())` compute the identical string and the test would pin
/// nothing about the change.
#[tokio::test]
async fn crawl_still_allows_a_queried_path_the_rule_does_not_match() {
    let mock = mock_with_vote_rule().await;

    Mock::given(method("GET"))
        .and(path("/voter-guide"))
        .respond_with(
            ResponseTemplate::new(200)
                // Without an HTML content-type the extractor takes the
                // plain-text path and never exercises the real pipeline.
                .insert_header("content-type", "text/html")
                .set_body_string("<html><body><h1>Voter guide</h1></body></html>"),
        )
        .expect(1)
        .mount(&mock)
        .await;

    let state = run_respecting_robots(request(format!("{}/voter-guide?ref=nav", mock.uri()))).await;

    assert_eq!(state.status, CrawlStatus::Completed);
    assert_eq!(
        state.data.len(),
        1,
        "an allowed path must still be crawled after the gate change"
    );
    // `push_failed_page` also lands in `data`, so length alone does not prove a
    // successful fetch. `blocked` plus the body do.
    assert_eq!(state.blocked, 0, "the page should not be marked blocked");
    let md = state.data[0].markdown.as_deref().unwrap_or_default();
    assert!(
        md.contains("Voter guide"),
        "expected the rendered body, got {md:?}"
    );
}
