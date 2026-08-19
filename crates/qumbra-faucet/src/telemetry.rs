//! The svc-lane three-piece kit for this binary: **spans, a `trace_id=` on the log
//! line, and one exemplar-carrying latency histogram** (observability-plan §C.1).
//!
//! ```text
//!   OTEL_EXPORTER_OTLP_ENDPOINT unset  →  tracer runs, NOTHING is exported
//!   OTEL_EXPORTER_OTLP_ENDPOINT set    →  the same tracer, plus an OTLP http/protobuf
//!                                          batch exporter on its own thread
//! ```
//!
//! ## The three decisions this module takes, and why
//!
//! **1. The tracer is always installed; only the *exporter* is env-gated.** The
//! baton's wording is "no `OTEL_EXPORTER_OTLP_ENDPOINT` ⇒ no exporter constructed,
//! zero overhead". Read literally as "no tracer either", pieces 2 and 3 of the kit
//! collapse: a `trace_id=` on the request log line and a `trace_id` exemplar on the
//! histogram both need an id, and an id only exists if something generated one. A
//! faucet whose log line reads `trace_id=0000…0` in the default configuration has a
//! field that lies rather than a field that is off. So: [`SdkTracerProvider`] is
//! built either way, and when the env is unset it is built **with no span
//! processor** — spans are recorded, ids are real, and every span is dropped at
//! `end()`. No exporter object, no socket, no HTTP client, no background thread, no
//! bytes. What remains is span-record allocation on a surface that serves a handful
//! of requests a second.
//!
//! **2. No `fmt` layer, ever — the subscriber is a bare registry.** This crate's
//! operator log is [`crate::http`]'s one-`format!` journal line, and the redaction
//! claim in that module's docs rests on that being the only thing this process
//! prints per request. A `tracing-subscriber` `fmt` layer would put a second,
//! unreviewed rendering of every span's fields on stdout. It is also what makes the
//! "zero error/warn spam" requirement structural rather than remembered: with no
//! `fmt` layer there is no path from a `tracing` event to a file descriptor.
//! `internal-logs` is off on all three OTel crates for the same reason, and the
//! cost is named in the PR — a failing export is currently silent.
//!
//! **3. `service.name`/`service.namespace` are compile-time constants, not env.**
//! `Resource::builder()` still merges `OTEL_RESOURCE_ATTRIBUTES`, so an operator can
//! add `deployment.environment`; what they cannot do is rename this service and
//! break the Loki/Tempo correlation the plan's standards line pins.

use std::sync::Arc;
use std::time::Duration;

use opentelemetry::trace::{TraceContextExt, TracerProvider as _};
use opentelemetry::KeyValue;
use opentelemetry_sdk::trace::SdkTracerProvider;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::Resource;
use prometheus_client::encoding::EncodeLabelSet;
use prometheus_client::metrics::exemplar::HistogramWithExemplars;
use prometheus_client::metrics::family::Family;
use prometheus_client::registry::Registry;
use tracing_opentelemetry::{OpenTelemetryLayer, OpenTelemetrySpanExt};
use tracing_subscriber::layer::SubscriberExt;

/// `service.name` on every span this binary emits. Fixed — see decision 3.
pub const SERVICE_NAME: &str = "qumbra-faucet";
/// `service.namespace` on every span this binary emits.
pub const SERVICE_NAMESPACE: &str = "qumbra";
/// The one environment variable that turns export on. Standard OTLP name, so an
/// operator who knows OpenTelemetry does not have to learn a Qumbra-specific one.
pub const OTLP_ENDPOINT_ENV: &str = "OTEL_EXPORTER_OTLP_ENDPOINT";

/// The instrumentation scope name spans are recorded under.
const SCOPE: &str = "qumbra-faucet";

/// Request-latency buckets, in seconds.
///
/// The range is set by what this surface actually does: `/healthz` and the static
/// icons answer in tens of microseconds, `/` renders a page from a snapshot, and
/// `POST /request` does a MAC check and a queue push. **The ~2.3 s grant proof is
/// deliberately NOT in this range** — it happens on the node loop, not in a
/// request (see [`crate::service::FaucetService::tick`]), and pretending otherwise
/// is what a request histogram covering it would do. The top buckets exist to catch
/// a request that is stuck behind a lock, not a proof.
const REQUEST_BUCKETS: [f64; 11] =
    [0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0];

/// The label set the latency histogram is keyed by.
///
/// `route` is the **matched route**, never the raw URL: `/r/<receipt>` collapses to
/// `/r/{receipt}` so a scrape cannot become an unbounded-cardinality record of which
/// receipts were looked at, and a raw path never reaches a label.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct RequestLabels {
    pub method: String,
    pub route: String,
    pub status: u16,
}

/// The exemplar label set: one field, the W3C trace id, which is what makes a
/// bucket clickable through to the span in Tempo.
#[derive(Clone, Debug, Default, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct TraceExemplar {
    pub trace_id: String,
}

/// This binary's metric registry — one histogram, and the registry it is served
/// from.
///
/// Held behind an `Arc` and handed to both the listener (which observes) and the
/// metrics endpoint (which encodes). Cheap to clone, safe to share.
#[derive(Debug)]
pub struct FaucetMetrics {
    registry: Registry,
    latency: Family<RequestLabels, HistogramWithExemplars<TraceExemplar>>,
}

impl Default for FaucetMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl FaucetMetrics {
    pub fn new() -> FaucetMetrics {
        let latency = Family::<RequestLabels, HistogramWithExemplars<TraceExemplar>>::
            new_with_constructor(|| HistogramWithExemplars::new(REQUEST_BUCKETS.iter().copied()));
        let mut registry = Registry::default();
        registry.register(
            "qumbra_faucet_request_duration_seconds",
            "Wall time from the faucet listener accepting a request to the response being \
             handed to the socket, by matched route and status",
            latency.clone(),
        );
        FaucetMetrics { registry, latency }
    }

    /// Record one served request. `trace_id` is the exemplar — `None` when no tracer
    /// produced a valid id, in which case the observation still lands in its bucket
    /// and simply carries no exemplar.
    pub fn observe_request(&self, labels: RequestLabels, seconds: f64, trace_id: Option<String>) {
        self.latency
            .get_or_create(&labels)
            .observe(seconds, trace_id.map(|trace_id| TraceExemplar { trace_id }));
    }

    /// The OpenMetrics exposition, terminated with `# EOF`.
    ///
    /// **OpenMetrics, not the Prometheus text format** — exemplars exist only in
    /// OpenMetrics, and this histogram's whole reason for being here is its
    /// exemplars. The content type in [`crate::metrics_server`] matches.
    pub fn encode(&self) -> String {
        let mut out = String::new();
        // The encoder's only failure mode is `fmt::Error` from the writer, and a
        // `String` writer does not fail.
        let _ = prometheus_client::encoding::text::encode(&mut out, &self.registry);
        out
    }
}

/// The OpenMetrics content type. Exemplars are an OpenMetrics feature; labelling
/// this `text/plain; version=0.0.4` (which is what `qumbra-node`'s `/metrics`
/// serves, correctly, because it has no exemplars) would tell a scraper to parse it
/// with a grammar that has no place to put them.
pub const OPENMETRICS_CONTENT_TYPE: &str =
    "application/openmetrics-text; version=1.0.0; charset=utf-8";

/// A live tracer, and whether anything is being exported.
///
/// Held by `main` for the process lifetime; [`Telemetry::shutdown`] flushes.
#[derive(Debug)]
pub struct Telemetry {
    provider: SdkTracerProvider,
    endpoint: Option<String>,
    metrics: Arc<FaucetMetrics>,
}

impl Telemetry {
    /// Build the tracer, install it as the global `tracing` subscriber, and
    /// construct an OTLP exporter **only** if [`OTLP_ENDPOINT_ENV`] names one.
    ///
    /// Idempotence: a second call in the same process builds a second provider but
    /// cannot replace the installed subscriber (`tracing` allows one global). That
    /// is fine for the binary, which calls this once, and it is why the tests that
    /// need a tracer live in their own integration-test binaries.
    pub fn init() -> Telemetry {
        Self::init_with_metrics(Arc::new(FaucetMetrics::new()))
    }

    /// Build and install a tracer around a **caller-supplied** span exporter,
    /// bypassing the environment gate entirely.
    ///
    /// This is the seam `tests/otel_spans.rs` uses: the span tree, the resource
    /// attributes and the parent/child edges are asserted against an in-process
    /// exporter rather than a live collector, and — the point — against *this*
    /// function's resource and *this* function's `install`, not a copy of them
    /// written in the test. A test that builds its own provider proves that the
    /// test's provider works.
    ///
    /// `with_simple_exporter`, not batch: a test that has to sleep for a flush is a
    /// test that is flaky on a loaded runner.
    pub fn install_with_exporter<E>(exporter: E, metrics: Arc<FaucetMetrics>) -> Telemetry
    where
        E: opentelemetry_sdk::trace::SpanExporter + 'static,
    {
        let provider = SdkTracerProvider::builder()
            .with_resource(resource())
            .with_simple_exporter(exporter)
            .build();
        install(&provider);
        Telemetry { provider, endpoint: Some("in-process exporter".to_string()), metrics }
    }

    /// [`Telemetry::init`], with a metrics registry the caller already holds.
    pub fn init_with_metrics(metrics: Arc<FaucetMetrics>) -> Telemetry {
        let endpoint = std::env::var(OTLP_ENDPOINT_ENV)
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        let mut builder = SdkTracerProvider::builder().with_resource(resource());
        let mut exporting = None;
        if let Some(ep) = endpoint.as_deref() {
            match opentelemetry_otlp::SpanExporter::builder()
                .with_http()
                .with_protocol(opentelemetry_otlp::Protocol::HttpBinary)
                .with_timeout(Duration::from_secs(10))
                .build()
            {
                Ok(exporter) => {
                    builder = builder.with_batch_exporter(exporter);
                    exporting = Some(ep.to_string());
                }
                // Loud, once, on the operator's own stream — this is a startup
                // misconfiguration, not a per-request event, so it does not violate
                // the "no spam" rule and the alternative is a faucet that silently
                // exports nothing while its config says it should.
                Err(e) => qlab_devnet::jeprintln!(
                    "qumbra-faucet: {OTLP_ENDPOINT_ENV}={ep} but the OTLP exporter could not be \
                     built ({e}). Spans are still generated; nothing is exported."
                ),
            }
        }
        let provider = builder.build();
        install(&provider);
        Telemetry { provider, endpoint: exporting, metrics }
    }

    /// The endpoint spans are being exported to, or `None` when export is off.
    pub fn endpoint(&self) -> Option<&str> {
        self.endpoint.as_deref()
    }

    /// Whether an exporter was constructed. **The negative is the interesting one**
    /// — see `tests/otel_disabled.rs`.
    pub fn exporting(&self) -> bool {
        self.endpoint.is_some()
    }

    /// The shared metric registry.
    pub fn metrics(&self) -> Arc<FaucetMetrics> {
        Arc::clone(&self.metrics)
    }

    /// One line for the startup banner, in the same honesty voice as the faucet's
    /// other posture lines: it names what is on, or says plainly that nothing is.
    pub fn posture_line(&self) -> String {
        match self.endpoint() {
            Some(ep) => format!("tracing:       OTLP http/protobuf → {ep}"),
            None => format!(
                "tracing:       spans generated, NOT exported (set {OTLP_ENDPOINT_ENV} to export)"
            ),
        }
    }

    /// Flush and stop. Called on shutdown; a failure is reported and not fatal —
    /// a faucet must not fail to exit because a collector was unreachable.
    pub fn shutdown(self) {
        if let Err(e) = self.provider.shutdown() {
            qlab_devnet::jeprintln!("qumbra-faucet: tracer shutdown: {e}");
        }
    }
}

/// The OTel resource every span this binary emits carries.
///
/// `Resource::builder` (not `builder_empty`) so `OTEL_RESOURCE_ATTRIBUTES` and the
/// SDK's own `telemetry.sdk.*` still merge in — an operator can add
/// `deployment.environment`; what they cannot do is rename the service out from
/// under the correlation the plan's standards line pins.
pub fn resource() -> Resource {
    Resource::builder()
        .with_service_name(SERVICE_NAME)
        .with_attributes([KeyValue::new("service.namespace", SERVICE_NAMESPACE)])
        .build()
}

/// Install `provider` as the process's `tracing` subscriber. Returns whether this
/// call was the one that installed it.
fn install(provider: &SdkTracerProvider) -> bool {
    let tracer = provider.tracer(SCOPE);
    opentelemetry::global::set_tracer_provider(provider.clone());
    let subscriber = tracing_subscriber::Registry::default().with(OpenTelemetryLayer::new(tracer));
    tracing::subscriber::set_global_default(subscriber).is_ok()
}

/// The current span's trace id as 32 lowercase hex, or `None` if no tracer is
/// installed or the context is invalid.
///
/// This is the exact token [`crate::http`] puts on the journal line and the exact
/// value the histogram exemplar carries — one source, so the log and the metric
/// cannot disagree about which trace a request belongs to.
pub fn current_trace_id() -> Option<String> {
    let context = tracing::Span::current().context();
    let span_context = context.span().span_context().clone();
    span_context.is_valid().then(|| span_context.trace_id().to_string())
}

/// The trace/span context of the current span, for linking a later, causally
/// related span to it. `None` when no tracer is installed.
pub fn current_span_context() -> Option<opentelemetry::trace::SpanContext> {
    let context = tracing::Span::current().context();
    let span_context = context.span().span_context().clone();
    span_context.is_valid().then_some(span_context)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exposition is OpenMetrics and the exemplar is on the bucket, carrying the
    /// trace id verbatim. This is piece 3 of the kit asserted at the encoder, where
    /// it is a pure function; `tests/otel_spans.rs` asserts the same thing end to
    /// end over a real socket with a real trace id.
    #[test]
    fn the_histogram_exposition_carries_a_trace_id_exemplar() {
        let m = FaucetMetrics::new();
        let labels = RequestLabels {
            method: "GET".to_string(),
            route: "/healthz".to_string(),
            status: 200,
        };
        m.observe_request(labels, 0.004, Some("0af7651916cd43dd8448eb211c80319c".to_string()));

        let text = m.encode();
        assert!(
            text.contains("# TYPE qumbra_faucet_request_duration_seconds histogram"),
            "{text}"
        );
        assert!(text.contains("qumbra_faucet_request_duration_seconds_count"), "{text}");
        // The OpenMetrics exemplar syntax: `… # {trace_id="…"} value timestamp`.
        assert!(
            text.contains("# {trace_id=\"0af7651916cd43dd8448eb211c80319c\"}"),
            "no exemplar in the exposition:\n{text}"
        );
        // …attached to a bucket, not to the count or the sum.
        let exemplar_line = text
            .lines()
            .find(|l| l.contains("# {trace_id="))
            .expect("an exemplar line");
        assert!(exemplar_line.contains("_bucket{"), "{exemplar_line}");
        // The labels travel with it.
        assert!(exemplar_line.contains("method=\"GET\""), "{exemplar_line}");
        assert!(exemplar_line.contains("route=\"/healthz\""), "{exemplar_line}");
        assert!(exemplar_line.contains("status=\"200\""), "{exemplar_line}");
        assert!(text.trim_end().ends_with("# EOF"), "OpenMetrics is EOF-terminated:\n{text}");
    }

    /// An observation with no trace id is still a measurement — it just has nothing
    /// to link to. The failure this guards against is a histogram that silently
    /// drops the request when tracing is off.
    #[test]
    fn an_observation_without_a_trace_id_is_still_counted() {
        let m = FaucetMetrics::new();
        m.observe_request(
            RequestLabels { method: "GET".into(), route: "/".into(), status: 200 },
            0.002,
            None,
        );
        let text = m.encode();
        assert!(
            text.contains("qumbra_faucet_request_duration_seconds_count{method=\"GET\",route=\"/\",status=\"200\"} 1"),
            "{text}"
        );
        assert!(!text.contains("# {trace_id="), "no exemplar without an id:\n{text}");
    }

    /// With no tracer installed in this test binary, the id helper answers `None`
    /// rather than a string of zeros. The all-zeros trace id is the specific lie
    /// this module's decision 1 exists to prevent.
    #[test]
    fn a_trace_id_is_none_rather_than_zeros_when_nothing_is_installed() {
        assert_eq!(current_trace_id(), None);
        assert!(current_span_context().is_none());
    }
}
