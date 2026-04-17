use criterion::{Criterion, criterion_group, criterion_main};
use secrets_detection_rust::config::SecretsDetectionConfig;
use secrets_detection_rust::detect_and_redact;

fn bench_detect_and_redact(c: &mut Criterion) {
    let config = SecretsDetectionConfig {
        redact: true,
        ..Default::default()
    };
    let text = "prefix AWS_ACCESS_KEY_ID=AKIAFAKE12345EXAMPLE suffix";
    c.bench_function("detect_and_redact/aws", |b| {
        b.iter(|| detect_and_redact(text, &config))
    });
}

criterion_group!(benches, bench_detect_and_redact);
criterion_main!(benches);
