use std::borrow::Cow;
use std::time::Duration;

use criterion::{Criterion, criterion_group, criterion_main};
use loi_core::SyscallEvent;

fn sample_event() -> SyscallEvent {
    SyscallEvent::new(
        4242,
        1,
        Cow::Borrowed("write"),
        [1, 0xdead_beef, 64, 0, 0, 0],
        64,
        Duration::from_nanos(1_500),
    )
}

fn bench_serialize_event(c: &mut Criterion) {
    let event = sample_event();
    c.bench_function("event_serde::serialize_event_to_json", |b| {
        b.iter(|| serde_json::to_string(std::hint::black_box(&event)).unwrap());
    });
}

criterion_group!(benches, bench_serialize_event);
criterion_main!(benches);
