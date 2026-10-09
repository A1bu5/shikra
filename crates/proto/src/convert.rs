use prost_types::Timestamp;
use time::OffsetDateTime;

pub fn timestamp_now() -> Timestamp {
    to_timestamp(OffsetDateTime::now_utc())
}

pub fn to_timestamp(at: OffsetDateTime) -> Timestamp {
    Timestamp {
        seconds: at.unix_timestamp(),
        nanos: at.nanosecond() as i32,
    }
}

pub fn from_timestamp(ts: &Timestamp) -> OffsetDateTime {
    let base =
        OffsetDateTime::from_unix_timestamp(ts.seconds).unwrap_or(OffsetDateTime::UNIX_EPOCH);
    base + time::Duration::nanoseconds(i64::from(ts.nanos))
}
