//! Dates, to the precision this tool needs and no further.
//!
//! Used for two things: "this advisory has been public for 412 days" (a far
//! sharper motivator than a severity word) and day-granular streak tracking.
//!
//! Deliberately no `chrono`. The reference implementation pulled in the whole
//! crate to format one timestamp; we need day arithmetic on UTC dates, which is
//! Hinnant's algorithm and about twenty lines.

use std::time::{SystemTime, UNIX_EPOCH};

/// A UTC calendar date.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Date {
    pub year: i64,
    pub month: i64,
    pub day: i64,
}

impl Date {
    /// Parses the leading `YYYY-MM-DD` of an RFC 3339 timestamp.
    ///
    /// OSV timestamps look like `2020-11-18T12:00:00Z`; the time of day is
    /// irrelevant when the answer is measured in days.
    pub fn parse(text: &str) -> Option<Date> {
        let date = text.get(..10)?;
        let mut parts = date.split('-');
        let year = parts.next()?.parse().ok()?;
        let month = parts.next()?.parse().ok()?;
        let day = parts.next()?.parse().ok()?;

        if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
            return None;
        }
        Some(Date { year, month, day })
    }

    /// Today, in UTC. Returns `None` only if the system clock predates 1970.
    pub fn today() -> Option<Date> {
        let seconds = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
        Some(Date::from_days(seconds as i64 / 86_400))
    }

    /// Days since the Unix epoch. Howard Hinnant's `days_from_civil`.
    pub fn to_days(self) -> i64 {
        let y = if self.month <= 2 {
            self.year - 1
        } else {
            self.year
        };
        let era = if y >= 0 { y } else { y - 399 } / 400;
        let yoe = y - era * 400;
        let mp = (self.month + 9) % 12;
        let doy = (153 * mp + 2) / 5 + self.day - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        era * 146_097 + doe - 719_468
    }

    /// Inverse of [`Date::to_days`] (`civil_from_days`).
    pub fn from_days(days: i64) -> Date {
        let z = days + 719_468;
        let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
        let doe = z - era * 146_097;
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let y = yoe + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let day = doy - (153 * mp + 2) / 5 + 1;
        let month = if mp < 10 { mp + 3 } else { mp - 9 };
        Date {
            year: if month <= 2 { y + 1 } else { y },
            month,
            day,
        }
    }

    /// Whole days from `self` to `other`. Negative if `other` is earlier.
    pub fn days_until(self, other: Date) -> i64 {
        other.to_days() - self.to_days()
    }

    /// `YYYY-MM-DD`, for the history file.
    pub fn to_iso(self) -> String {
        format!("{:04}-{:02}-{:02}", self.year, self.month, self.day)
    }
}

/// Days between an RFC 3339 timestamp and today, clamped at zero.
///
/// Zero rather than a negative number, because an advisory published "tomorrow"
/// is a clock-skew artefact, not information.
pub fn days_since(timestamp: &str) -> Option<u32> {
    let published = Date::parse(timestamp)?;
    let today = Date::today()?;
    Some(published.days_until(today).max(0) as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_osv_timestamps() {
        assert_eq!(
            Date::parse("2020-11-18T12:00:00Z"),
            Some(Date {
                year: 2020,
                month: 11,
                day: 18
            })
        );
        assert_eq!(
            Date::parse("2026-02-04"),
            Some(Date {
                year: 2026,
                month: 2,
                day: 4
            })
        );
    }

    #[test]
    fn rejects_nonsense() {
        assert_eq!(Date::parse(""), None);
        assert_eq!(Date::parse("not-a-date"), None);
        assert_eq!(Date::parse("2020-13-01T00:00:00Z"), None);
        assert_eq!(Date::parse("2020-00-01T00:00:00Z"), None);
        assert_eq!(Date::parse("2020-01-99T00:00:00Z"), None);
    }

    #[test]
    fn epoch_is_day_zero() {
        let epoch = Date {
            year: 1970,
            month: 1,
            day: 1,
        };
        assert_eq!(epoch.to_days(), 0);
        assert_eq!(Date::from_days(0), epoch);
    }

    #[test]
    fn day_arithmetic_round_trips_across_leap_years() {
        // 2020 and 2000 are leap years, 1900 and 2100 are not; a naive
        // implementation gets at least one of these wrong.
        for date in [
            (2020, 2, 29),
            (2000, 2, 29),
            (1900, 3, 1),
            (2100, 3, 1),
            (1970, 1, 1),
            (2026, 12, 31),
        ] {
            let d = Date {
                year: date.0,
                month: date.1,
                day: date.2,
            };
            assert_eq!(
                Date::from_days(d.to_days()),
                d,
                "round trip failed for {d:?}"
            );
        }
    }

    #[test]
    fn measures_known_intervals() {
        let a = Date {
            year: 2020,
            month: 1,
            day: 1,
        };
        let b = Date {
            year: 2021,
            month: 1,
            day: 1,
        };
        // 2020 was a leap year.
        assert_eq!(a.days_until(b), 366);
        assert_eq!(b.days_until(a), -366);

        let leap_day = Date {
            year: 2020,
            month: 2,
            day: 29,
        };
        assert_eq!(a.days_until(leap_day), 59);
    }

    #[test]
    fn formats_iso_dates_with_padding() {
        assert_eq!(
            Date {
                year: 2026,
                month: 2,
                day: 4
            }
            .to_iso(),
            "2026-02-04"
        );
    }

    #[test]
    fn today_is_sane() {
        let today = Date::today().expect("system clock should be after 1970");
        assert!(today.year >= 2024, "got {today:?}");
        assert_eq!(Date::from_days(today.to_days()), today);
    }

    #[test]
    fn future_timestamps_clamp_to_zero() {
        assert_eq!(days_since("2999-01-01T00:00:00Z"), Some(0));
        assert!(days_since("2020-01-01T00:00:00Z").unwrap() > 2000);
    }
}
