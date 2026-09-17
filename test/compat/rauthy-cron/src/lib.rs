// Development-only oracle: Rauthy v0.36.2 pins cron 0.17.0.
// This is not a GoAuthy runtime dependency or a completed scheduler test.
#[cfg(test)]
mod tests {
    use chrono::{DateTime, TimeZone, Utc};
    use chrono_tz::America::New_York;
    use cron::Schedule;

    fn next(expression: &str, after: &str) -> DateTime<Utc> {
        expression
            .parse::<Schedule>()
            .unwrap()
            .after(&after.parse::<DateTime<Utc>>().unwrap())
            .next()
            .unwrap()
    }

    #[test]
    fn grammar_and_calendar_contract() {
        for expression in [
            "0 30 2 * * *",
            "0 30 2 * * * *",
            "@yearly",
            "@monthly",
            "@weekly",
            "@daily",
            "@hourly",
        ] {
            assert!(expression.parse::<Schedule>().is_ok(), "{expression}");
        }
        for expression in [
            "0 30 2 * * * * extra",
            "0 0 0 * * 0 *",
            "0 0 0 * * * 2101",
            "@reboot",
        ] {
            assert!(expression.parse::<Schedule>().is_err(), "{expression}");
        }
        // January 1, 2027 is Friday; Sunday AND day 1 next occurs August 1.
        assert_eq!(
            next("0 0 0 1 * 1 2027", "2027-01-01T00:00:00Z").to_rfc3339(),
            "2027-08-01T00:00:00+00:00"
        );
        assert_eq!(
            next("0 0 0 1 1 * 2100", "2099-12-31T00:00:00Z").year(),
            2100
        );
        assert!("0 0 0 29 2 * *"
            .parse::<Schedule>()
            .unwrap()
            .after(&"2099-01-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap())
            .next()
            .is_none());
    }

    use chrono::Datelike;

    #[test]
    fn local_dst_gap_and_duplicate() {
        let gap = "0 30 2 * * * *".parse::<Schedule>().unwrap();
        let after = New_York
            .with_ymd_and_hms(2027, 3, 14, 1, 59, 59)
            .single()
            .unwrap();
        assert_eq!(
            gap.after(&after).next().unwrap().to_rfc3339(),
            "2027-03-15T02:30:00-04:00"
        );
        let fold = "0 30 1 * * * *".parse::<Schedule>().unwrap();
        let after = New_York
            .with_ymd_and_hms(2027, 11, 7, 0, 59, 59)
            .single()
            .unwrap();
        let dates: Vec<_> = fold.after(&after).take(2).map(|d| d.to_rfc3339()).collect();
        assert_eq!(
            dates,
            ["2027-11-07T01:30:00-04:00", "2027-11-07T01:30:00-05:00"]
        );
    }
    // Upstream bug evidence, not desired GoAuthy dispatch behavior.
    #[test]
    fn upstream_fold_iterator_can_go_backwards() {
        let schedule = "0 * 1 * * * *".parse::<Schedule>().unwrap();
        let after = New_York
            .with_ymd_and_hms(2027, 11, 7, 0, 59, 59)
            .single()
            .unwrap();
        let dates: Vec<_> = schedule.after(&after).take(3).collect();
        assert_eq!(dates[0].to_rfc3339(), "2027-11-07T01:00:00-04:00");
        assert_eq!(dates[1].to_rfc3339(), "2027-11-07T01:00:00-05:00");
        assert_eq!(dates[2].to_rfc3339(), "2027-11-07T01:01:00-04:00");
        assert!(dates[2] < dates[1]);
    }
}
