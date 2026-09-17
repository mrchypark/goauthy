// Hex-line parser oracle for the opt-in Go differential check.
use cron::{Schedule, TimeUnitSpec};
use std::io::{self, BufRead};
fn main() {
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let bytes: Result<Vec<u8>, _> = (0..line.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&line[i..i + 2], 16))
            .collect();
        let expression = match bytes.ok().and_then(|b| String::from_utf8(b).ok()) {
            Some(expression) => expression,
            None => {
                println!("err");
                continue;
            }
        };
        match expression.parse::<Schedule>() {
            Err(_) => println!("err"),
            Ok(s) => {
                let fields = [
                    s.seconds().iter().collect::<Vec<_>>(),
                    s.minutes().iter().collect(),
                    s.hours().iter().collect(),
                    s.days_of_month().iter().collect(),
                    s.months().iter().collect(),
                    s.days_of_week().iter().collect(),
                    s.years().iter().collect(),
                ];
                println!(
                    "{}",
                    fields
                        .iter()
                        .map(|f| f
                            .iter()
                            .map(|n| n.to_string())
                            .collect::<Vec<_>>()
                            .join(","))
                        .collect::<Vec<_>>()
                        .join("|")
                );
            }
        }
    }
}
