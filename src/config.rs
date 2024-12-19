pub mod config {
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

#[derive(Debug)]
struct Config {
    values_ : HashMap<String, HashMap<String,String>>,
}

impl Config {
    fn new() -> Config {
        Config {
            values_: HashMap::new(),
        }
    }

    fn get(&self, section: &str, key: &str) -> Option<&str> {
        self.values_.get(section).and_then(|v| v.get(key).map(|v| v.as_str()))
    }

    fn has_section(&self, section: &str) -> bool {
        self.values_.contains_key(section)
    }

    fn get_int(&self, section: &str, key: &str) -> Option<i32> {
        self.get(section, key).and_then(|v| v.parse().ok())
    }

    fn get_str(&self, section: &str, key: &str) -> Option<String> {
        self.get(section, key).map(|v| v.to_string())
    }

    fn get_bool(&self, section: &str, key: &str) -> Option<bool> {
        self.get(section, key).and_then(|v| v.parse().ok())
    }

}

pub fn parse_file(file_path: &str) -> Config {
    let path = Path::new(file_path);
    let file = File::open(path).expect("無法打開配置文件");
    let reader = BufReader::new(file);
    let mut config = Config::new();
    let mut current_section = String::new();

    for line in reader.lines() {
        let line = line.expect("讀取配置文件時出現錯誤");
        let line = line.trim();

        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if line.starts_with('[') && line.ends_with(']') {
            current_section = line[1..line.len() - 1].to_string();
            continue;
        }

        let mut parts = line.splitn(2, '=');
        let key = parts.next().expect("配置文件格式錯誤").trim();
        let value = parts.next().expect("配置文件格式錯誤").trim();

        config.values_
            .entry(current_section.clone())
            .or_insert_with(HashMap::new)
            .insert(key.to_string(), value.to_string());
    }

    config
}

}