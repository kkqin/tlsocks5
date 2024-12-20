use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::io;

#[derive(Debug)]
pub struct Config {
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

    pub fn has_section(&self, section: &str) -> bool {
        self.values_.contains_key(section)
    }

    pub fn get_int(&self, section: &str, key: &str) -> Option<i32> {
        self.get(section, key).and_then(|v| v.parse().ok())
    }

    pub fn get_str(&self, section: &str, key: &str) -> Option<String> {
        self.get(section, key).map(|v| v.to_string())
    }

    pub fn get_bool(&self, section: &str, key: &str) -> Option<bool> {
        self.get(section, key).and_then(|v| v.parse().ok())
    }

}

pub fn parse_file(file_path: &str) -> Result<Config, io::Error> {
    let path = Path::new(file_path);
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) => {
            return Err(io::Error::new(io::ErrorKind::InvalidInput,
                    format!("文件：{file_path}:{e}"),
            ))
        }
    };
    let reader = BufReader::new(file);
    let mut config = Config::new();
    let mut current_section = String::new();

    for line in reader.lines() {
        let line = line?;
        let line = line.trim();

        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if line.starts_with('[') && line.ends_with(']') {
            current_section = line[1..line.len() - 1].to_string();
            continue;
        }

        let mut parts = line.splitn(2, '=');
        let key = match parts.next() {
            Some(k) => k.trim(),
            None => {
                eprintln!("配置文件格式錯誤：缺少 key");
                return Err(io::Error::new(io::ErrorKind::InvalidInput,
                    format!("配置格式错误：key"),
                ))
            }
        };

        let value = match parts.next() {
            Some(k) => k.trim(),
            None => {
                eprintln!("配置文件格式錯誤：缺少 value");
                return Err(io::Error::new(io::ErrorKind::InvalidInput,
                    format!("配置格式错误：value"),
                ))
            }
        };

        config.values_
            .entry(current_section.clone())
            .or_insert_with(HashMap::new)
            .insert(key.to_string(), value.to_string());
    }
    Ok(config)
}
