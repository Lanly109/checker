#![windows_subsystem = "windows"]

mod config;
mod render;

use anyhow::Result;
use chrono::{DateTime, FixedOffset, Utc};
use config::{Contestant, FileEntry, Problem};
use regex::Regex;
use std::fs::{read_dir, File};
use std::io::Read;
use std::path::Path;

fn try_crc32<P: AsRef<Path>>(path: P) -> Result<String, String> {
    let mut f = File::open(path).map_err(|e| format!("无法读取文件内容:{}", e))?;
    let mut s = Vec::new();
    f.read_to_end(&mut s)
        .map_err(|e| format!("无法读取文件内容:{}", e))?;
    Ok(format!("{:x}", md5::compute(&s)))
}

/// This function is used just as its name tells. See Rust [`Result::into_ok_or_err`].
fn result_into_ok_or_err<T>(r: Result<T, T>) -> T {
    match r {
        Ok(v) => v,
        Err(v) => v,
    }
}

#[derive(thiserror::Error, Debug)]
pub enum CSPError {
    #[error("错误 1, checker.cfg.json 不存在, 请联系监考员.\n({0})")]
    ConfigNotExist(#[source] std::io::Error),
    #[error("错误 2, checker.cfg.json 无法解析, 请联系监考员.\n({0})")]
    ConfigCannotParse(#[source] serde_json::Error),
    #[error("错误 2，checker.cfg.json 配置的根目录或其中文件无法访问，请联系监考员.\n({0})")]
    RootDirAccessFail(#[source] std::io::Error),
    #[error("错误 3, 没有找到有效的选手目录. 请阅读考生须知.")]
    NoValidContestantDir,
    #[error("错误 4, 找到多个选手目录.\n{0}")]
    MultipleContestantDir(String),
    #[error("无法解析 CSV 文件")]
    FailedToLoadCsv,
    #[error("无法解析 BIN 文件")]
    FailedToLoadBin,
    #[error("无法解析 Problem 文件")]
    FailedToLoadExternProblem,
    #[error("找不到 .txt 文件")]
    NoTxtFile,
    #[error("找到多个 .txt 文件")]
    MultipleTxtFiles,
    #[error("程序内部错误，请联系监考员.\n({0})")]
    Unknown(
        #[from]
        #[source]
        anyhow::Error,
    ),
}

fn build_message(messages: &mut Vec<(String, Color)>) -> Result<()> {
    let cfg_file = if let Some(d) = std::env::args().nth(1) {
        File::open(Path::new(&d).join("checker.cfg.json"))
    } else {
        File::open("checker.cfg.json")
    };
    let cfg_file = cfg_file.map_err(CSPError::ConfigNotExist)?;
    let mut cfg: Contestant =
        serde_json::from_reader(cfg_file).map_err(CSPError::ConfigCannotParse)?;

    for file in cfg.md5_check.iter() {
        let real_hash = result_into_ok_or_err(try_crc32(&file.name));
        let expected_hash = &file.md5;

        if real_hash != *expected_hash {
            messages.push((
                format!(
                    "文件 {} 校验值不匹配: found {}, expected {}.",
                    &file.name, real_hash, expected_hash
                ),
                Color::Red,
            ));
        } else {
            messages.push((
                format!("文件 {} 校验通过: {}.", &file.name, expected_hash),
                Color::Green,
            ));
        }
    }

    let mut valid_folders = Vec::new();

    for dir in read_dir(&cfg.root_path).map_err(CSPError::RootDirAccessFail)? {
        let dir = dir.map_err(CSPError::RootDirAccessFail)?;
        if dir.file_type()?.is_dir() && cfg.regex.is_match(dir.file_name().to_str().unwrap()) {
            valid_folders.push(dir.path());
        }
    }

    if valid_folders.is_empty() {
        Err(CSPError::NoValidContestantDir)?
    }

    if valid_folders.len() > 1 {
        Err(CSPError::MultipleContestantDir(
            valid_folders
                .iter()
                .map(|f| format!("    {:?}", f))
                .collect::<Vec<_>>()
                .join("\n"),
        ))?
    }

    let valid_folder_name = valid_folders.into_iter().next().unwrap();
    let user_directory = valid_folder_name;
    let student_id_found = Path::new(&user_directory)
        .strip_prefix(&cfg.root_path)?
        .to_str()
        .unwrap();

    // 获取 user_directory 下所有 .txt 文件名
    let mut txt_files = Vec::new();
    for entry in read_dir(&user_directory)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() && path.extension().and_then(|e| e.to_str()) == Some("txt") {
            if let Some(filename) = path.file_name().and_then(|n| n.to_str()) {
                txt_files.push(filename.to_string());
            }
        }
    }
    
    // 检查 .txt 文件数量并给出提示
    if txt_files.is_empty() {
        messages.push((CSPError::NoTxtFile.to_string(), Color::Red));
    } else if txt_files.len() > 1 {
        messages.push((CSPError::MultipleTxtFiles.to_string(), Color::Red));
    }
    
    let student_name = txt_files
        .into_iter()
        .next()
        .unwrap_or_default()
        .trim_end_matches(".txt")
        .to_string();

    let concate_id_name = format!("{} {}", student_id_found, student_name);

    messages.push((
        format!(
            "找到选手目录： 「{}」",
            concate_id_name
        ),
        Color::Yellow,
    ));

    let validate_bin_path = if let Some(d) = std::env::args().nth(1) {
        std::path::Path::new(&d).join("validate.bin")
    } else {
        std::path::Path::new("validate.bin").to_path_buf()
    };
    
    if validate_bin_path.exists() {
        let mut validate_bin_file = File::open(&validate_bin_path)
            .map_err(|_| CSPError::FailedToLoadBin)?;
        let mut validate_bin_content = Vec::new();
        validate_bin_file
            .read_to_end(&mut validate_bin_content)
            .map_err(|_| CSPError::FailedToLoadBin)?;
        
        // 计算 concate_id_name 的 md5
        let concate_id_name_md5 = format!("{:x}", md5::compute(concate_id_name.as_bytes()));

        // messages.push((
        //     format!("选手信息 MD5: {}", concate_id_name_md5),
        //     Color::Black,
        // ));
        
        // 将 validate.bin 内容按行解析，检查 md5 是否存在
        let validate_content = String::from_utf8_lossy(&validate_bin_content);
        let validate_hashes: Vec<&str> = validate_content
            .lines()
            .map(|line| line.trim())
            .filter(|line| !line.is_empty())
            .collect();
        
        if validate_hashes.contains(&concate_id_name_md5.as_str()) {
            messages.push((
                format!("准考证号与姓名匹配通过"),
                Color::Green
            ));
        } else {
            messages.push((
                format!("准考证号与姓名匹配失败({})，请检查输入是否正确", concate_id_name_md5),
                Color::Red
            ));
        }
    }
    
    if cfg.problem_extern {
        let problem_extern_path = "problem.extern";
        let mut problem_extern_file = File::open(&problem_extern_path)
            .map_err(|_| CSPError::FailedToLoadExternProblem)?;
        let mut problem_extern_content = String::new();
        problem_extern_file
            .read_to_string(&mut problem_extern_content)
            .map_err(|_| CSPError::FailedToLoadExternProblem)?;
        let extern_problems: Vec<String> = problem_extern_content
            .lines()
            .map(|line| line.trim().to_string())
            .filter(|line| !line.is_empty())
            .collect();
        
        cfg.problems = extern_problems
            .into_iter()
            .map(|name| {
                let regex_pattern = cfg.problem_regex.to_string().replace("{0}", &name);
                // messages.push((
                //     format!("加载外部题目: {} 使用正则 {}", name, regex_pattern),
                //     Color::Black,
                // ));
                let regex = Regex::new(&regex_pattern).unwrap_or_else(|_| cfg.problem_regex.clone());
                Problem {
                    name,
                    regex,
                    existing_files: Vec::new(),
                }
            })
            .collect();
    }

    for dir1 in read_dir(&user_directory)? {
        let dir1 = dir1?;
        if !dir1.file_type()?.is_dir() {
            continue;
        }
        for dir2 in read_dir(dir1.path())? {
            let dir2 = dir2?;
            if !dir2.file_type()?.is_file() {
                continue;
            }
            for prob in cfg.problems.iter_mut() {
                if prob
                    .regex
                    .is_match(dir2.path().strip_prefix(&user_directory)?.to_str().unwrap())
                {
                    prob.existing_files.push(FileEntry::from(&dir2)?);
                }
            }
        }
    }

    for prob in cfg.problems.iter() {
        messages.push((format!("题目 {}: ", prob.name), Color::Black));
        if prob.existing_files.is_empty() {
            messages.push((format!("    未找到源代码文件."), Color::Black));
        } else if prob.existing_files.len() == 1 {
            let file_entry = &prob.existing_files[0];
            let filename = file_entry.path.to_str().unwrap_or("");
            let f = Path::new(filename).strip_prefix(&user_directory)?;
            messages.push((
                format!(
                    "    找到文件 {} => 校验码 {}.",
                    f.display(),
                    result_into_ok_or_err(try_crc32(filename))
                ),
                Color::Black,
            ));
            if let Ok(mod_date) = file_entry.metadata.modified() {
                let mod_date: DateTime<Utc> = mod_date.into();
                let date_shanghai =
                    mod_date.with_timezone(&FixedOffset::east_opt(8 * 3600).unwrap());
                if mod_date >= cfg.start_time && mod_date <= cfg.end_time {
                    messages.push((
                        format!("             修改日期有效 {}.", date_shanghai),
                        Color::Black,
                    ));
                } else {
                    messages.push((
                        format!("             修改日期不在考试时间范围内 {}.", date_shanghai),
                        Color::Red,
                    ));
                }
            } else {
                messages.push((format!("             文件没有修改日期记录."), Color::Yellow));
            }
            let size = file_entry.metadata.len();
            if size > cfg.size_limit_kb * 1024 {
                messages.push((
                    format!("             文件大小 {}KiB 超出限制.", size / 1024),
                    Color::Red,
                ));
            }
        } else {
            messages.push((format!("    找到多个源代码文件:"), Color::Red));
            for file in prob.existing_files.iter() {
                messages.push((format!("        {}", file.path.display()), Color::Red));
            }
        }
    }

    let problem_names = cfg.problems.iter()
        .map(|p| p.name.as_str())
        .collect::<Vec<_>>()
        .join(",");
    let problem_names_md5 = format!("{:x}", md5::compute(problem_names.as_bytes()));
    messages.push((format!("题目列表 MD5: {}\n", problem_names_md5), Color::Yellow));

    if let Ok(f) = if let Some(d) = std::env::args().nth(1) {
        File::open(Path::new(&d).join("checker.hash.csv"))
    } else {
        File::open("checker.hash.csv")
    } {
        messages.push((format!("{}", "正在加载比对校验文件."), Color::Yellow));
        let mut map = std::collections::HashMap::<String, Vec<(String, String)>>::new();

        let mut rdr = csv::ReaderBuilder::new().has_headers(false).from_reader(f);
        for result in rdr.records() {
            // exam_id,problem,hash,room_id,seat_id
            let record = match result {
                Ok(v) => v,
                _ => Err(CSPError::FailedToLoadCsv)?,
            };
            let student_id = &record[0];
            let problem = &record[1];
            let hash = &record[2];

            if !map.contains_key(student_id) {
                map.insert(student_id.to_string(), Vec::new());
            }
            map.get_mut(student_id)
                .unwrap()
                .push((problem.to_string(), hash.to_string()));
        }

        for prob in cfg.problems.iter() {
            let f = prob.existing_files.first();
            let real_hash = if let Some(f) = f {
                result_into_ok_or_err(try_crc32(&f.path))
            } else {
                "文件不存在".to_string()
            };
            let submit_hash = map
                .get(student_id_found)
                .and_then(|m| {
                    m.iter()
                        .find(|(p, _)| *p == prob.name)
                        .map(|(_, h)| h.as_str())
                })
                .unwrap_or("文件不存在");

            if real_hash != *submit_hash {
                messages.push((
                    format!(
                        "题目 {} 校验值不匹配: found {}, expected {}.",
                        &prob.name, real_hash, submit_hash
                    ),
                    Color::Red,
                ));
            } else {
                messages.push((
                    format!("题目 {} 校验通过: {}.", &prob.name, submit_hash),
                    Color::Green,
                ));
            }
        }
    }

    Ok(())
}

pub fn main() {
    let mut messages = Vec::new();
    if let Err(e) = build_message(&mut messages) {
        messages.push((format!("{}", e), Color::Red));
    }
    render::render(&messages).unwrap();
}

#[derive(Debug)]
pub(crate) enum Color {
    Red,
    Yellow,
    Green,
    Black,
}
