mod config;

use colored::Colorize;
use config::{Contestant, Problem};
use std::fmt::format;
use std::fs::{read_dir, File};
use std::io::Read;
use std::path::Path;
use std::result;

fn quit(reason: &str, code: i32) -> ! {
    eprintln!("{}", reason);
    eprintln!("按下 Enter 键退出...");
    std::io::stdin().read_line(&mut String::new()).unwrap();
    std::process::exit(code)
}

fn try_crc32<P: AsRef<Path>>(path: P) -> Result<String, String> {
    let mut f = File::open(path).map_err(|e| format!("无法读取文件内容:{}", e))?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf)
        .map_err(|e| format!("无法读取文件内容:{}", e))?;
    let mut hasher = crc32fast::Hasher::new();
    hasher.update(&buf);
    Ok(format!("{:#08X}", hasher.finalize()))
}

/// This function is used just as its name tells. See Rust [`Result::into_ok_or_err`].
fn result_into_ok_or_err<T>(r: Result<T, T>) -> T {
    match r {
        Ok(v) => v,
        Err(v) => v,
    }
}

fn main() {
    let cfg_file = if let Some(d) = std::env::args().nth(1) {
        File::open(Path::new(&d).join("checker.cfg.json"))
    } else {
        File::open("checker.cfg.json")
    };
    if cfg_file.is_err() {
        quit("错误 1, checker.cfg.json 不存在, 请联系监考员.", 1);
    }
    let cfg = serde_json::from_reader(cfg_file.unwrap());
    if cfg.is_err() {
        quit("错误 2, checker.cfg.json 无法解析, 请联系监考员.", 2);
    }
    let mut cfg: Contestant = cfg.unwrap();

    let mut valid_folders = Vec::new();

    for dir in read_dir(&cfg.root_path).unwrap() {
        let dir = dir.unwrap();
        if dir.file_type().unwrap().is_dir()
            && cfg.regex.is_match(dir.file_name().to_str().unwrap())
        {
            valid_folders.push(dir.path());
        }
    }

    if valid_folders.is_empty() {
        quit("错误 3, 没有找到有效的选手目录. 请阅读考生须知.", 3);
    }

    if valid_folders.len() > 1 {
        eprintln!("找到多个选手目录: ");
        for valid_folder in valid_folders.iter() {
            eprintln!("    {:?}", valid_folder);
        }
        quit("错误 4, 找到多个选手目录.", 4);
    }

    let valid_folder_name = valid_folders.into_iter().next().unwrap();
    let user_directory = valid_folder_name;

    for dir1 in read_dir(&user_directory).unwrap() {
        let dir1 = dir1.unwrap();
        if !dir1.file_type().unwrap().is_dir() {
            continue;
        }
        for dir2 in read_dir(dir1.path()).unwrap() {
            let dir2 = dir2.unwrap();
            if !dir2.file_type().unwrap().is_file() {
                continue;
            }
            for prob in cfg.problems.iter_mut() {
                if prob.regex.is_match(
                    dir2.path()
                        .strip_prefix(&user_directory)
                        .unwrap()
                        .to_str()
                        .unwrap(),
                ) {
                    prob.existing_files
                        .push(dir2.path().to_str().unwrap().to_string());
                }
            }
        }
    }

    for prob in cfg.problems.iter() {
        print!("题目 {}: ", prob.name);
        if prob.existing_files.is_empty() {
            println!("未找到源代码文件.");
        } else if prob.existing_files.len() == 1 {
            let f = Path::new(&prob.existing_files[0])
                .strip_prefix(&user_directory)
                .unwrap();
            println!(
                "找到文件 {} => 校验码 {}.",
                f.display(),
                result_into_ok_or_err(try_crc32(&prob.existing_files[0]))
            );
        } else {
            println!("找到多个源代码文件:");
            for file in prob.existing_files.iter() {
                println!("    {}", file);
            }
        }
    }

    if let Ok(f) = if let Some(d) = std::env::args().nth(1) {
        File::open(Path::new(&d).join("checker.hash.csv"))
    } else {
        File::open("checker.hash.csv")
    } {
        println!("{}", "正在加载比对校验文件.".yellow());
        let mut map = std::collections::HashMap::<String, Vec<(String, String)>>::new();

        let mut rdr = csv::ReaderBuilder::new().has_headers(false).from_reader(f);
        for result in rdr.records() {
            // exam_id,problem,hash,room_id,seat_id
            let record = result.expect("无法解析 CSV 文件");
            let student_id = &record[0];
            let problem = &record[1];
            let hash = &record[2];
            let _room_id = &record[3];
            let _seat_id = &record[4];

            if !map.contains_key(student_id) {
                map.insert(student_id.to_string(), Vec::new());
            }
            map.get_mut(student_id)
                .unwrap()
                .push((problem.to_string(), hash.to_string()));
        }

        let student_id_found = Path::new(&user_directory)
            .strip_prefix(&cfg.root_path)
            .unwrap()
            .to_str()
            .unwrap();
        if let Some(s) = map.get(student_id_found) {
            for (p, h) in s.iter() {
                let file = &cfg
                    .problems
                    .iter()
                    .find(|prob| prob.name == *p)
                    .unwrap()
                    .existing_files
                    .first();
                let real_hash = if let Some(f) = file {
                    result_into_ok_or_err(try_crc32(f))
                } else {
                    "文件不存在".to_string()
                };
                if real_hash != *h {
                    println!(
                        "{}",
                        format!(
                            "题目 {} 校验值不匹配: found {}, expected {}.",
                            p, real_hash, h
                        )
                        .on_red()
                    );
                } else {
                    println!("{}", format!("题目 {} 校验通过: {}.", p, h).on_green());
                }
            }
        } else {
            println!(
                "{}",
                format!("未找到校验目录的匹配项: {}", student_id_found).on_yellow()
            );
        }
    }

    quit("", 0);
}
