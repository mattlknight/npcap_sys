// MIT License

// Copyright (c) 2019 Matthew Knight

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// Copied directly from https://github.com/retep998/winapi-rs

use std::fmt::Write;
use std::fs;
use std::path::Path;
use utils::read_file;
const MAX_LEN: usize = 99;
const ROOT: &'static str = "src";
// (module name, &[lines to skip]); Omit the lines to whitelist the whole module.
const WHITE_LIST: &'static [(&'static str, &'static [&'static str])] = &[
    ("lib.rs", &[]),
    (
        r"um\d3d12sdklayers.rs",
        &[
            "    D3D12_GPU_BASED_VALIDATION_PIPELINE_STATE_CREATE_FLAG_FRONT_LOAD_CREATE_UNGUARDED_VALIDATION_SHADERS = 0x02,",
            "    D3D12_GPU_BASED_VALIDATION_PIPELINE_STATE_CREATE_FLAG_FRONT_LOAD_CREATE_GUARDED_VALIDATION_SHADERS = 0x04,",
            "    D3D12_MESSAGE_ID_CREATEGRAPHICSPIPELINESTATE_OM_DUAL_SOURCE_BLENDING_CAN_ONLY_HAVE_RENDER_TARGET_0",
        ],
    ),
];
#[test]
fn check_lines() {
    let mut err_list = String::new();
    process_modules(ROOT, &mut err_list);
    assert!(
        err_list.is_empty(),
        "All files must have a maximum line length of {}, must not contain blank lines, \
        and must end with a trailing newline. The following inconsistencies were found:\n\n{}\
        Note: if you can't make a line fit, add it to WHITE_LIST at {}:14",
        MAX_LEN,
        err_list,
        file!(),
    );
}
fn process_modules<P: AsRef<Path>>(dir: P, err_list: &mut String) {
    let dir = fs::read_dir(dir).expect("read_dir failed");
    for path in dir.map(|e| e.expect("DirEntry failed").path()) {
        if path.is_dir() {
            process_modules(&path, err_list);
        } else if path.extension().map(|ext| ext == "rs").unwrap_or(false) {
            check_module(&path, err_list);
        }
    }
}
fn check_module<P: AsRef<Path>>(path: P, err_list: &mut String) {
    let clean_path = &path.as_ref().to_str().expect("Path.to_str() failed")[ROOT.len() + 1..];
    let file = read_file(&path);
    let mut marked = false;
    let maybe_this = WHITE_LIST.into_iter()
                               .find(|&&(module, _)| module == clean_path)
                               .map(|&(_, allowed_lines)| allowed_lines);
    if maybe_this.map(|skip_lines| !skip_lines.is_empty()).unwrap_or(true) {
        for (line, n) in file.lines().zip(1..) {
            if line.matches('"').count() >= 2 // Allow long string constants
                || maybe_this.map(|skip_lines| skip_lines.contains(&line)).unwrap_or(false) {
                continue
            }
            let len = line.split_terminator("//")
                          .next()
                          .map(|actual| actual.trim_right().chars().count())
                          .unwrap_or(0);
            if line.is_empty() || len > MAX_LEN {
                if !marked {
                    writeln!(err_list, "--> {}:", clean_path).unwrap();
                    marked = true;
                }
                writeln!(err_list, "Line {} ({} chars);", n, len).unwrap();
            }
        }
    }
    if !file.ends_with('\n') {
        if !marked {
            writeln!(err_list, "--> {}:", clean_path).unwrap();
        }
        err_list.push_str("The file must end with a trailing newline.\n\n");
    } else if marked {
        err_list.push('\n');
    }
}
