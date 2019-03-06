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

use std::collections::HashMap;
use std::fs::read_dir;
use std::io::{self, Write};
use std::path::Path;

use utils::read_file;

fn check_if_files_in_mod(
    files: &[String],
    mod_file: &Path,
    errors: &mut u32,
) {
    let content = read_file(mod_file);
    let mut imports = HashMap::new();
    for x in content.split('\n')
                    .filter_map(|s| {
                        let x: Vec<&str> = s.split("mod ").collect();
                        if x.len() < 2 {
                            None
                        } else {
                            // We assume that only one mod import is present on a line.
                            x[1].split(';').next()
                        }
                    }) {
        imports.insert(x.to_owned(), false);
    }
    for file in files {
        if let Some(import) = imports.get_mut(file) {
            *import = true;
        } else {
            writeln!(&mut io::stderr(),
                     "\"{}\" isn't imported in \"{}\"",
                     file,
                     mod_file.display()).unwrap();
            *errors += 1;
        }
    }

    // Just because we want to have checks without compilation!
    for (import, found) in &imports {
        if *found == false {
            writeln!(&mut io::stderr(),
                     "module \"{}\" is imported in \"{}\" but doesn't exist",
                     import,
                     mod_file.display()).unwrap();
            *errors += 1;
        }
    }
}

fn read_dirs<P: AsRef<Path>>(
    dir: P,
    errors: &mut u32,
) {
    let mut files = Vec::new();
    let mut mod_file = None;

    for entry in read_dir(dir).expect("read_dir failed") {
        let entry = entry.expect("entry failed");
        let path = entry.path();
        if path.is_dir() {
            read_dirs(path, errors);
            files.push(entry.file_name().into_string().unwrap());
        } else {
            let file_name = entry.file_name().into_string().unwrap();
            if file_name != "mod.rs" {
                files.push(file_name.replace(".rs", ""));
            } else {
                mod_file = Some(path);
            }
        }
    }
    if !files.is_empty() && mod_file.is_some() {
        check_if_files_in_mod(&files, &mod_file.unwrap(), errors);
    }
}

#[test]
fn check_all_files_are_used() {
    let mut errors = 0;
    read_dirs("src", &mut errors);
    assert!(errors == 0, "Not sorted feature(s) found");
}
