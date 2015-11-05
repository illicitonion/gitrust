use std::error::Error;
use std::path::Path;
use std::process::{Command, Stdio};
use std::str::from_utf8;
use std::string::String;
use tempdir::TempDir;

pub fn squash_merge(base_repo: &str, base_branch: &str, head_repo: &str, head_branch: &str, commit_message: &str, username: &str, password: &str) -> Result<String, Box<Error + Send + Sync>> {
    let tmpdir = try!(TempDir::new("_gitclone"));

    try!(clone(tmpdir.path(), base_repo));

    let mut branch_to_merge = String::new();
    if base_repo != head_repo {
        try!(add_remote(tmpdir.path(), "tomerge", head_repo));
        try!(fetch(tmpdir.path(), Some("tomerge")));

        branch_to_merge.push_str("tomerge/");
    } else {
        branch_to_merge.push_str("origin/");
    }
    branch_to_merge.push_str(head_branch);

    try!(checkout(tmpdir.path(), base_branch));
    try!(merge_with_squash(tmpdir.path(), &branch_to_merge));
    let sha = try!(commit(tmpdir.path(), commit_message));
    try!(push(tmpdir.path(), "origin", base_branch, username, password));
    return Ok(sha);
}

fn add_remote(path: &Path, remote_name: &str, remote_url: &str) -> Result<(), Box<Error + Send + Sync>> {
    try!(run_git_command(path, &["remote", "add", remote_name, remote_url]));
    return Ok(());
}

fn fetch(path: &Path, remote_name: Option<&str>) -> Result<(), Box<Error + Send + Sync>> {
    let mut args = Vec::new();
    args.push("fetch");
    if remote_name.is_some() {
        args.push(remote_name.unwrap());
    }
    try!(run_git_command(path, &args[..]));
    return Ok(());
}

fn clone(path: &Path, repo: &str) -> Result<(), Box<Error + Send + Sync>> {
    try!(run_git_command(path, &["clone", repo, "."]));
    return Ok(());
}

fn checkout(path: &Path, branch: &str) -> Result<(), Box<Error + Send + Sync>> {
    try!(run_git_command(path, &["checkout", branch]));
    return Ok(());
}

fn merge_with_squash(path: &Path, branch: &str) -> Result<(), Box<Error + Send + Sync>> {
    try!(run_git_command(path, &["merge", "--squash", branch]));
    return Ok(());
}

fn commit(path: &Path, message: &str) -> Result<String, Box<Error + Send + Sync>> {
    let output = try!(run_git_command(path, &["commit", "-m", message]));
    let mut parts = output.split(" ");
    let part = match parts.nth(1) {
        Some(p) => p,
        None => { return Err(From::from(format!("could not find sha in {}", output))) },
    };
    return Ok(part.to_owned());
}

fn push(path: &Path, remote: &str, branch: &str, username: &str, password: &str) -> Result<(), Box<Error + Send + Sync>> {
    let output = try!(
        Command::new("expect")
        .arg("-c").arg(format!("eval spawn git push {} {}", remote, branch))
        .arg("-c").arg("expect \"Username\"")
        .arg("-c").arg(format!("send \"{}\\r\"", username))
        .arg("-c").arg("expect \"Password\"")
        .arg("-c").arg(format!("send \"{}\\r\"", password))
        .arg("-c").arg("expect eof")
        .current_dir(path)
        .stdin(Stdio::null())
        .output()
    );
    if !output.status.success() {
        return Err(From::from(format!("Bad exit code running git push: {}, stderr: {}", output.status.code().unwrap_or(-1), try!(String::from_utf8(output.stderr)))));
    }
    return Ok(());
}

fn run_git_command(path: &Path, args: &[&str]) -> Result<String, Box<Error + Send + Sync>> {
    let output = try!(
        Command::new("git")
        .args(args)
        .current_dir(path)
        .output()
    );
    if !output.status.success() {
        return Err(From::from(format!("Bad exit code running git {}: {}, stderr: {}", args[0], output.status.code().unwrap_or(-1), try!(String::from_utf8(output.stderr)))));
    }
    return Ok(try!(String::from_utf8(output.stdout)));
}
