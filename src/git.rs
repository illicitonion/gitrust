extern crate uuid;

use std::error::Error;
use std::fs::{self, File};
use std::os::unix::prelude::{AsRawFd, FromRawFd};
use std::path::Path;
use std::process::{Command, Stdio};
use std::str::from_utf8;
use std::string::String;
use tempdir::TempDir;
use self::uuid::Uuid;

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
    try!(push(tmpdir.path(), "origin", base_branch, username, password, false));
    return Ok(sha);
}

pub fn rewrite_history(repo: &str, branch: &str, baseline_repo: &str, baseline_branch: &str, commit_message: &str, username: &str, password: &str) -> Result<String, Box<Error + Send + Sync>> {
    let tmpdir = try!(TempDir::new("_gitclone"));
    let repodir = tmpdir.path().join("repo");
    let repodir_path = repodir.as_path();
    try!(fs::create_dir(repodir_path));

    try!(clone(repodir_path, repo));

    let mut branch_to_diff = String::new();
    if baseline_repo != repo {
        try!(add_remote(tmpdir.path(), "todiff", baseline_repo));
        try!(fetch(tmpdir.path(), Some("todiff")));

        branch_to_diff.push_str("todiff/");
    } else {
        branch_to_diff.push_str("origin/");
    }
    branch_to_diff.push_str(baseline_branch);

    let new_branch = Uuid::new_v4().to_hyphenated_string();
    try!(create_branch(repodir_path, &new_branch));
    // It would be nice to use tempfile here, but it has a dep clash with time
    let tmpfile = tmpdir.path().join(&new_branch);
    unsafe {
        try!(diff(repodir_path, &branch_to_diff, &format!("origin/{}", branch), Stdio::from_raw_fd(try!(File::create(tmpfile.as_path())).as_raw_fd())));
        try!(apply(repodir_path, Stdio::from_raw_fd(try!(File::open(tmpfile.as_path())).as_raw_fd())));
    }
    try!(add_all(repodir_path));

    let sha = try!(commit(repodir_path, commit_message));
    try!(push(repodir_path, "origin", &format!("{}:{}", new_branch, branch), username, password, true));

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

fn create_branch(path: &Path, new_branch: &str) -> Result<(), Box<Error + Send + Sync>> {
    try!(run_git_command(path, &["checkout", "-b", new_branch]));
    return Ok(());
}

fn merge_with_squash(path: &Path, branch: &str) -> Result<(), Box<Error + Send + Sync>> {
    try!(run_git_command(path, &["merge", "--squash", branch]));
    return Ok(());
}

fn add_all(path: &Path) -> Result<(), Box<Error + Send + Sync>> {
    try!(run_git_command(path, &["add", "-A"]));
    return Ok(());
}

fn commit(path: &Path, message: &str) -> Result<String, Box<Error + Send + Sync>> {
    let output = try!(run_git_command(path, &["commit", "-m", message]));
    // [branch sha1] commit message
    let mut parts = output.split(" ");
    let part = match parts.nth(1) {
        Some(p) => { let mut s = p.to_owned(); s.pop() ; s },
        None => { return Err(From::from(format!("could not find sha in {}", output))) },
    };
    return Ok(try!(expand_sha(path, &part)));
}

fn expand_sha(path: &Path, sha: &str) -> Result<String, Box<Error + Send + Sync>> {
    return Ok(try!(run_git_command(path, &["log", "-n1", sha, "--pretty=format:%H"])));
}

fn diff(path: &Path, base: &str, head: &str, out_to: Stdio) -> Result<(), Box<Error + Send + Sync>> {
    try!(run_git_command_with_fn(path, &["diff", base, head], |c| c.stdout(out_to)));
    return Ok(());
}

fn apply(path: &Path, in_from: Stdio) -> Result<(), Box<Error + Send + Sync>> {
    try!(run_git_command_with_fn(path, &["apply", "-"], |c| c.stdin(in_from)));
    return Ok(());
}

fn push(path: &Path, remote: &str, branch: &str, username: &str, password: &str, force: bool) -> Result<(), Box<Error + Send + Sync>> {
    let do_force = match force {
        true => " --force",
        false => "",
    };

    let output = try!(
        Command::new("expect")
        .arg("-c").arg(format!("eval spawn git push{} {} {}", do_force, remote, branch))
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
    return run_git_command_with_fn(path, args, |c| c);
}

fn run_git_command_with_fn<F>(path: &Path, args: &[&str], f: F) -> Result<String, Box<Error + Send + Sync>>
    where F : FnOnce(&mut Command) -> &mut Command {
    let output = try!(
        f(Command::new("git")
        .args(args)
        .current_dir(path))
        .output()
    );
    if !output.status.success() {
        return Err(From::from(format!("Bad exit code running git {}: {}, stderr: {}", args[0], output.status.code().unwrap_or(-1), try!(String::from_utf8(output.stderr)))));
    }
    return Ok(try!(String::from_utf8(output.stdout)));
}
