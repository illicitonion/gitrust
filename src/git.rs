extern crate uuid;

use std::error::Error;
use std::path::Path;
use std::process::{Command, Stdio};
use std::str::from_utf8;
use std::string::String;
use tempdir::TempDir;
use self::uuid::Uuid;

pub fn squash_merge(base_repo: &str, base_branch: &str, head_repo: &str, head_branch: &str, commit_message: &str, username: &str, password: &str, committer_name: &str, committer_email: &str) -> Result<String, String> {
    let tmpdir = try_or_string!(TempDir::new("_gitclone"));

    try!(clone(tmpdir.path(), base_repo));
    let branch_to_merge = try!(fetch_remote(tmpdir.path(), base_repo, head_repo, head_branch));

    try!(checkout(tmpdir.path(), base_branch));
    try!(merge_with_squash(tmpdir.path(), &branch_to_merge));
    let sha = try!(commit(tmpdir.path(), commit_message, committer_name, committer_email));
    try!(push(tmpdir.path(), "origin", base_branch, username, password, false));

    return Ok(sha);
}

pub fn rewrite_history(repo: &str, branch: &str, baseline_repo: &str, baseline_branch: &str, commit_message: &str, username: &str, password: &str, committer_name: &str, committer_email: &str) -> Result<String, String> {
    let tmpdir = try_or_string!(TempDir::new("_gitclone"));

    try!(clone(tmpdir.path(), repo));

    let branch_to_diff = try!(fetch_remote(tmpdir.path(), repo, baseline_repo, baseline_branch));

    try!(checkout(tmpdir.path(), &branch_to_diff));

    let new_branch = Uuid::new_v4().to_hyphenated_string();
    try!(create_branch(tmpdir.path(), &new_branch));
    try!(merge_with_squash(tmpdir.path(), &format!("origin/{}", branch)));
    let sha = try!(commit(tmpdir.path(), commit_message, committer_name, committer_email));
    try!(push(tmpdir.path(), "origin", &format!("{}:{}", new_branch, branch), username, password, true));

    return Ok(sha);
}

fn add_remote(path: &Path, remote_name: &str, remote_url: &str) -> Result<(), String> {
    try!(run_git_command(path, &["remote", "add", remote_name, remote_url]));
    return Ok(());
}

fn fetch(path: &Path, remote_name: Option<&str>) -> Result<(), String> {
    let mut args = Vec::new();
    args.push("fetch");
    if remote_name.is_some() {
        args.push(remote_name.unwrap());
    }
    try!(run_git_command(path, &args[..]));
    return Ok(());
}

fn fetch_remote(path: &Path, cloned_repo: &str, remote_repo: &str, remote_branch: &str) -> Result<String, String> {
    let mut target = String::new();
    if cloned_repo != remote_repo {
        try!(add_remote(path, "remote", remote_repo));
        try!(fetch(path, Some("remote")));

        target.push_str("remote/");
    } else {
        target.push_str("origin/");
    }
    target.push_str(remote_branch);
    return Ok(target);
}

fn clone(path: &Path, repo: &str) -> Result<(), String> {
    try!(run_git_command(path, &["clone", repo, "."]));
    return Ok(());
}

fn checkout(path: &Path, branch: &str) -> Result<(), String> {
    try!(run_git_command(path, &["checkout", branch]));
    return Ok(());
}

fn create_branch(path: &Path, new_branch: &str) -> Result<(), String> {
    try!(run_git_command(path, &["checkout", "-b", new_branch]));
    return Ok(());
}

fn merge_with_squash(path: &Path, branch: &str) -> Result<(), String> {
    try!(run_git_command(path, &["merge", "--squash", branch]));
    return Ok(());
}

fn commit(path: &Path, message: &str, name: &str, email: &str) -> Result<String, String> {
    let author = format!("{} <{}>", name, email);
    let output = try!(run_git_command(path, &["commit", "-m", message, "--author", &author]));
    // [branch sha1] commit message
    let mut parts = output.split(" ");
    let part = match parts.nth(1) {
        Some(p) => { let mut s = p.to_owned(); s.pop() ; s },
        None => { return Err(From::from(format!("could not find sha in {}", output))) },
    };
    return Ok(try!(expand_sha(path, &part)));
}

fn expand_sha(path: &Path, sha: &str) -> Result<String, String> {
    return Ok(try!(run_git_command(path, &["log", "-n1", sha, "--pretty=format:%H"])));
}

fn push(path: &Path, remote: &str, branch: &str, username: &str, password: &str, force: bool) -> Result<(), String> {
    let do_force = match force {
        true => " --force",
        false => "",
    };

    let output = try_or_string!(
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
        return Err(format!("Bad exit code running git push: {}, stderr: {}", output.status.code().unwrap_or(-1), try_or_string!(String::from_utf8(output.stderr))));
    }
    return Ok(());
}

fn run_git_command(path: &Path, args: &[&str]) -> Result<String, String> {
    return run_git_command_with_fn(path, args, |c| c);
}

fn run_git_command_with_fn<F>(path: &Path, args: &[&str], f: F) -> Result<String, String>
    where F : FnOnce(&mut Command) -> &mut Command {
    let output = try_or_string!(
        f(Command::new("git")
        .args(args)
        .current_dir(path))
        .output()
    );
    if !output.status.success() {
        return Err(format!("Bad exit code running git {}: {}, stderr: {}", args[0], output.status.code().unwrap_or(-1), try_or_string!(String::from_utf8(output.stderr))));
    }
    return Ok(try_or_string!(String::from_utf8(output.stdout)));
}
