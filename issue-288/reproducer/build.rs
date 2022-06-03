extern crate gcc;

fn main() {
    gcc::Config::new()
        .file("src/c/foo.c")
        .include("src")
        .compile("libfoo.a");
}
