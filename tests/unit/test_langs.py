from labsec.langs import detect_languages, slugify


def test_detects_languages_by_extension(make_tree):
    root = make_tree(
        {
            "Api/Program.cs": "class P {}",
            "Api/Api.csproj": "<Project/>",
            "web/src/app.component.ts": "export {}",
            "web/src/util.js": "1",
            "tools/run.py": "print(1)",
            "main.go": "package main",
            "Dockerfile": "FROM scratch",
            "svc/Dockerfile.prod": "FROM scratch",
            "infra/main.tf": "",
        }
    )
    langs = detect_languages(root)
    assert langs["csharp"] == 2
    assert langs["typescript"] == 1
    assert langs["javascript"] == 1
    assert langs["python"] == 1
    assert langs["go"] == 1
    assert langs["dockerfile"] == 2
    assert langs["terraform"] == 1


def test_ignores_dependency_and_build_directories(make_tree):
    root = make_tree(
        {
            "src/a.ts": "",
            "node_modules/lib/index.js": "",
            "bin/Debug/x.cs": "",
            "obj/y.cs": "",
            "dist/z.js": "",
            ".angular/cache/w.js": "",
            ".git/hooks/h.py": "",
        }
    )
    assert detect_languages(root) == {"typescript": 1}


def test_ignores_minified_files(make_tree):
    root = make_tree({"a.min.js": "", "b.js": ""})
    assert detect_languages(root) == {"javascript": 1}


def test_honors_exclude_globs(make_tree):
    root = make_tree({"src/a.cs": "", "tests/b.cs": "", "legacy/old/c.py": ""})
    langs = detect_languages(root, excludes=["tests/**", "legacy"])
    assert langs == {"csharp": 1}


def test_empty_project_has_no_languages(make_tree):
    root = make_tree({"README.md": "hi"})
    assert detect_languages(root) == {}


def test_slugify():
    assert slugify("My Project") == "my-project"
    assert slugify("My_App.v2") == "my_app.v2"
    assert slugify("  ../weird//name  ") == "weird-name"
