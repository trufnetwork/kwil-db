# Contributing

Thanks for taking the time to contribute to kwil-db! 

Please follow the guidelines below when contributing. If you have any questions, please feel free to reach out to us on [Discord](https://discord.com/invite/HzRPZ59Kay) or use the [discussions](https://github.com/trufnetwork/kwil-db/discussions) feature on GitHub.

## Table of Contents

- [Discussions](#discussions)
- [Issues](#issues)
- [Pull Requests](#pull-requests)
    - [Commit Messages](#commit-messages)
    - [Coding Style](#coding-style)
    - [Pull Request Process](#pull-request-process)
- [Development Guidelines](#development-guidelines)
    - [Grammar Development](#grammar-development)
    - [Parser Testing](#parser-testing)
- [License](#license)

## Discussions

Discussions are for general discussions related to kwil-db. This can be to discuss kwil-db architecture, important tradeoffs / considerations, or any topics that cannot be directly closed by a pull request.

Examples of good discussions:

- Discussing potental ways to price queries in kwil-db
- Discussing the tradeoffs of using postgres vs sqlite.
- Discussing potential procedures for handling consensus failures & changes (and a future issue if the discussion determines we need a feature, bug fix, or documentation change).

Discussions can lead to an issue if they determine that a feature, bug fix, or documentation change is needed.

## Issues

Issues are for reporting bugs, requesting features, requesting repository documentation, or discussing any other changes that can be directly resolved with a pull request to the kwil-db repository.

For general discussions, or discussions where it is unclear how the discussion would be closed by a pull request, please use the [discussion](https://github.com/trufnetwork/kwil-db/discussions) section.

For opening issues, please follow the following guidelines:

- **Use templates** for creating issues about bugs, feature requests, or documentation requests.
- **Search** the issue tracker before opening an issue to avoid duplicates.
- **Be clear & detailed** about what you are reporting. If reporting a bug, please include a minimal reproducible example, a detailed explanation of your KwilD configuration, and any logs or error messages that may be relevant. 

We strongly recommended submitting an issue before submitting a pull request, especially for pull requests that will require significant effort on your part. This is to ensure that the issue is not already being worked on and that your pull request will be accepted. Some features or fixes are intentionally not included in kwil-db - use issues to check with maintainers and save time!

## Pull Requests

### Commit Messages

kwil-db uses recommended [Go commit messages](https://go.dev/doc/contribute#commit_messages), with breaking changes and deprecations to be noted in the commit message footer. Commits should follow the following format:

```
[Package/File/Directory Name]: [Concise and concrete description of the PR/Issue]

[Longer description of the PR/Issue, if necessary]

[Optional: Issues Tagged + Breaking changes/deprecations]
```

For example:

```
cmd/kwil-cli: Add new command to do something

This PR adds a new command to do something. It also adds a new flag to the existing command to do something else.

Resolves #123

BREAKING CHANGE: This PR changes the behavior of the foo command. It now does something else.
```

There are two types of breaking changes: API breaking changes and consensus breaking changes. API breaking changes are any changes that effect the external API of packages that are consumed outside of kwil-db (i.e. proto, core, extensions, and cmd). Consensus breaking changes are any changes that effect the consensus protocol of kwil-db (i.e. changes to the database, or changes to the consensus protocol in internal).

Changes to internal packages (i.e. deployments, internal, parse, scripts, and test) that do not affect the database or consensus are not considered breaking changes and do not need to be tagged in the commit footer.

### Coding Style

Please ensure that your contributions adhere to the following coding guidelines:

- Code should adhere to the official Go [formatting](https://go.dev/doc/effective_go#formatting) guidelines (i.e. use [`gofmt`](https://pkg.go.dev/cmd/gofmt) or `task fmt` to format code).
- Code must be documented adhering to the Go commentary [guidelines](https://go.dev/doc/effective_go#commentary) and Go Doc [comments](https://go.dev/doc/comment).
- Code should be tested as much as possible. Tests should be placed in the same package as the code they are testing, in a file named `*_test.go` (e.g. `foo.go` should have a corresponding `foo_test.go`).

### Pull Request Process

1. Fork the repository by clicking the "Fork" button on the top right of the repository page. Clone the kwil-db repository and add your fork as a remote.

```bash
git clone https://github.com/trufnetwork/kwil-db
cd kwil-db
git checkout main
git remote add <your-origin-name> <your-fork-url>
git fetch <your-origin-name>
```

2. Create a new branch from the main branch, and add your changes to the new branch. Ensure that your code and commits follow the [coding style](#coding-style) and [commit message](#commit-messages) guidelines above.

```bash
git checkout main
git pull
git checkout -b <branch-name>
```

3. Start local Postgres before running tests:

```bash
docker compose -f ./deployments/compose/postgres/docker-compose.yml up
```

4. Ensure that your PR is ready to be merged and all unit and acceptance tests pass:

```bash
task install:deps # If first time contributing
task fmt  
task lint  
task tidy  
task test:unit  
task test:act 
```

5. Push your branch to github.

```bash
git add -u # Add all changes
git add <file> # Add specific files, if necessary
git commit -m "Your commit message"
git push -u <your-origin-name> <branch-name>
```

Please ensure that all the commits in your git history match the commit message [guidelines](#commit-messages) above. You can use `git rebase -i` to edit your commit history.

6. Open a pull request to the `main` branch of the kwil-db repository. Please follow the PR template. If `main` updates while the PR is open, please update the branch with latest `main` (rebase or merge).

7. Wait for a maintainer to review your PR. If there are any issues, you will be notified and you can make the necessary changes.

## Development Guidelines

### Grammar Development

If you're modifying the Kuneiform grammar (`.g4` files), please follow the comprehensive [Grammar Development Guide](docs/dev/grammar-development.md). This covers:

- ANTLR setup and Java requirements
- Grammar modification workflow
- Parser generation process
- Go visitor implementation updates
- Testing strategies for grammar changes

**Quick reference for grammar changes:**

1. **Prerequisites**: Ensure Java 17+ is installed
2. **Backup**: Always backup grammar files before changes
3. **Modify**: Edit `KuneiformParser.g4` and/or `KuneiformLexer.g4`
4. **Generate**: Run `./generate.sh` in `node/engine/parse/grammar/`
5. **Update**: Modify Go visitor code in `node/engine/parse/antlr.go`
6. **Test**: Add test cases in `node/engine/parse/parse_test.go`
7. **Verify**: Run `go test ./node/engine/parse/... -v`

### Parser Testing

When adding new language features or modifying existing ones:

- **Add comprehensive test cases** covering normal usage, edge cases, and error conditions
- **Follow existing test patterns** in `parse_test.go`
- **Test both positive and negative scenarios** (valid syntax and syntax errors)
- **Ensure all existing tests still pass** after changes
- **Use descriptive test names** that explain what is being tested

**Test case structure:**
```go
{
    name:  "Descriptive test name",
    input: "SQL or Kuneiform syntax to test",
    expect: &ExpectedASTStructure{...},
    err:   nil, // or expected error
},
```

For grammar changes, tests should verify that:
1. New syntax parses correctly
2. AST structure matches expectations  
3. Existing functionality remains unaffected
4. Error handling works for invalid syntax

## License

By contributing to kwil-db, you agree that your contributions will be licensed under its [Apache 2.0 License](https://www.apache.org/licenses/LICENSE-2.0).
