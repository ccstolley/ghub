ghub
====
A command line interface for github

## Requirements

- Python 2.7 or greater
- git

## Introduction

`ghub` is a simple command line utility for facilitating common
tasks with github. It uses the repository found in the current
working directory to determine upstream and origin URLs.

More exhaustive tools exist (see http://hub.github.com for one
example). This tool is intended to be simple, fast and have few
dependencies.

This tool is unfinished. Most of the examples below don't work yet.

## Getting Started

1. Generate a personal access token from
   [github](https://github.com/settings/applications).
2. Store the access token in your gitconfig. This has potentially
   serious security implications. Only do this on a machine you trust:
   ```
   git config --global github.token <token value>
   ```
3. Create remote repositories for `upstream` and `origin`. Eg.:
    ```
    git remote add origin git@github.com:joesmith/ghub

    git remote add upstream git@github.com:ccstolley/ghub
    ```
4. Add an alias for ghub.py to make it easier to invoke from the
   shell. Eg., in tcsh:
    ```
    alias ghub python ${HOME}/stuff/ghub/ghub.py
    ```
5. Go drink beer.

## Examples

Display a specific issue:
    
    ghub issue 442

Post a comment to a specific issue:

    ghub comm 442

List a summary of all issues assigned to me:
    
    ghub list

Create a pull request from the current branch to the specific upstream branch:

    ghub cpr dev

Display pull request comments:

    ghub pr 101

Display pull request diff:
    
    ghub dpr 101
