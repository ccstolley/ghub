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
