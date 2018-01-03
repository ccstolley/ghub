ghub
====

[![Build Status](https://travis-ci.org/ccstolley/ghub.svg?branch=master)](https://travis-ci.org/ccstolley/ghub)

A command line interface for github.

## Requirements

- Python 3.4.3 or greater
- git

## Introduction

`ghub` is a simple command line utility for facilitating common
tasks with github. It uses the repository found in the current
working directory to determine `upstream` and  `origin` URLs. You
can also use a single `origin` repo if you prefer.

More exhaustive tools exist (see http://hub.github.com for one
example). This tool is intended to be simple, fast and have few
dependencies.

This tool is a work in progress.

## Getting Started

1. Install ghub:
    ```
    git clone git@github.com:ccstolley/ghub

    cd ghub

    python3 ./setup.py install
    ```
2. Generate a personal access token from
   [github](https://github.com/settings/applications).
3. Stash the access token. This has potentially serious security
   implications. The token will be stored in the clear on the file system
   in a file readable only by you. Only do this on a machine you trust:
   ```
   ghub -S
   Enter token: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
   API token has been successfully stashed.
   ```
4. Create remote repositories for `upstream` and `origin`. Eg.:
    ```
    git remote add origin git@github.com:joesmith/ghub

    # optional
    git remote add upstream git@github.com:ccstolley/ghub
    ```
5. Drink a beer.

## Usage
```
usage: ghub [-h] [-i] [-p] [-d] [-n base] [-m] [-c] [-o] [-x] [-a [login]]
            [-v] [-ok] [-r [login[,login2]]] [-S] [-U]
            [number] [message]

command line interface to github

positional arguments:
  number                optional issue/PR number/login
  message               optional message

optional arguments:
  -h, --help            show this help message and exit
  -i, --showissue       show issue #, or show all for specified user
  -p, --showpull        show pull request # or show all open pull requests by
                        default if number is not specified
  -d, --diff            show diff for pull request #
  -n base, --newpull base
                        create a new pull request from the current branch to
                        base_branch
  -m, --mergepull       merge pull request #
  -c, --comment         post comment on issue #
  -o, --openissue       create a new issue
  -x, --close           close an issue #
  -a [login], --assign [login]
                        assign an issue to login
  -v, --verbose         be verbose
  -ok, --approve        approve pull request #
  -r [login[,login2]], --review [login[,login2]]
                        request review from login(s)
  -S, --stashtoken      Stash github API token
  -U, --unstashtoken    Destroy stashed github API token
```

## Examples

Display issue 442:

    ghub -i 442

Post a comment issue 442:

    ghub -c 442

Close issue 442:

    ghub -x 442

List all open issues in this repo:

    ghub -i

List all open pull requests in this repo:

    ghub -p

List issues assigned to ccstolley, including comments and summary:

    ghub -i ccstolley -v

Create a pull request from the current branch to the specific upstream branch:

    ghub -n master

Add reviewers to pull request 414:

    ghub -r manny,moe,jack 414

Display pull request and comments:

    ghub -p 101

Approve pull request:

    ghub -ok 101

Merge pull request:

    ghub -m 101

Most commands also allow you to specify a message as an additional argument, eg:

    ghub -ok 101 'LGTM'

    ghub -x 442 'resolved by #440'

Display pull request diff in color (requires cdiff):

    ghub -d 101 | cdiff
