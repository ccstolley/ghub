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

## Usage
```
usage: ghub.py [-h] [-i [number]] [-p [number]] [-d number] [-n base_branch]
               [-m number] [-c number] [-v]

command line interface to github

optional arguments:
  -h, --help            show this help message and exit
  -i [number], --showissue [number]
                        show issue #, or show all for specified user
  -p [number], --showpull [number]
                        show pull request # or show all
  -d number, --diff number
                        show diff for pull request #
  -n base_branch, --newpull base_branch
                        create a new pull request from the current branch to
                        base_branch
  -m number, --mergepull number
                        merge pull request #
  -c number, --comment number
                        post comment on issue #
  -v, --verbose         be verbose
```

## Examples

Display a specific issue:
    
    ghub -i 442

Post a comment to a specific issue:

    ghub -c 442

List all open issues assigned to me in this repo:
    
    ghub -i
    
List all unassigned open issues in this repo:

    ghub -i none
    
List all open issues in this repo:

    ghub -i '*'

List issues assigned to ccstolley, including comments and summary:

    ghub -i ccstolley -v

Create a pull request from the current branch to the specific upstream branch:

    ghub -n dev

Display pull request and comments:

    ghub -p 101
    
Merge pull request:

    ghub -m 101

Display pull request diff in color (requires cdiff):
    
    ghub -d 101 | cdiff
