import urllib2
import sys
import subprocess
import json
import tempfile
import os
import textwrap
from operator import itemgetter
import termios
import struct
import fcntl

GITHUB_API_URL = 'https://api.github.com'
ORIGIN_LINE_START = 'Push  URL:'
GIT_EXECUTABLE = subprocess.Popen(
    'which \git', shell=True, stdout=subprocess.PIPE).communicate()[0].strip()

def git_cmd(args):
    result, _ = subprocess.Popen(
        [GIT_EXECUTABLE, ] + args, shell=False, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE).communicate() 
    return result.strip()


def get_console_width():
    result = struct.unpack('hhhh', fcntl.ioctl(
        0, termios.TIOCGWINSZ, struct.pack('HHHH', 0,0,0,0)))
    return result[1]


def wrap_to_console(text):
    """
    Wraps text to console width. For now, we won't cache the width value.
    """
    width = max(get_console_width() - 16, 52)
    return textwrap.wrap(text, width, replace_whitespace=False,
        break_long_words=False, break_on_hyphens=False)


def make_github_request(*args, **kwargs):
    """
    Send an authorization token in a github api request.
    """
    token = get_api_token()
    method = kwargs.pop('method', None)
    kwargs.setdefault('headers', {}).update(
            {'Authorization': 'token %s' % token,
             'User-agent': 'ccstolley-ghub'})
    req = urllib2.Request(*args, **kwargs)
    if method:
        req.get_method = lambda : method
    try:
        urlstream = urllib2.urlopen(req)
    except urllib2.HTTPError as e:
        print "%d %s" % (e.getcode(), e.reason)
        print json.dumps(json.loads(e.read()), indent=2)
        raise SystemExit
    content_type = urlstream.headers['content-type']
    if content_type.split(';')[0] == ('application/json'):
        return json.loads(urlstream.read())
    else:
        return urlstream.read()


def get_api_token():
    """
    Retrieve the API token.
    """
    return git_cmd("config --get github.token".split())


def get_branch():
    """
    Get the current local branch.
    """
    branch_name = git_cmd("symbolic-ref HEAD".split())
    if branch_name:
        return branch_name.strip().replace("refs/heads/", "")
    else:
        return None


def get_repo_and_user(remote_name='origin'):
    """
    Call git remote to retrieve the repo and user for the specified
    remote name. Typical values are 'upstream' and 'origin'.
    """
    origin = git_cmd(('remote show ' + remote_name).split())
    for line in origin.splitlines():
        line = line.strip()
        if line.startswith(ORIGIN_LINE_START):
            origin_line = line[len(ORIGIN_LINE_START):].strip()
            _, user_name_repo = origin_line.split(':')
            while user_name_repo.startswith('/'):
                user_name_repo = user_name_repo[1:]
            user_name, repo = user_name_repo.split('/')
            repo = repo.replace('.git', '')
            return user_name, repo


def get_lead_commit(base_branch):
    """
    Retreives the sha1 and subject of the first commit to appear
    on this branch (but not on base branch).
    """
    commit = git_cmd(("cherry -v " +
                      base_branch).split()).splitlines()[0].split()
    return (commit[1], ' '.join(commit[2:]))


def get_commit_message_body(commit_sha1):
    """
    Returns commit message body (no subject) for the given sha1.
    """
    cmd = "log --format=%b -n 1 " + commit_sha1
    return git_cmd(cmd.split())


def get_pull_requests(number):
    branch = get_branch()
    if branch is None:
        print 'ERROR: detached head'
        sys.exit(1)
    else:
        user, repo = get_repo_and_user('upstream')
        url = GITHUB_API_URL + '/repos/%s/%s/pulls' % (user, repo)
        if number:
            url += '/%d' % number
        return make_github_request(url)


def get_pull_request_diff(number):
    user, repo = get_repo_and_user('upstream')
    url = GITHUB_API_URL + '/repos/%s/%s/pulls/%s' % (user, repo, number)
    return make_github_request(url,
        headers={'accept': 'application/vnd.github.diff'})


def display_pull_requests(verbose=False, number=None):
    pullreqs = get_pull_requests(number)
    if number:
        pullreqs = (pullreqs, )
    for pr in pullreqs:
        print_pull_request(pr, verbose)
        print


def colored(text, color, attrs=None):
    colormap = dict(zip(
        ['grey', 'red', 'green', 'yellow', 'blue', 'magenta', 'cyan',
         'white', ], range(30, 38)))
    attrmap = dict(zip(
        ['bold', 'dark', '', 'underline', 'blink', '', 'reverse', 'concealed' ],
        range(1, 9)))
    reset = '\033[0m'
    fmt_str = '\033[%dm%s'
    text = fmt_str % (colormap[color], text)
    if attrs is not None:
        for attr in attrs:
            text = fmt_str % (attrmap[attr], text)
    return text + reset


def print_tuple(a, b, a_color='white', b_color='white'):
    print '%25s : %s' % (
        colored(a, a_color, attrs=['bold']),
        colored(b, b_color))


def get_pull_request_comments(number):
    user, repo = get_repo_and_user('upstream')
    url = GITHUB_API_URL + '/repos/%s/%s/issues/%d/comments' % (
        user, repo, number)
    issue_comments = make_github_request(url)
    url = GITHUB_API_URL + '/repos/%s/%s/pulls/%d/comments' % (
        user, repo, number)
    pull_comments = make_github_request(url)
    return sorted(issue_comments + pull_comments, key=itemgetter('created_at'))


def print_pull_request_comments(number):
    r = get_pull_request_comments(number)
    for comment in r:
        paragraphs = comment['body'].splitlines()
        for i, par in enumerate(paragraphs):
            wrapped_body = wrap_to_console(par)
            if i == 0:
                print_tuple(comment['user']['login'][:12], wrapped_body.pop(0),
                            a_color='cyan')
            for line in wrapped_body:
                print_tuple('', line)
        print


def print_pull_request(pr, verbose):
    if verbose:
        print_tuple('Title', '#%s %s' % (pr['number'], pr['title']),
                    b_color='yellow')
        print_tuple('Submitter', pr['user']['login'])
        print_tuple('Created At', pr['created_at'])
        if 'mergeable' in pr:
            if pr['merged']:
                mergelabel = ('Already merged', 'white', 'magenta')
            elif pr['mergeable']:
                mergelabel = ('Yes', 'white', 'green')
            else:
                mergelabel = ('No', 'white', 'red')
            print_tuple('Mergable', *mergelabel)
        print_tuple('URL', pr['html_url'])
        if 'commits' in pr:
            adds = colored("+%d" % pr['additions'], 'green')
            dels = colored("-%d" % pr['deletions'], 'red')
            print_tuple('Commits', "%d (%s, %s)" % (
                pr['commits'], adds, dels))
        paragraphs = pr['body'].splitlines()
        for i, par in enumerate(paragraphs):
            if i == 0:
                print_tuple('Body', '')
            for line in wrap_to_console(par):
                print_tuple('', line)
        print
        print_pull_request_comments(pr['number'])
    else:
        print_tuple(pr['user']['login'], '#%s %s' % (pr['number'], pr['title']))


def create_pull_request(base_branch):
    """
    Creates a new pull request from the commits in the current branch against
    the supplied base branch in upstream.
    """
    (upstream_user, upstream_repo) = get_repo_and_user('upstream')
    (user, repo) = get_repo_and_user('origin')
    (sha1, subj) = get_lead_commit(base_branch)
    body = get_commit_message_body(sha1)
    branch = get_branch()
    url = GITHUB_API_URL + '/repos/%s/%s/pulls' % (upstream_user, upstream_repo)

    data = json.dumps({'title': subj, 'body': body,
                       'head': ":".join((user, branch)), 'base': base_branch})
    result = make_github_request(url, data,
                                 headers={'content-type': 'application/json'})
    if 'number' in result:
        print "Submitted Pull Request #%d - %s" % (result['number'], result['title'])
    else:
        print "Sorry, something bad happened:" + result


def get_text_from_editor(def_text):
    tmp = tempfile.mktemp()
    open(tmp, "w").write(def_text)
    editor = os.environ.get("EDITOR","vim")
    os.system("%s + %s" % (editor, tmp))
    return "\n".join([k for k in open(tmp).read().splitlines()
                      if not k.startswith("#")])


def merge_pull_request(number):
    (upstream_user, upstream_repo) = get_repo_and_user('upstream')
    commit_msg = get_text_from_editor("# Enter merge comments for PR %d\n\n" %
                                      number)
    if not commit_msg:
        print "No commit message: Aborting."
        raise SystemExit
    data = json.dumps({'commit_message': commit_msg})
    url = GITHUB_API_URL + '/repos/%s/%s/pulls/%d/merge' % (
        upstream_user, upstream_repo, number)
    result = make_github_request(
        url, data, method='PUT', headers={'content-type': 'application/json'})
    if 'merged' in result:
        print "Pull Request #%d: %s" % (number, result['message'])
    else:
        print "Sorry, something bad happened:" + str(result)


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(
        description='command line interface to github')
    parser.add_argument(
        '-s', '--showpull', metavar='number', nargs='?', type=int,
        help='show pull request # or show all', default=0)
    parser.add_argument(
        '-d', '--diff', metavar='number', nargs=1, type=int,
        help='show diff for pull request #')
    parser.add_argument(
        '-n', '--newpull', help='create a new pull request from the current '
        'branch to base_branch',
        metavar='base_branch', nargs=1)
    parser.add_argument(
        '-m', '--mergepull', help='merge pull request #', type=int,
        metavar='number', nargs=1)
    parser.add_argument(
        '-v', '--verbose', help='be verbose', action='store_true')
    args = parser.parse_args()

    if args.showpull is not 0:
        display_pull_requests(number=args.showpull,
                              verbose=args.verbose or args.showpull)
    elif args.diff:
        print get_pull_request_diff(args.diff[0])
    elif args.newpull:
        create_pull_request(args.newpull[0])
    elif args.mergepull:
        merge_pull_request(args.mergepull[0])
    else:
        parser.print_usage()
