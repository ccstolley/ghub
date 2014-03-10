import urllib2
import sys
import subprocess
import json
import termcolor
import textwrap

GITHUB_API_URL = 'https://api.github.com'
GITHUB_HTML_URL = 'https://github.com'
ORIGIN_LINE_START = 'Push  URL:'
GIT_EXECUTABLE = subprocess.Popen(
    'which \git', shell=True, stdout=subprocess.PIPE).communicate()[0].strip()

def git_cmd(args):
    result, _ = subprocess.Popen(
        [GIT_EXECUTABLE, ] + args, shell=False, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE).communicate() 
    return result.strip()


def make_github_request(*args, **kwargs):
    """
    Send an authorization token in a github api request.
    """
    token = get_api_token()
    kwargs.setdefault('headers', {}).update(
            {'Authorization': 'token %s' % token})
    req = urllib2.Request(*args, **kwargs)
    urlstream = urllib2.urlopen(req)
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
        user, repo = get_repo_and_user()
        url = GITHUB_API_URL + '/repos/%s/%s/pulls' % (user, repo)
        if number:
            url += '/%d' % number
        return make_github_request(url)


def get_pull_request_diff(number):
    user, repo = get_repo_and_user()
    url = GITHUB_HTML_URL + '/%s/%s/pull/%s.diff' % (user, repo, number)
    return make_github_request(url)


def display_pull_requests(verbose=False, number=None):
    pullreqs = get_pull_requests(number)
    if number:
        pullreqs = (pullreqs, )
    for pr in pullreqs:
        print_pull_request(pr, verbose)
        print


def print_pull_request(pr, verbose):
    def print_tuple(a, b, a_color='white', b_color='white'):
        print '%25s : %s' % (
            termcolor.colored(a, a_color, attrs=['bold']),
            termcolor.colored(b, b_color))

    if verbose:
        print_tuple('Title', '#%s %s' % (pr['number'], pr['title']),
                    b_color='yellow')
        print_tuple('Submitter', pr['user']['login'])
        print_tuple('Created At', pr['created_at'])
        if 'mergeable' in pr:
            col = 'green' if pr['mergeable'] else 'red'
            print_tuple('Mergable', pr['mergeable'], b_color=col)
        print_tuple('URL', pr['html_url'])
        paragraphs = pr['body'].splitlines()
        for i, par in enumerate(paragraphs):
            if i == 0:
                print_tuple('Body', '')
            for line in textwrap.wrap(par, 52, replace_whitespace=False):
                print_tuple('', line)
    else:
        print_tuple(pr['user']['login'], '#%s %s' % (pr['number'], pr['title']))


def create_pull_request(base_branch):
    """
    Creates a new pull request from the commits in the current branch against
    the supplied base branch in upstream.
    """
    (upstream_user, upstream_repo) = get_repo_and_user('upstream')
    (user, repo) = get_repo_and_user('upstream')
    (sha1, subj) = get_lead_commit(base_branch)
    body = get_commit_message_body(sha1)
    branch = get_branch()
    url = GITHUB_API_URL + '/repos/%s/%s/pulls' % (upstream_user, upstream_repo)

    data = json.dumps({'title': subj, 'body': body,
                       'head': ":".join((user, branch)), 'base': base_branch})
    result = make_github_request(url, data)
    if 'number' in result:
        print "Submitted Pull Request #%d - %s" % (result['number'], result['title'])
    else:
        print "Sorry, something bad happened:" + result


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
        '-v', '--verbose', help='be verbose', action='store_true')
    args = parser.parse_args()

    if args.showpull is not 0:
        display_pull_requests(number=args.showpull,
                              verbose=args.verbose or args.showpull)
    elif args.diff:
        print get_pull_request_diff(args.diff[0])
    elif args.newpull:
        create_pull_request(args.newpull[0])
    else:
        parser.print_usage()
