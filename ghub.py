import urllib2
import subprocess


GITHUB_API_URL = 'https://api.github.com'
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
    return urllib2.urlopen(req).read()


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


def get_repo_and_user():
    """
    Call show origin to retrieve the repo and user.
    """
    origin = git_cmd('remote show origin'.split())
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


def list_pull_requests():
    branch = get_branch()
    if branch is None:
        print 'detached head'
        sys.exit(1)
    else:
        user, repo = get_repo_and_user()
        url = GITHUB_API_URL + '/repos/%s/%s/pulls' % (user, repo)
        return make_github_request(url)


