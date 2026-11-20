"""Network adapters for an existing admitted host; no server or key generation."""
import json
import re
import urllib.error
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError('redirect refused')


def request_json(url, *, method='GET', payload=None, token=None):
    data = None if payload is None else json.dumps(payload).encode()
    headers = {'Accept': 'application/vnd.github+json', 'User-Agent': 'StegVerse-Q56-source-candidate',
               'Content-Type': 'application/json', 'X-GitHub-Api-Version': '2026-03-10'}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.build_opener(NoRedirect).open(req, timeout=15) as response:
        raw = response.read(1_000_001)
        if len(raw) > 1_000_000:
            raise ValueError('response too large')
        return json.loads(raw)


class PublicRouter:
    def register_public_origin(self, origin):
        return request_json('https://8374.stegverse.org/router/register', method='POST',
                            payload={'origin': origin})


class GitHubInstallation:
    def __init__(self, token_provider):
        # Supplied by existing TVC-authorized installation authentication.
        self.token_provider = token_provider

    def create_installation_check(self, installation_id, repository, check):
        if not isinstance(repository, str) or not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository):
            raise ValueError('repository invalid')
        token = self.token_provider(installation_id)
        if not isinstance(token, str) or not token:
            raise ValueError('installation token unavailable')
        found = False
        for page in range(1, 1001):
            listing = request_json('https://api.github.com/installation/repositories?per_page=100&page=' + str(page), token=token)
            repos = listing.get('repositories')
            if not isinstance(repos, list):
                raise ValueError('installation repository list invalid')
            if any(isinstance(r, dict) and isinstance(r.get('full_name'), str)
                   and r['full_name'].lower() == repository.lower() for r in repos):
                found = True
                break
            if len(repos) < 100:
                break
        if not found:
            raise ValueError('repository not in installation')
        return request_json('https://api.github.com/repos/' + repository + '/check-runs',
                            method='POST', payload=check, token=token)
