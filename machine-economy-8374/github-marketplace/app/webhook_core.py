"""GitHub App source adapter. No listener, local secrets, or new custody path.

Existing host integration supplies TVC-managed secret bytes, an atomic durable
delivery adapter, installation auth, and router/GitHub interfaces. Without those
bindings no event is accepted for effects. Tests use explicit local fixtures.
"""
import hashlib
import hmac
import json
import re


class NonAllow(ValueError):
    pass


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise NonAllow('DUPLICATE_PAYLOAD_KEY')
        result[key] = value
    return result


def positive_id(value):
    return type(value) is int and value > 0


def verify_signature(body, signature, secret):
    if not isinstance(body, bytes) or len(body) > 2_000_000:
        raise NonAllow('WEBHOOK_BODY_INVALID')
    if not isinstance(secret, bytes) or not secret:
        raise NonAllow('EXISTING_TVC_SECRET_BINDING_REQUIRED')
    if not isinstance(signature, str) or not re.fullmatch(r'sha256=[0-9a-f]{64}', signature):
        raise NonAllow('WEBHOOK_SIGNATURE_REQUIRED')
    expected = 'sha256=' + hmac.new(secret, body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise NonAllow('WEBHOOK_SIGNATURE_MISMATCH')


def receipt_check(head_sha, evidence_url, pair_id, evidence_sha256):
    # A receipt link is publication, not recomputation. Never mint a success badge.
    if not isinstance(head_sha, str) or not re.fullmatch('[0-9a-f]{40}', head_sha):
        raise NonAllow('COMMIT_BINDING_REQUIRED')
    if not isinstance(evidence_url, str) or not evidence_url.startswith('https://8374.stegverse.org/'):
        raise NonAllow('PUBLIC_RECEIPT_ORIGIN_REQUIRED')
    if not isinstance(evidence_sha256, str) or not re.fullmatch('[0-9a-f]{64}', evidence_sha256):
        raise NonAllow('EVIDENCE_PIN_REQUIRED')
    if not isinstance(pair_id, str) or not re.fullmatch('PAIR-[0-9]{6,}', pair_id):
        raise NonAllow('PAIR_ID_REQUIRED')
    return {'name': 'StegVerse receipt publication', 'head_sha': head_sha,
            'status': 'completed', 'conclusion': 'neutral', 'details_url': evidence_url,
            'output': {'title': 'Published receipt; independent replay not established',
                       'summary': pair_id + ' | evidence SHA256 ' + evidence_sha256 +
                       ' | source publication only; no native admission or owner binding.'}}


def handle(headers, body, *, secret, deliveries, bindings, router, github):
    """Return effect summary; rejected/ambiguous delivery cannot be replayed blindly.

    deliveries.begin(id, payload_digest) must atomically reserve a delivery id,
    reject every duplicate, and retain partial/ambiguous outcomes. finish writes
    its final disposition. These are REQUIRED existing-host integration methods,
    never satisfied by an in-memory production fallback.
    """
    verify_signature(body, headers.get('X-Hub-Signature-256'), secret)
    delivery = headers.get('X-GitHub-Delivery')
    if not isinstance(delivery, str) or not re.fullmatch('[A-Za-z0-9-]{1,128}', delivery):
        raise NonAllow('DELIVERY_ID_REQUIRED')
    if any(x is None for x in (deliveries, bindings, router, github)):
        raise NonAllow('EXISTING_HOST_ADAPTERS_REQUIRED')
    try:
        payload = json.loads(body, object_pairs_hook=unique_object)
    except (ValueError, UnicodeError) as exc:
        raise NonAllow('WEBHOOK_JSON_INVALID') from exc
    if not isinstance(payload, dict):
        raise NonAllow('WEBHOOK_OBJECT_REQUIRED')
    event = headers.get('X-GitHub-Event')
    action = payload.get('action')
    if event not in ('installation', 'installation_repositories', 'marketplace_purchase', 'ping'):
        raise NonAllow('UNSUPPORTED_EVENT')
    # HMAC does not authenticate unsigned event headers. Bind event to signed shape.
    if event.startswith('installation'):
        install = payload.get('installation')
        if not isinstance(install, dict) or not positive_id(install.get('id')):
            raise NonAllow('INSTALLATION_BINDING_REQUIRED')
        account = install.get('account', {})
        if not isinstance(account, dict) or not positive_id(account.get('id')):
            raise NonAllow('INSTALLATION_ACCOUNT_REQUIRED')
        allowed = ('created', 'deleted', 'suspend', 'unsuspend') if event == 'installation' else ('added', 'removed')
        if action not in allowed:
            raise NonAllow('UNSUPPORTED_INSTALLATION_ACTION')
    elif event == 'marketplace_purchase':
        purchase = payload.get('marketplace_purchase')
        if not isinstance(purchase, dict) or not isinstance(purchase.get('account'), dict):
            raise NonAllow('MARKETPLACE_ACCOUNT_REQUIRED')
        if not positive_id(purchase['account'].get('id')) or action not in ('purchased', 'changed', 'cancelled', 'pending_change', 'pending_change_cancelled'):
            raise NonAllow('MARKETPLACE_ACTION_INVALID')
    elif not payload.get('zen') or 'hook' not in payload:
        raise NonAllow('PING_SHAPE_INVALID')
    if not deliveries.begin(delivery, hashlib.sha256(body).hexdigest()):
        raise NonAllow('DELIVERY_ALREADY_RESERVED')
    try:
        if event == 'ping':
            result = {'disposition': 'PING_ACCEPTED', 'authority_effect': 'NONE'}
        elif event == 'marketplace_purchase':
            # Record billing notification only. Pending changes are not effective
            # entitlements; trusted Marketplace reconciliation remains required.
            bindings.record_purchase(delivery, action, purchase)
            result = {'disposition': 'BILLING_NOTIFICATION_RECORDED', 'action': action,
                      'entitlement': 'NOT_GRANTED', 'authority_effect': 'NONE'}
        elif action in ('deleted', 'suspend'):
            bindings.disable_installation(install['id'], delivery)
            result = {'disposition': 'INSTALLATION_DISABLED', 'authority_effect': 'NONE'}
        elif event == 'installation_repositories' and action == 'removed':
            bindings.remove_repositories(install['id'], payload.get('repositories_removed', []), delivery)
            result = {'disposition': 'REPOSITORIES_REMOVED', 'authority_effect': 'NONE'}
        else:
            # Binding is owner-configured; no webhook-controlled URL or key slot.
            origin = bindings.public_origin(install['id'], account['id'])
            if not isinstance(origin, str) or not re.fullmatch(r'https://[A-Za-z0-9.-]+(?::443)?', origin):
                raise NonAllow('OWNER_PUBLIC_SERVICE_ORIGIN_REQUIRED')
            # Adapter speaks only to POST https://8374.stegverse.org/router/register
            # and sends {origin}. It must not use a payment/operator route.
            registered = router.register_public_origin(origin)
            bindings.record_installation(install['id'], account['id'], registered, delivery)
            result = {'disposition': 'PUBLIC_REGISTRATION_RECORDED',
                      'provenance': 'NOT_ESTABLISHED_BY_REGISTRATION', 'authority_effect': 'NONE'}
        deliveries.finish(delivery, result)
        return result
    except Exception:
        # Reservation stays consumed after an uncertain external effect. Recovery
        # reconciles existing evidence instead of replaying registration blindly.
        deliveries.finish(delivery, {'disposition': 'AMBIGUOUS_RECONCILE', 'authority_effect': 'NONE'})
        raise


def publish_receipt(github, installation_id, repository, head_sha, evidence_url, pair_id, evidence_sha256):
    if not positive_id(installation_id) or not isinstance(repository, str) or not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository):
        raise NonAllow('INSTALLATION_REPOSITORY_BINDING_REQUIRED')
    check = receipt_check(head_sha, evidence_url, pair_id, evidence_sha256)
    # Existing GitHub adapter verifies repository is in this authenticated
    # installation and gets its short-lived token through TVC; no local JWT key.
    return github.create_installation_check(installation_id, repository, check)
