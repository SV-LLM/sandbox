"""Receiver adapter for an existing BaseHTTPRequestHandler-compatible host.

This module binds no socket and starts no process. The original host calls
receive(handler, context) ONLY at its explicitly admitted GitHub webhook route.
context provides the existing TVC secret resolver and durable/authorized adapters.
"""
import json
import webhook_core


def reply(handler, status, code):
    body = json.dumps({'disposition': code, 'authority_effect': 'NONE'}).encode()
    handler.send_response(status)
    handler.send_header('Content-Type', 'application/json')
    handler.send_header('Content-Length', str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)
    return status


def receive(handler, context):
    if handler.command != 'POST':
        return reply(handler, 405, 'POST_REQUIRED')
    if handler.headers.get('Content-Type', '').split(';', 1)[0].strip().lower() != 'application/json':
        return reply(handler, 415, 'JSON_CONTENT_TYPE_REQUIRED')
    # Refuse ambiguous request framing; existing host must enforce its ordinary
    # read deadline and route admission before calling this adapter.
    if handler.headers.get('Transfer-Encoding'):
        return reply(handler, 400, 'TRANSFER_ENCODING_REFUSED')
    if hasattr(handler.headers, 'get_all') and len(handler.headers.get_all('Content-Length', [])) != 1:
        return reply(handler, 400, 'DUPLICATE_CONTENT_LENGTH_REFUSED')
    length = handler.headers.get('Content-Length', '')
    if len(length) > 7 or not length.isascii() or not length.isdecimal() or not 0 < int(length) <= 2_000_000:
        return reply(handler, 413, 'BOUNDED_CONTENT_LENGTH_REQUIRED')
    if context is None:
        return reply(handler, 503, 'EXISTING_HOST_BINDINGS_REQUIRED')
    try:
        body = handler.rfile.read(int(length))
        if len(body) != int(length):
            return reply(handler, 400, 'WEBHOOK_BODY_TRUNCATED')
        # Secret is fetched only via the original authorized custody interface,
        # never accepted from payload/headers, written to disk, or returned.
        secret = context.webhook_secret()
        webhook_core.handle(handler.headers, body, secret=secret,
                            deliveries=context.deliveries, bindings=context.bindings,
                            router=context.router, github=context.github)
        return reply(handler, 200, 'RECEIPT_RECORDED')
    except webhook_core.NonAllow as exc:
        code = str(exc)
        status = 409 if code == 'DELIVERY_ALREADY_RESERVED' else 400
        if code.startswith('WEBHOOK_SIGNATURE'):
            status = 401
        if code in ('EXISTING_HOST_ADAPTERS_REQUIRED', 'EXISTING_TVC_SECRET_BINDING_REQUIRED'):
            status = 503
        return reply(handler, status, code)
    except (TimeoutError, OSError):
        # Durable reservation, if reached, remains retained by the core.
        return reply(handler, 503, 'AMBIGUOUS_OR_UNAVAILABLE_RECONCILE')
    except Exception:
        return reply(handler, 503, 'EXISTING_HOST_INTEGRATION_REQUIRED')
