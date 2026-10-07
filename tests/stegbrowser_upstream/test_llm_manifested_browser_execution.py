from src.stegbrowser.llm_profile import validate_llm_profile_request

def test_llm_v1_accepts_manifested_credential_free_https_browser_actions():
    req = validate_llm_profile_request({
        "schema":"stegbrowser.llm-profile-request.v1","profile":"llm.v1",
        "prompt":"Return TEST5_A","response_marker":"TEST5_A",
        "provider":"free-browser-model","model":"manifest-selected",
        "secure_url":"https://example.test/chat",
        "browser_actions":[
            {"op":"fill","selector":"textarea","value":"Return TEST5_A"},
            {"op":"press","selector":"textarea","key":"Enter"},
            {"op":"wait_for","selector":"[data-answer]"},
            {"op":"read_text","selector":"[data-answer]"},
        ],
        "journey":{
            "schema":"stegverse.packet-carried-endpoint-receipt-journey/v1",
            "journey_id":"test5-a","origin_endpoint":"worker-a","ephemeral_endpoint":"stegbrowser",
            "outbound_manifest_sha256":"sha256:out","return_manifest_sha256":"sha256:return",
            "return_predecessor_manifest_sha256":"sha256:out",
        },
    })
    assert req["secure_url"] == "https://example.test/chat"
    assert req["browser_actions"][-1]["op"] == "read_text"

def test_llm_v1_rejects_non_https_endpoint():
    import pytest
    with pytest.raises(ValueError, match="secure_url must use https"):
        validate_llm_profile_request({
            "schema":"stegbrowser.llm-profile-request.v1","profile":"llm.v1",
            "prompt":"x","response_marker":"x","secure_url":"http://example.test",
            "browser_actions":[{"op":"read_text","selector":"body"}],
            "journey":{"schema":"stegverse.packet-carried-endpoint-receipt-journey/v1","journey_id":"j",
            "origin_endpoint":"a","ephemeral_endpoint":"b","outbound_manifest_sha256":"o",
            "return_manifest_sha256":"r","return_predecessor_manifest_sha256":"o"},
        })


def test_llm_authorization_refusal_finalizes_ephemeral_lease():
    """Denied navigation must not leave an opened session unfinalized."""
    from unittest.mock import MagicMock, patch
    import pytest
    from src.stegbrowser.llm_browser_execution import execute_manifested_llm_browser_operation

    session = MagicMock()
    session.authorize.side_effect = PermissionError("origin is outside the lease")
    request = {
        "schema": "stegbrowser.llm-profile-request.v1",
        "profile": "llm.v1",
        "prompt": "Return TEST5_A",
        "response_marker": "TEST5_A",
        "secure_url": "https://example.test/chat",
        "browser_actions": [{"op": "read_text", "selector": "body"}],
        "journey": {
            "schema": "stegverse.packet-carried-endpoint-receipt-journey/v1",
            "journey_id": "lease-refusal",
            "origin_endpoint": "origin",
            "ephemeral_endpoint": "stegbrowser",
            "outbound_manifest_sha256": "sha256:out",
            "return_manifest_sha256": "sha256:return",
            "return_predecessor_manifest_sha256": "sha256:out",
        },
    }
    with patch("src.stegbrowser.llm_browser_execution.EphemeralBrowserSession.open", return_value=session):
        with pytest.raises(PermissionError, match="origin is outside the lease"):
            execute_manifested_llm_browser_operation(request, lease={})
    session.close.assert_called_once_with(reason="error")
