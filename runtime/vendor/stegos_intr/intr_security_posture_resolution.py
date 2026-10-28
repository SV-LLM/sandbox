"""Authoritative task-scoped security-posture resolution at the Interlock/InTr boundary."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from hashlib import sha256
from json import dumps
from typing import Any, Mapping

RESOLUTION_SCHEMA = "stegos.intr-security-posture-resolution.v1"
INSTANCE_SCHEMA = "stegverse.intr.security-posture-instance.v1"
REQUEST_SCHEMA = "stegverse.sdk.security-posture-request.v1"
TIER_RANK = {"SECURE": 1, "HIGH": 2, "HIGHEST": 3}
DATA_CLASS_MINIMUM = {"PII":"HIGH","ePHI":"HIGHEST","EPHI":"HIGHEST","PHI":"HIGHEST","PII_EPHI":"HIGHEST","sensitive-health-data":"HIGHEST"}
CHANNEL_MINIMUM = {"KV-SKAP":"HIGHEST","SKAP-KV":"HIGHEST"}
POSTURE_ID = {"SECURE":"stegverse.security.secure.v1","HIGH":"stegverse.security.high.v1","HIGHEST":"stegverse.security.health-pii-high.v1"}

class InTrSecurityPostureError(ValueError): pass

def _require(condition: bool, reason: str) -> None:
    if not condition: raise InTrSecurityPostureError(reason)

def _digest(value: Mapping[str, Any]) -> str:
    return sha256(dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()

def _parse_time(value: str) -> datetime:
    try: result=datetime.fromisoformat(value.replace("Z","+00:00"))
    except (AttributeError,ValueError) as exc: raise InTrSecurityPostureError("invalid_posture_resolution_time") from exc
    _require(result.tzinfo is not None,"posture_resolution_time_must_be_timezone_aware")
    return result.astimezone(timezone.utc)

def _tier(value: object, field: str) -> str:
    text=str(value or ""); _require(text in TIER_RANK,f"unsupported_{field}"); return text

def resolve_task_security_posture(*,request: Mapping[str,Any],task_id:str,payload_sha256:str,transition_request_sha256:str,observed_at:str,ttl_seconds:int=900)->dict[str,Any]:
    _require(request.get("schema")==REQUEST_SCHEMA,"invalid_sdk_posture_request_schema")
    _require(request.get("authority_effect")=="NONE_REQUEST_INPUT_ONLY","sdk_posture_request_must_be_non_authorizing")
    _require(request.get("task_id")==task_id,"posture_request_task_mismatch")
    _require(isinstance(ttl_seconds,int) and 0<ttl_seconds<=3600,"posture_ttl_out_of_bounds")
    _require(isinstance(payload_sha256,str) and payload_sha256.startswith("sha256:") and len(payload_sha256)==71,"payload_sha256_required")
    _require(isinstance(transition_request_sha256,str) and transition_request_sha256.startswith("sha256:") and len(transition_request_sha256)==71,"transition_request_sha256_required")
    org_floor=_tier(request.get("organization_minimum_tier","SECURE"),"organization_minimum_tier")
    data_class=request.get("data_class"); channel=request.get("channel")
    candidates=[org_floor]
    if data_class in DATA_CLASS_MINIMUM: candidates.append(DATA_CLASS_MINIMUM[data_class])
    if channel in CHANNEL_MINIMUM: candidates.append(CHANNEL_MINIMUM[channel])
    automatic=max(candidates,key=lambda t:TIER_RANK[t])
    selection_present=request.get("selection_present") is True or request.get("selected_tier") is not None
    selected=_tier(request.get("selected_tier"),"selected_tier") if selection_present else automatic
    _require(TIER_RANK[selected]>=TIER_RANK[automatic],"selected_security_posture_below_automatic_floor")
    effective=max((automatic,selected),key=lambda t:TIER_RANK[t])
    issued=_parse_time(observed_at); expires=issued+timedelta(seconds=ttl_seconds)
    material={"task_id":task_id,"payload_sha256":payload_sha256,"transition_request_sha256":transition_request_sha256,"automatic_tier":automatic,"selected_tier":selected,"selection_present":selection_present,"effective_tier":effective,"channel":channel,"data_class":data_class,"issued_at":issued.isoformat().replace("+00:00","Z"),"expires_at":expires.isoformat().replace("+00:00","Z")}
    instance_sha=_digest(material)
    instance={"schema":INSTANCE_SCHEMA,"instance_id":f"INTR-SP-{instance_sha[:24]}",**material,"automatic_posture_id":POSTURE_ID[automatic],"selected_posture_id":POSTURE_ID[selected],"effective_posture_id":POSTURE_ID[effective],"resolution_authority":"INTERLOCK_INTR","credential_authority":"TV/TVC","transferable":False,"reusable_across_tasks":False,"authority_effect":"NONE_POSTURE_ADMISSION_EVIDENCE_ONLY"}
    instance["instance_sha256"]=_digest(instance)
    return {"schema":RESOLUTION_SCHEMA,"task_id":task_id,"automatic_posture":{"tier":automatic,"posture_id":POSTURE_ID[automatic]},"selected_posture":{"tier":selected,"posture_id":POSTURE_ID[selected],"selection_present":selection_present},"effective_posture":{"tier":effective,"posture_id":POSTURE_ID[effective]},"posture_instance":instance,"resolution_authority":"INTERLOCK_INTR","credential_authority":"TV/TVC","sdk_authoritative_final_tier":False,"authority_effect":"NONE_POSTURE_ADMISSION_EVIDENCE_ONLY"}

def verify_task_security_posture_instance(instance:Mapping[str,Any],*,task_id:str,payload_sha256:str,transition_request_sha256:str,observed_at:str)->None:
    _require(instance.get("schema")==INSTANCE_SCHEMA,"invalid_intr_posture_instance_schema")
    _require(instance.get("resolution_authority")=="INTERLOCK_INTR","posture_resolution_authority_mismatch")
    _require(instance.get("credential_authority")=="TV/TVC","credential_authority_mismatch")
    _require(instance.get("task_id")==task_id,"posture_instance_task_mismatch")
    _require(instance.get("payload_sha256")==payload_sha256,"posture_instance_payload_mismatch")
    _require(instance.get("transition_request_sha256")==transition_request_sha256,"posture_instance_transition_mismatch")
    _require(instance.get("transferable") is False and instance.get("reusable_across_tasks") is False,"posture_instance_reuse_forbidden")
    observed=_parse_time(observed_at)
    _require(_parse_time(str(instance.get("issued_at")))<=observed<_parse_time(str(instance.get("expires_at"))),"posture_instance_inactive")
    body=dict(instance); claimed=body.pop("instance_sha256",None)
    _require(claimed==_digest(body),"posture_instance_digest_mismatch")
