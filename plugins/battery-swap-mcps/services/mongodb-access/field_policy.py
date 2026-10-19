"""Typed, recursive projections from reviewed public Mongoose schemas."""
import hashlib
import math
import re
from datetime import datetime, timezone

from bson import ObjectId, Int64, Decimal128
from access import Denied, SECRET

DROP=object()
SENSITIVE_VALUE=re.compile(r"password|passwd|secret|credential|authorization|bearer|api[ _-]?key|token|\botp\b|://|-----BEGIN|gh[pousr]_|github_pat_|sk-[A-Za-z0-9]|AIza",re.I)
TOKEN_VALUE=re.compile(r"[A-Za-z0-9_+/=-]{24,}")


def safe_label(value,limit=160):
    if type(value) is not str or len(value)>limit or SENSITIVE_VALUE.search(value) or TOKEN_VALUE.search(value):
        return DROP
    if any(not (c.isalnum() or c in " _-+.,()/%%#&'") for c in value):return DROP
    return value


def sanitize(value,spec,depth=0):
    if depth>12:return DROP
    if value is None:return None
    kind=spec["kind"]
    if kind=="object":
        if type(value) is not dict:return DROP
        out={}
        for name,child in spec["fields"].items():
            if name in value:
                result=sanitize(value[name],child,depth+1)
                if result is not DROP:out[name]=result
        return out
    if kind=="array":
        if type(value) is not list or len(value)>spec.get("max_items",100):return DROP
        out=[]
        for item in value:
            result=sanitize(item,spec["items"],depth+1)
            if result is not DROP:out.append(result)
        return out
    if kind=="id":
        if type(value) is ObjectId:return {"$oid":str(value)}
        if type(value) is str and len(value)<=128:
            return {"reference":hashlib.sha256(value.encode()).hexdigest()[:24]}
        return DROP
    if kind=="number":
        if type(value) in (int,Int64,float) and math.isfinite(value) and abs(value)<=10**15:return value
        if type(value) is Decimal128:
            val=value.to_decimal()
            if val.is_finite() and abs(val)<=10**15:return {"$numberDecimal":str(val)}
        return DROP
    if kind=="boolean":return value if type(value) is bool else DROP
    if kind=="date":
        if type(value) is not datetime:return DROP
        value=value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)
        return {"$date":value.isoformat()}
    if kind=="enum":return value if type(value) is str and value in spec["values"] else DROP
    if kind=="label":return safe_label(value,spec.get("max_length",160))
    if kind=="reference":
        if type(value) is ObjectId:return {"$oid":str(value)}
        if type(value) is not str or not 1<=len(value)<=128:return DROP
        return {"reference":hashlib.sha256(value.encode()).hexdigest()[:24]}
    if kind=="phone":
        if type(value) is not str or not re.fullmatch(r"\+?[0-9 ()-]{7,24}",value):return DROP
        digits=re.sub(r"\D","",value)
        return {"last4":digits[-4:],"reference":hashlib.sha256(digits.encode()).hexdigest()[:24]}
    if kind=="email":
        if type(value) is not str or len(value)>254 or not re.fullmatch(r"[^@\s]+@[A-Za-z0-9.-]{1,80}\.[A-Za-z]{2,24}",value):return DROP
        domain=value.rsplit("@",1)[1].lower()
        if safe_label(domain) is DROP:return DROP
        return {"domain":domain,"reference":hashlib.sha256(value.lower().encode()).hexdigest()[:24]}
    if kind=="last4":return value if type(value) is str and re.fullmatch(r"[0-9]{4}",value) else DROP
    return DROP


def validate_spec(spec,depth=0):
    if not isinstance(spec,dict) or depth>12:raise Denied("EXPLICIT_FIELD_POLICY_REQUIRED")
    kind=spec.get("kind")
    if kind=="object":
        fields=spec.get("fields")
        if not isinstance(fields,dict) or not fields or len(fields)>150:raise Denied("EXPLICIT_FIELD_POLICY_REQUIRED")
        for name,child in fields.items():
            if not isinstance(name,str) or not re.fullmatch(r"[A-Za-z0-9_+\-]{1,128}",name) or SECRET.search(name):
                raise Denied("EXPLICIT_FIELD_POLICY_REQUIRED")
            validate_spec(child,depth+1)
    elif kind=="array":
        if type(spec.get("max_items")) is not int or not 1<=spec["max_items"]<=100:raise Denied("EXPLICIT_FIELD_POLICY_REQUIRED")
        validate_spec(spec.get("items"),depth+1)
    elif kind=="enum":
        if not isinstance(spec.get("values"),list) or not spec["values"] or any(type(x) is not str or len(x)>160 for x in spec["values"]):raise Denied("EXPLICIT_FIELD_POLICY_REQUIRED")
    elif kind=="label":
        if type(spec.get("max_length")) is not int or not 1<=spec["max_length"]<=160:raise Denied("EXPLICIT_FIELD_POLICY_REQUIRED")
    elif kind not in ("id","number","boolean","date","reference","phone","email","last4"):
        raise Denied("EXPLICIT_FIELD_POLICY_REQUIRED")


def leaves(spec,path="",in_array=False):
    if spec["kind"]=="object":
        out={}
        for name,child in spec["fields"].items():out.update(leaves(child,path+"."+name if path else name,in_array))
        return out
    if spec["kind"]=="array":return leaves(spec["items"],path,True)
    return {path:(spec,in_array)}


def query_value(value,spec):
    if value is None:return None
    kind=spec["kind"]
    if kind=="id":
        if type(value) is not str or not re.fullmatch(r"[0-9a-fA-F]{24}",value):raise Denied("QUERY_VALUE_NOT_APPROVED")
        return ObjectId(value)
    if kind=="date":
        if type(value) is not str or len(value)>40:raise Denied("QUERY_VALUE_NOT_APPROVED")
        try:
            parsed=datetime.fromisoformat(value.replace("Z","+00:00"))
            if parsed.tzinfo is None:raise ValueError()
            return parsed.astimezone(timezone.utc)
        except ValueError:raise Denied("QUERY_VALUE_NOT_APPROVED") from None
    result=sanitize(value,spec)
    if result is DROP or type(result) not in (str,int,float,bool):raise Denied("QUERY_VALUE_NOT_APPROVED")
    return result
