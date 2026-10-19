"""Single-worker durable quotas around encrypted OAuth storage; no key listing required."""
import asyncio
import json
import time

class QuotaStore:
    LIMITS={"mcp-oauth-proxy-clients":64,"mcp-oauth-transactions":128,
            "mcp-authorization-codes":128,"mcp-jti-mappings":512,
            "mcp-refresh-tokens":128,"mcp-upstream-tokens":128}
    INDEX="mongodb-read-quota-index"
    def __init__(self,store):self.store=store;self.lock=asyncio.Lock()
    def __getattr__(self,name):return getattr(self.store,name)
    async def put(self,key,value,*,collection=None,ttl=None):
        if not isinstance(key,str) or len(key)>512 or collection not in self.LIMITS:
            raise ValueError("OAUTH_STATE_KEY_REJECTED")
        if len(json.dumps(value,ensure_ascii=True,allow_nan=False).encode())>65536:
            raise ValueError("OAUTH_STATE_TOO_LARGE")
        limit=self.LIMITS[collection]
        lifetime=30*86400 if collection in ("mcp-oauth-proxy-clients","mcp-jti-mappings","mcp-refresh-tokens","mcp-upstream-tokens") else 600
        ttl=lifetime if ttl is None else min(float(ttl),lifetime)
        async with self.lock:
            index=await self.store.get(collection,collection=self.INDEX) or {"entries":{}}
            entries=index["entries"]
            for candidate,expiry in list(entries.items()):
                if expiry<=time.time():
                    await self.store.delete(candidate,collection=collection)
                    del entries[candidate]
            if ttl<=0:
                await self.store.delete(key,collection=collection);entries.pop(key,None)
            else:
                if key not in entries and len(entries)>=limit:raise ValueError("OAUTH_STATE_CAPACITY_REACHED")
                entries[key]=time.time()+ttl
            if len(json.dumps(index).encode())>65536:raise ValueError("OAUTH_STATE_CAPACITY_REACHED")
            # Reserve quota durably before writing a value; interrupted writes fail closed.
            await self.store.put(collection,index,collection=self.INDEX)
            if ttl>0:await self.store.put(key,value,collection=collection,ttl=ttl)
    async def delete(self,key,*,collection=None):
        async with self.lock:
            result=await self.store.delete(key,collection=collection)
            index=await self.store.get(collection,collection=self.INDEX)
            if index and key in index["entries"]:
                del index["entries"][key]
                await self.store.put(collection,index,collection=self.INDEX)
            return result
