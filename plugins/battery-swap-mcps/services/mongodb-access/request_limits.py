import asyncio
from starlette.responses import JSONResponse

class RequestLimits:
    def __init__(self, app):
        self.app = app
        self.slots = asyncio.Semaphore(16)

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope.get("path") == "/health":
            return await self.app(scope, receive, send)
        acquired = False
        try:
            try:
                await asyncio.wait_for(self.slots.acquire(), 0.05)
                acquired = True
                chunks = []
                size = 0
                async def read():
                    nonlocal size
                    while True:
                        message = await receive()
                        if message["type"] == "http.disconnect":
                            raise ValueError()
                        size += len(message.get("body", b""))
                        if size > 65536:
                            raise ValueError()
                        chunks.append(message)
                        if not message.get("more_body", False):
                            break
                await asyncio.wait_for(read(), 10)
            except asyncio.TimeoutError:
                return await JSONResponse({"error": "temporarily_unavailable"}, status_code=503)(scope, receive, send)
            except ValueError:
                return await JSONResponse({"error": "request_rejected"}, status_code=413)(scope, receive, send)
            async def bounded_receive():
                return chunks.pop(0) if chunks else await receive()
            await self.app(scope, bounded_receive, send)
        finally:
            if acquired:
                self.slots.release()
