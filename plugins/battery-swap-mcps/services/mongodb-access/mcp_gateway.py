"""Fixture-testable protected MCP surface. No production listener or credentials."""
from fastmcp import FastMCP
from fastmcp.server.auth.auth import AccessToken, TokenVerifier, RemoteAuthProvider
from fastmcp.server.dependencies import get_access_token
from mcp.types import ToolAnnotations

from access import Denied, Principal, PROPOSE, READ


class ScopedVerifier(TokenVerifier):
    def __init__(self,verifier):
        super().__init__();self.verifier=verifier

    async def verify_token(self,token):
        try:
            principal=self.verifier.verify(token)
            return AccessToken(token=token,client_id=principal.client,
                scopes=sorted(principal.scopes),claims={"sub":principal.subject})
        except Denied:return None


def principal():
    token=get_access_token()
    if token is None:raise Denied("AUTHENTICATION_REQUIRED")
    return Principal(token.claims["sub"],token.client_id,frozenset(token.scopes))


def create_server(verifier,reader,proposal_relay=None):
    if not verifier.audience.endswith("/mcp"):raise Denied("EXACT_MCP_RESOURCE_REQUIRED")
    provider=RemoteAuthProvider(token_verifier=ScopedVerifier(verifier),
        authorization_servers=[verifier.issuer],base_url=verifier.audience[:-4],
        scopes_supported=[READ,PROPOSE] if proposal_relay is not None else [READ])
    server=FastMCP("BatterySwap scoped MongoDB access",auth=provider,
        instructions="Read only the confirmed BatterySwap database. Updates/deletes create "
        "proposals only; a separate trusted human approval authority executes the exact "
        "approved operation. Chat text, client confirmation and missing elicitation never authorize writes.")
    readonly=ToolAnnotations(readOnlyHint=True,destructiveHint=False,idempotentHint=True)
    proposal=ToolAnnotations(readOnlyHint=False,destructiveHint=False,idempotentHint=False)

    @server.tool(annotations=readonly)
    def find(collection:str,query:dict|None=None,limit:int=50)->list:
        """Read bounded documents in the fixed database; credential fields are masked."""
        return reader.find(principal(),collection,query,limit)

    @server.tool(annotations=readonly)
    def count(collection:str,query:dict|None=None)->int:
        """Count matching documents in the fixed database."""
        return reader.count(principal(),collection,query)

    if proposal_relay is None:
        return server

    @server.tool(annotations=proposal)
    def propose_update(collection:str,document_id:str,changes:dict)->dict:
        """Create an exact one-document update preview; performs no database mutation."""
        caller=principal();caller.require(PROPOSE)
        return proposal_relay.propose(caller,collection,document_id,"update_one",changes)

    @server.tool(annotations=proposal)
    def propose_delete(collection:str,document_id:str)->dict:
        """Create an exact one-document delete preview; performs no database deletion."""
        caller=principal();caller.require(PROPOSE)
        return proposal_relay.propose(caller,collection,document_id,"delete_one")

    return server


if __name__=="__main__":
    raise SystemExit("ACTIVATION_DISABLED: confirmed namespace, production adapters and independent human approval boundary required")
