"""
Mirror of the main application's response/input schema.

These models must stay identical to the ones in the main bot repo's
`schema.py`, so that a result produced here passes the main app's
`DetectionResult(**data)` unchanged. The wrapper ships in its own
container and can't import the main repo, hence the copy.

If the main schema changes, update this file to match and re-run the
tests (tests/test_schema_contract.py checks the shape).

Only the models the wrapper uses are mirrored: DetectionResult/Evidence
(what a detector returns) and AddressContext and its parts (what an
"address_with_context" detector receives).
"""

from typing import List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

Label = Literal["scam", "not_scam", "insufficient_evidence"]
RequiredInputType = Literal["address", "address_with_context"]


class Evidence(BaseModel):
    description: str
    weight: float


class DetectionResult(BaseModel):
    label: Label
    risk_type: Optional[str] = None
    confidence: float
    evidence: List[Evidence] = Field(default_factory=list)
    explanation: str
    reasoning_trace: Optional[str] = None


class ContractInfo(BaseModel):
    is_contract: bool
    bytecode: Optional[str] = None
    abi: List[dict] = Field(default_factory=list)
    verified_source: bool = False
    creation_tx: Optional[str] = None
    creator: Optional[str] = None


class TxRecord(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    hash: str
    from_: str = Field(alias="from")
    to: str
    value: str
    timestamp: str
    method: Optional[str] = None


class TokenBalance(BaseModel):
    symbol: str
    contract_address: str
    balance: str
    decimals: int


class LiquidityEvent(BaseModel):
    type: str
    timestamp: str
    amount_usd: float


class LiquidityPool(BaseModel):
    pool_address: str
    dex: str
    token_pair: List[str]
    liquidity_usd: float
    liquidity_events: List[LiquidityEvent] = Field(default_factory=list)


class AddressContext(BaseModel):
    chain: str
    address: str
    queried_at: str
    contract: Optional[ContractInfo] = None
    tx_history: List[TxRecord] = Field(default_factory=list)
    tokens: List[TokenBalance] = Field(default_factory=list)
    liquidity: List[LiquidityPool] = Field(default_factory=list)
    fetcher_provenance: dict = Field(default_factory=dict)
