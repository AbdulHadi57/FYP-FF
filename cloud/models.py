from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any


class Flow(BaseModel):
    id: int
    captured_at: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: int
    total_packets: int
    flow_duration: float
    verdict: str
    ja4_pred: Optional[str] = "none"
    ttp_predictions: Optional[str] = None
    apt_matches: Optional[str] = None
    confidence: float
    severity: float
    traffic_type: Optional[str] = "other"
    traffic_type_confidence: Optional[float] = 0.0
    summary: str
    features_json: Optional[str] = "{}"
    sni: Optional[str] = None


class FlowDetail(BaseModel):
    id: int
    features: Dict[str, Any]


class Stats(BaseModel):
    total_flows: int
    malicious_flows: int
    avg_severity: float
    top_source: str
    top_attackers: List[dict]
    last_flow_timestamp: Optional[str] = None


class TimelinePoint(BaseModel):
    bucket: str
    flow_count: int
    malicious_count: int


class ModuleStats(BaseModel):
    ja4_diversity: int
    ja4s_diversity: int
    top_ja4: List[dict]
    top_ja4s: List[dict]
    top_ja4h: List[dict]
    top_ja4x: List[dict]
    top_ja4ssh: List[dict]
    top_ja4t: List[dict]
    top_ja4ts: List[dict]
    top_ja4l: List[dict]
    top_ja4d: List[dict]
    ja4_malicious_count: int = 0
    ja4_benign_count: int = 0
    ja4_malicious_flows: List[Dict[str, Any]] = Field(default_factory=list)

    ttp_technique_counts: Dict[str, int] = Field(default_factory=dict)
    ttp_technique_names: Dict[str, str] = Field(default_factory=dict)
    ttp_total_predictions: int = 0
    ttp_top_techniques: List[Dict[str, Any]] = Field(default_factory=list)
    ttp_recent_flows: List[Dict[str, Any]] = Field(default_factory=list)

    apt_actor_count: int = 0
    apt_top_groups: List[Dict[str, Any]] = Field(default_factory=list)
    apt_actor_profiles: List[Dict[str, Any]] = Field(default_factory=list)
    apt_stix_stats: Dict[str, Any] = Field(default_factory=dict)

    module_activity: Dict[str, int] = Field(default_factory=dict)
    threat_status_distribution: Dict[str, int] = Field(default_factory=dict)
    recent_features: Dict[str, List[Dict[str, Any]]] = Field(default_factory=dict)


class ActionableEvent(BaseModel):
    id: str
    flow_id: Optional[int] = None
    timestamp: str
    severity: str
    category: str
    module_source: str
    confidence: Optional[float] = None
    title: str
    message: str
    source_ip: Optional[str] = None
    affected_asset: Optional[str] = None
    action_required: bool = False
    recommended_action: Optional[str] = None
    status: str = "open"
    resolution_note: Optional[str] = None


class ResolutionRequest(BaseModel):
    note: str


class ForensicsStats(BaseModel):
    flag_counts: List[Dict[str, Any]]
    payload_stats: Dict[str, List[int]]
    top_ports: List[Dict[str, Any]]
    top_source_ips: List[Dict[str, Any]]


class IngestModuleResult(BaseModel):
    module: str
    label: str
    confidence: float
    score: float
    rationale: str


class IngestRequest(BaseModel):
    captured_at: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    total_packets: int
    flow_duration: float
    payload: Dict[str, Any]


class IngestResponse(BaseModel):
    flow_id: int
    verdict: str
    modules: List[IngestModuleResult]
    ttp_predictions: Optional[List[Dict[str, Any]]] = None
    severity: float


class TTPStatsResponse(BaseModel):
    total_predictions: int
    unique_techniques: int
    technique_distribution: List[Dict[str, Any]]
    recent_ttp_flows: List[Dict[str, Any]]
    model_loaded: bool


class APTStatsResponse(BaseModel):
    actor_count: int
    top_apt_groups: List[Dict[str, Any]]
    actor_profiles: List[Dict[str, Any]]
    stix_stats: Dict[str, Any]
    window_seconds: int


class NodeRegistration(BaseModel):
    hostname: str
    domain_fqdn: Optional[str] = None
    capabilities: Dict[str, Any] = Field(default_factory=dict)


class AgentRegistrationRequest(NodeRegistration):
    agent_id: Optional[str] = None
    os_type: Optional[str] = None
    os_version: Optional[str] = None
    agent_version: Optional[str] = None
    interfaces: List[str] = Field(default_factory=list)
    ip_addresses: List[str] = Field(default_factory=list)
    dc_hint: Optional[str] = None


class DcRegistrationRequest(NodeRegistration):
    dc_id: Optional[str] = None
    fqdn: Optional[str] = None
    forest_fqdn: Optional[str] = None
    site_name: Optional[str] = None
    os_version: Optional[str] = None
    runner_version: Optional[str] = None


class HeartbeatRequest(BaseModel):
    auth_token: str
    status: str = "online"
    payload: Dict[str, Any] = Field(default_factory=dict)


class CreateActionRequest(BaseModel):
    target_type: str
    target_id: str
    action_type: str
    payload: Dict[str, Any] = Field(default_factory=dict)
    requested_by: str = "system"
    reason: Optional[str] = None
    require_approval: Optional[bool] = None


class ActionStatusUpdateRequest(BaseModel):
    auth_token: str
    status: str
    result: Dict[str, Any] = Field(default_factory=dict)


class ApproveActionRequest(BaseModel):
    approved_by: str
    approved: bool
    note: Optional[str] = None


class RollbackActionRequest(BaseModel):
    requested_by: str
    reason: Optional[str] = None


class ActionJobResponse(BaseModel):
    id: str
    target_type: str
    target_id: str
    action_type: str
    payload: Dict[str, Any] = Field(default_factory=dict)
    status: str
    approval_required: bool = False
    approval_status: str = "not_required"
    rollback_of_action_id: Optional[str] = None
    requested_by: Optional[str] = None
    reason: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


class RegistrationResponse(BaseModel):
    node_id: str
    node_type: str
    auth_token: str
    heartbeat_interval_seconds: int
    websocket_path: str


class NodeSummary(BaseModel):
    id: str
    hostname: str
    status: str
    last_seen: Optional[str] = None
    domain_fqdn: Optional[str] = None
    dc_id: Optional[str] = None
    primary_ip: Optional[str] = None


class ResponseTemplateUpsertRequest(BaseModel):
    name: str
    description: Optional[str] = None
    target_action_type: str
    default_payload: Dict[str, Any] = Field(default_factory=dict)
    require_approval: bool = True
    enabled: bool = True


class ResponseTemplateSummary(BaseModel):
    id: str
    name: str
    description: Optional[str] = None
    target_action_type: str
    default_payload: Dict[str, Any] = Field(default_factory=dict)
    require_approval: bool = True
    enabled: bool = True
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


class TemplateDispatchRequest(BaseModel):
    template_name: str
    agent_id: str
    target_ip: Optional[str] = None
    target_port: Optional[int] = None
    protocol: Optional[str] = None
    payload_overrides: Dict[str, Any] = Field(default_factory=dict)
    requested_by: str
    reason: Optional[str] = None
    require_approval: Optional[bool] = None


class TemplateDispatchResponse(BaseModel):
    template_name: str
    agent_id: str
    resolved_dc_id: str
    action: ActionJobResponse


# Backward-compatible aliases used by older imports/tests.
AgentRegistration = AgentRegistrationRequest
DCRegistration = DcRegistrationRequest
ActionRequest = CreateActionRequest
ActionStatusUpdate = ActionStatusUpdateRequest
ApprovalRequest = ApproveActionRequest
ResponseTemplateRequest = ResponseTemplateUpsertRequest
