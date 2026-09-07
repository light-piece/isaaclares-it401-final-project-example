from dataclasses import dataclass


@dataclass(frozen=True)
class ApprovalRecord:
    area: str
    status: str

    @classmethod
    def from_dict(cls, values):
        return cls(**values)


@dataclass(frozen=True)
class ITChange:
    title: str
    change_type: str
    risk_level: str
    affected_system: str
    scheduled_window: str
    summary: str
    risk_signals: tuple[str, ...]
    mitigation: str
    rollback_plan: str
    change_owner: str
    change_ticket: str
    review_status: str
    approval_records: tuple[ApprovalRecord, ...]
    audit_trail: tuple[str, ...]

    @classmethod
    def from_dict(cls, values):
        return cls(
            **{
                **values,
                "risk_signals": tuple(values["risk_signals"]),
                "approval_records": tuple(
                    ApprovalRecord.from_dict(record)
                    for record in values["approval_records"]
                ),
                "audit_trail": tuple(values["audit_trail"]),
            }
        )
