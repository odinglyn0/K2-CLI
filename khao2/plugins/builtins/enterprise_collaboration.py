"""Enterprise collaboration plugin for team workspaces and workflow automation."""
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Callable
from khao2.plugins import (
    IntegrationPlugin, PluginMetadata, PluginContext,
    PluginError
)


@dataclass
class Workspace:
    """Represents a team workspace."""
    workspace_id: str
    name: str
    description: str
    owner: str
    members: List[str]
    created_at: float
    settings: Dict[str, Any] = None

    def __post_init__(self):
        if self.settings is None:
            self.settings = {}


@dataclass
class SharedScan:
    """Represents a shared scan result."""
    scan_id: str
    workspace_id: str
    shared_by: str
    shared_at: float
    permissions: List[str]  # ['read', 'write', 'delete']
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


@dataclass
class WorkflowRule:
    """Represents an automation workflow rule."""
    rule_id: str
    name: str
    description: str
    trigger: str  # 'scan_completed', 'anomaly_detected', etc.
    conditions: Dict[str, Any]
    actions: List[Dict[str, Any]]
    enabled: bool = True
    created_at: float = None

    def __post_init__(self):
        if self.created_at is None:
            self.created_at = time.time()


@dataclass
class EnterpriseConfig:
    """Configuration for enterprise features."""
    enable_workspaces: bool = True
    enable_sharing: bool = True
    enable_workflows: bool = True
    enable_audit: bool = True
    max_workspace_members: int = 50
    webhook_timeout: int = 30


class EnterpriseCollaborationPlugin(IntegrationPlugin):
    """Plugin for enterprise collaboration features."""

    def __init__(self):
        self.workspaces: Dict[str, Workspace] = {}
        self.shared_scans: Dict[str, SharedScan] = {}
        self.workflow_rules: Dict[str, WorkflowRule] = {}
        self.config: EnterpriseConfig = EnterpriseConfig()
        self.api_client = None
        self.audit_log = []

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="enterprise_collaboration",
            version="1.0.0",
            description="Team workspaces, sharing, and workflow automation",
            author="Khao2 Team",
            plugin_type="integration",
            entry_point="khao2.plugins.builtins.enterprise_collaboration.EnterpriseCollaborationPlugin",
            config_schema={
                "enable_workspaces": {
                    "type": "boolean",
                    "default": True,
                    "description": "Enable team workspaces"
                },
                "enable_sharing": {
                    "type": "boolean",
                    "default": True,
                    "description": "Enable scan result sharing"
                },
                "enable_workflows": {
                    "type": "boolean",
                    "default": True,
                    "description": "Enable workflow automation"
                },
                "max_workspace_members": {
                    "type": "integer",
                    "default": 50,
                    "description": "Maximum members per workspace"
                }
            }
        )

    def initialize(self, context: PluginContext) -> None:
        """Initialize the enterprise plugin."""
        self.api_client = context.services.get('api_client')

        # Load configuration
        plugin_config = context.config.get('enterprise_collaboration', {})
        self.config = EnterpriseConfig(
            enable_workspaces=plugin_config.get('enable_workspaces', True),
            enable_sharing=plugin_config.get('enable_sharing', True),
            enable_workflows=plugin_config.get('enable_workflows', True),
            enable_audit=plugin_config.get('enable_audit', True),
            max_workspace_members=plugin_config.get('max_workspace_members', 50),
            webhook_timeout=plugin_config.get('webhook_timeout', 30)
        )

        # Load persisted data
        self._load_data()

    def cleanup(self) -> None:
        """Clean up and save data."""
        self._save_data()

    def integrate(self, data: Any, **kwargs) -> Any:
        """Main integration method - handles different operations."""
        operation = kwargs.get('operation', 'unknown')

        if operation == 'create_workspace':
            return self.create_workspace(**kwargs)
        elif operation == 'share_scan':
            return self.share_scan(**kwargs)
        elif operation == 'create_workflow':
            return self.create_workflow_rule(**kwargs)
        elif operation == 'trigger_workflow':
            return self.trigger_workflow(**kwargs)
        elif operation == 'get_audit_log':
            return self.get_audit_log(**kwargs)
        else:
            raise PluginError(f"Unknown operation: {operation}")

    def create_workspace(self, name: str, description: str = "",
                        owner: str = "", **kwargs) -> Workspace:
        """Create a new workspace."""
        if not self.config.enable_workspaces:
            raise PluginError("Workspaces are disabled")

        import uuid
        workspace_id = f"ws_{uuid.uuid4().hex[:8]}"

        workspace = Workspace(
            workspace_id=workspace_id,
            name=name,
            description=description,
            owner=owner or "unknown",
            members=[owner] if owner else [],
            created_at=time.time()
        )

        self.workspaces[workspace_id] = workspace
        self._audit("workspace_created", workspace_id, owner)
        self._save_data()

        return workspace

    def share_scan(self, scan_id: str, workspace_id: str,
                  shared_by: str, permissions: List[str] = None, **kwargs) -> SharedScan:
        """Share a scan result with a workspace."""
        if not self.config.enable_sharing:
            raise PluginError("Sharing is disabled")

        if permissions is None:
            permissions = ['read']

        if workspace_id not in self.workspaces:
            raise PluginError(f"Workspace {workspace_id} not found")

        workspace = self.workspaces[workspace_id]
        if shared_by not in workspace.members:
            raise PluginError(f"User {shared_by} is not a member of workspace {workspace_id}")

        shared_scan = SharedScan(
            scan_id=scan_id,
            workspace_id=workspace_id,
            shared_by=shared_by,
            shared_at=time.time(),
            permissions=permissions
        )

        self.shared_scans[scan_id] = shared_scan
        self._audit("scan_shared", scan_id, shared_by, workspace_id)
        self._save_data()

        return shared_scan

    def create_workflow_rule(self, name: str, description: str,
                           trigger: str, conditions: Dict[str, Any],
                           actions: List[Dict[str, Any]], **kwargs) -> WorkflowRule:
        """Create a workflow automation rule."""
        if not self.config.enable_workflows:
            raise PluginError("Workflows are disabled")

        import uuid
        rule_id = f"rule_{uuid.uuid4().hex[:8]}"

        rule = WorkflowRule(
            rule_id=rule_id,
            name=name,
            description=description,
            trigger=trigger,
            conditions=conditions,
            actions=actions
        )

        self.workflow_rules[rule_id] = rule
        self._audit("workflow_created", rule_id)
        self._save_data()

        return rule

    def trigger_workflow(self, trigger: str, context: Dict[str, Any], **kwargs) -> List[Dict[str, Any]]:
        """Trigger workflow rules for a given event."""
        if not self.config.enable_workflows:
            return []

        executed_actions = []

        for rule in self.workflow_rules.values():
            if not rule.enabled or rule.trigger != trigger:
                continue

            if self._evaluate_conditions(rule.conditions, context):
                for action in rule.actions:
                    try:
                        result = self._execute_action(action, context)
                        executed_actions.append({
                            "rule_id": rule.rule_id,
                            "action": action,
                            "result": result
                        })
                    except Exception as e:
                        executed_actions.append({
                            "rule_id": rule.rule_id,
                            "action": action,
                            "error": str(e)
                        })

        return executed_actions

    def get_audit_log(self, limit: int = 50, **kwargs) -> List[Dict[str, Any]]:
        """Get audit log entries."""
        if not self.config.enable_audit:
            raise PluginError("Audit logging is disabled")

        return self.audit_log[-limit:] if limit > 0 else self.audit_log

    def _evaluate_conditions(self, conditions: Dict[str, Any], context: Dict[str, Any]) -> bool:
        """Evaluate workflow conditions against context."""
        # Simple condition evaluation - can be extended
        for key, expected_value in conditions.items():
            if key not in context:
                return False
            if context[key] != expected_value:
                return False
        return True

    def _execute_action(self, action: Dict[str, Any], context: Dict[str, Any]) -> Any:
        """Execute a workflow action."""
        action_type = action.get('type')

        if action_type == 'webhook':
            return self._execute_webhook(action, context)
        elif action_type == 'notification':
            return self._execute_notification(action, context)
        elif action_type == 'scan':
            return self._execute_scan(action, context)
        else:
            raise PluginError(f"Unknown action type: {action_type}")

    def _execute_webhook(self, action: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a webhook action."""
        import requests

        url = action.get('url')
        method = action.get('method', 'POST')
        headers = action.get('headers', {})
        payload = action.get('payload', context)

        try:
            response = requests.request(
                method=method,
                url=url,
                headers=headers,
                json=payload,
                timeout=self.config.webhook_timeout
            )
            return {
                "status_code": response.status_code,
                "response": response.text[:500]  # Truncate for logging
            }
        except Exception as e:
            raise PluginError(f"Webhook failed: {e}") from e

    def _execute_notification(self, action: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a notification action."""
        # Placeholder for notification system
        message = action.get('message', 'Workflow triggered')
        channel = action.get('channel', 'default')

        # In a real implementation, this would send to Slack, email, etc.
        return {
            "message": message,
            "channel": channel,
            "sent": True
        }

    def _execute_scan(self, action: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a scan action."""
        # Placeholder for triggering additional scans
        target = action.get('target')
        return {
            "target": target,
            "scan_triggered": True
        }

    def _audit(self, action: str, resource_id: str, user: str = "system", details: str = "") -> None:
        """Add an entry to the audit log."""
        if not self.config.enable_audit:
            return

        entry = {
            "timestamp": time.time(),
            "action": action,
            "resource_id": resource_id,
            "user": user,
            "details": details
        }
        self.audit_log.append(entry)

    def _load_data(self) -> None:
        """Load persisted data from disk."""
        data_dir = Path.home() / ".khao2" / "enterprise"
        data_dir.mkdir(parents=True, exist_ok=True)

        # Load workspaces
        ws_file = data_dir / "workspaces.json"
        if ws_file.exists():
            try:
                with open(ws_file, 'r') as f:
                    ws_data = json.load(f)
                    for ws_dict in ws_data.values():
                        ws = Workspace(**ws_dict)
                        self.workspaces[ws.workspace_id] = ws
            except (json.JSONDecodeError, TypeError, KeyError) as e:
                import logging
                logging.warning(f"Failed to load workspaces: {e}")

        # Load shared scans
        scans_file = data_dir / "shared_scans.json"
        if scans_file.exists():
            with open(scans_file, 'r') as f:
                scans_data = json.load(f)
                for scan_dict in scans_data.values():
                    scan = SharedScan(**scan_dict)
                    self.shared_scans[scan.scan_id] = scan

        # Load workflow rules
        rules_file = data_dir / "workflow_rules.json"
        if rules_file.exists():
            with open(rules_file, 'r') as f:
                rules_data = json.load(f)
                for rule_dict in rules_data.values():
                    rule = WorkflowRule(**rule_dict)
                    self.workflow_rules[rule.rule_id] = rule

        # Load audit log
        audit_file = data_dir / "audit_log.json"
        if audit_file.exists():
            with open(audit_file, 'r') as f:
                self.audit_log = json.load(f)

    def _save_data(self) -> None:
        """Save data to disk."""
        data_dir = Path.home() / ".khao2" / "enterprise"
        data_dir.mkdir(parents=True, exist_ok=True)

        # Save workspaces
        ws_file = data_dir / "workspaces.json"
        with open(ws_file, 'w') as f:
            json.dump(
                {ws_id: {
                    "workspace_id": ws.workspace_id,
                    "name": ws.name,
                    "description": ws.description,
                    "owner": ws.owner,
                    "members": ws.members,
                    "created_at": ws.created_at,
                    "settings": ws.settings
                } for ws_id, ws in self.workspaces.items()},
                f, indent=2
            )

        # Save shared scans
        scans_file = data_dir / "shared_scans.json"
        with open(scans_file, 'w') as f:
            json.dump(
                {scan_id: {
                    "scan_id": scan.scan_id,
                    "workspace_id": scan.workspace_id,
                    "shared_by": scan.shared_by,
                    "shared_at": scan.shared_at,
                    "permissions": scan.permissions,
                    "metadata": scan.metadata
                } for scan_id, scan in self.shared_scans.items()},
                f, indent=2
            )

        # Save workflow rules
        rules_file = data_dir / "workflow_rules.json"
        with open(rules_file, 'w') as f:
            json.dump(
                {rule_id: {
                    "rule_id": rule.rule_id,
                    "name": rule.name,
                    "description": rule.description,
                    "trigger": rule.trigger,
                    "conditions": rule.conditions,
                    "actions": rule.actions,
                    "enabled": rule.enabled,
                    "created_at": rule.created_at
                } for rule_id, rule in self.workflow_rules.items()},
                f, indent=2
            )

        # Save audit log
        audit_file = data_dir / "audit_log.json"
        with open(audit_file, 'w') as f:
            json.dump(self.audit_log, f, indent=2)


# Plugin metadata for discovery
PLUGIN_METADATA = EnterpriseCollaborationPlugin().metadata