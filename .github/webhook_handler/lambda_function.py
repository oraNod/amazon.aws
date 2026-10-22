"""
GitHub Webhook to Slack notification handler for AWS Lambda.

Receives workflow_run events from GitHub, validates signature,
filters for certification.yml failures, and posts to Slack.
"""

import hashlib
import hmac
import json
import os
import urllib.error
import urllib.request
from typing import Any


class SlackNotificationError(Exception):
    """Raised when posting to Slack webhook fails."""


def verify_signature(payload_body: bytes, signature_header: str, secret: str) -> bool:
    """Verify GitHub webhook signature."""
    if not signature_header:
        return False

    hash_object = hmac.new(secret.encode("utf-8"), msg=payload_body, digestmod=hashlib.sha256)
    expected_signature = "sha256=" + hash_object.hexdigest()

    return hmac.compare_digest(expected_signature, signature_header)


def post_to_slack(webhook_url: str, message: dict[str, Any]) -> None:
    """Post message to Slack incoming webhook."""
    req = urllib.request.Request(
        webhook_url, data=json.dumps(message).encode("utf-8"), headers={"Content-Type": "application/json"}
    )

    with urllib.request.urlopen(req) as response:
        if response.status != 200:
            raise SlackNotificationError(f"Slack returned status {response.status}")


def format_slack_message(workflow_run: dict[str, Any], repository: dict[str, Any]) -> dict[str, Any]:
    """Format a rich Slack message for workflow failure."""
    workflow_name = workflow_run.get("name", "Unknown")
    conclusion = workflow_run.get("conclusion", "unknown")
    html_url = workflow_run.get("html_url", "")
    run_number = workflow_run.get("run_number", "N/A")
    head_branch = workflow_run.get("head_branch", "unknown")
    repo_name = repository.get("full_name", "unknown")

    return {
        "blocks": [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": f"❌ Workflow Failed: {workflow_name}", "emoji": True},
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Repository:*\n{repo_name}"},
                    {"type": "mrkdwn", "text": f"*Branch:*\n{head_branch}"},
                    {"type": "mrkdwn", "text": f"*Run Number:*\n#{run_number}"},
                    {"type": "mrkdwn", "text": f"*Conclusion:*\n{conclusion}"},
                ],
            },
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "View Workflow Run", "emoji": True},
                        "url": html_url,
                        "style": "danger",
                    }
                ],
            },
        ]
    }


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """
    AWS Lambda handler for GitHub webhooks.

    Environment variables required:
    - GITHUB_WEBHOOK_SECRET: Secret for validating GitHub webhook signatures
    - SLACK_WEBHOOK_URL: Slack incoming webhook URL
    - WORKFLOW_NAME: Name of workflow to monitor (default: "Certification")
    """
    try:
        # Get configuration from environment
        github_secret = os.environ.get("GITHUB_WEBHOOK_SECRET")
        slack_webhook_url = os.environ.get("SLACK_WEBHOOK_URL")
        target_workflow = os.environ.get("WORKFLOW_NAME", "Certification")

        if not github_secret or not slack_webhook_url:
            return {"statusCode": 500, "body": json.dumps({"error": "Missing required environment variables"})}

        # Verify webhook signature
        signature_header = event.get("headers", {}).get("x-hub-signature-256", "")
        body = event.get("body", "")

        if isinstance(body, str):
            body_bytes = body.encode("utf-8")
        else:
            body_bytes = body

        if not verify_signature(body_bytes, signature_header, github_secret):
            return {"statusCode": 401, "body": json.dumps({"error": "Invalid signature"})}

        # Parse webhook payload
        payload = json.loads(body) if isinstance(body, str) else body

        # Check if this is a workflow_run event
        event_type = event.get("headers", {}).get("x-github-event", "")
        if event_type != "workflow_run":
            return {"statusCode": 200, "body": json.dumps({"message": "Not a workflow_run event, ignoring"})}

        # Extract workflow run details
        workflow_run = payload.get("workflow_run", {})
        workflow_name = workflow_run.get("name", "")
        conclusion = workflow_run.get("conclusion", "")

        # Filter: only process failures for target workflow
        if workflow_name != target_workflow:
            return {"statusCode": 200, "body": json.dumps({"message": f"Not {target_workflow} workflow, ignoring"})}

        if conclusion != "failure":
            return {"statusCode": 200, "body": json.dumps({"message": "Workflow did not fail, ignoring"})}

        # Send notification to Slack
        repository = payload.get("repository", {})
        slack_message = format_slack_message(workflow_run, repository)
        post_to_slack(slack_webhook_url, slack_message)

        return {"statusCode": 200, "body": json.dumps({"message": "Notification sent to Slack"})}

    except (json.JSONDecodeError, urllib.error.URLError, SlackNotificationError, KeyError, ValueError) as e:
        print(f"Error processing webhook: {e!s}")
        return {"statusCode": 500, "body": json.dumps({"error": str(e)})}
