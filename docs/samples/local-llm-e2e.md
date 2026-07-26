# Local LLM contract fixture — E2E sample

Date: 2026-07-25  
Target: `http://127.0.0.1:4010/v1/chat`  
Scope: loopback only  
Suite: `local-benign-canary`  
Content: operator-reviewed benign canary  

The integration flow creates an explicit loopback scope, sends one approved
probe through the shared taxonomy runner, receives the fixture's fixed canary
response, classifies the operator-defined indicator as `failed`, and records
start/completion events without probe or response content.

```json
{
  "suite": "local-benign-canary",
  "target": "http://127.0.0.1:4010/v1/chat",
  "target_mode": "black-box",
  "dry_run": false,
  "results": [
    {
      "id": "operator-canary-1",
      "category_id": "PIT-I-16",
      "delivery": "direct",
      "status": "failed",
      "detail": "operator-defined failure indicator matched",
      "http_status": 200
    }
  ]
}
```

The result means only that this deliberately weak fixture returned the chosen
canary. It is regression evidence for the guarded transport and classifier, not
proof about a real model.
