# agent-federation-network

Multi-agent federation protocol for cross-organizational agent collaboration with identity verification.

## Features

- **Identity Management**: Cryptographic identity verification for AI agents with attestation chains
- **Federation Nodes**: Register and manage federation nodes with heartbeat monitoring and trust relationships
- **Trust Scoring**: Organization-level trust assessment with capability-based access control
- **Cross-Organization Tasks**: Secure task delegation across organizational boundaries
- **Message Routing**: Priority-based message queue with dead letter handling and subscription patterns
- **Audit Logging**: Immutable audit trail for all federation operations

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                   Federation Network                        │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │  Org A      │  │  Org B      │  │  Org C      │         │
│  │  ┌────────┐ │  │  ┌────────┐ │  │  ┌────────┐ │         │
│  │  │ Agent  │ │  │  │ Agent  │ │  │  │ Agent  │ │         │
│  │  └────────┘ │  │  └────────┘ │  │  └────────┘ │         │
│  │  ┌────────┐ │  │  ┌────────┐ │  │  ┌────────┐ │         │
│  │  │ Node   │ │  │  │ Node   │ │  │  │ Node   │ │         │
│  │  └────────┘ │  │  └────────┘ │  │  └────────┘ │         │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
│                                                              │
│  ┌─────────────────────────────────────────────────────┐    │
│  │            Trust Manager                            │    │
│  │  - Organization trust levels                        │    │
│  │  - Cross-org task tracking                          │    │
│  │  - Risk scoring                                     │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

## Installation

```bash
bun install
```

## Usage

### Register an Agent

```bash
bun run src/index.ts register-agent \
  --organization-id org-1 \
  --agent-id agent-001 \
  --metadata '{"capabilities":["text-analysis","data-processing"]}'
```

### Issue an Attestation

```bash
bun run src/index.ts issue-attestation \
  --agent-id agent-001 \
  --claims '{"role":"processor","clearance":"level-2"}' \
  --validity-ms 86400000
```

### Verify Attestation Chain

```bash
bun run src/index.ts verify-chain --agent-id agent-001
```

### Register a Federation Node

```bash
bun run src/index.ts register-node \
  --node-id node-001 \
  --endpoint https://node-001.example.com \
  --organization-id org-1
```

### Trust an Agent

```bash
bun run src/index.ts trust-agent \
  --node-id node-001 \
  --agent-id agent-001
```

### Set Organization Trust Level

```bash
bun run src/index.ts set-trust \
  --organization-id org-2 \
  --level partial \
  --capabilities text-analysis,data-processing \
  --restrictions no-external-data-sharing
```

### Create a Cross-Organization Task

```bash
bun run src/index.ts create-task \
  --requesting-agent agent-001 \
  --target-org org-2 \
  --task-type data-analysis \
  --priority 8 \
  --ttl-ms 600000
```

### Send a Message

```bash
bun run src/index.ts send-message \
  --type task_request \
  --from agent-001 \
  --to-org org-2 \
  --payload '{"task":"analysis","data":"sample"}' \
  --priority 7
```

### Receive Messages

```bash
bun run src/index.ts receive-message
```

### View Statistics

```bash
bun run src/index.ts stats
```

## Core Components

### IdentityManager

Handles cryptographic identity management:
- Key pair generation (Ed25519-style)
- Agent registration with public key storage
- Signature creation and verification
- Attestation chain issuance and verification

### FederationNodeManager

Manages federation node registration and health:
- Node registration with endpoint and organization mapping
- Heartbeat tracking for liveness detection
- Agent trust relationships per node
- Automatic inactive node pruning

### TrustManager

Provides organization-level trust assessment:
- Trust level configuration (none/partial/full)
- Capability-based access control
- Cross-organization task tracking
- Risk scoring based on historical performance

### MessageRouter

Implements priority-based message routing:
- 10 priority levels (1 = highest)
- TTL-based message expiration
- Dead letter queue for failed messages
- Topic-based subscriptions

## API Reference

### Identity Commands

| Command | Description |
|---------|-------------|
| `register-agent` | Register a new agent with cryptographic identity |
| `issue-attestation` | Issue a signed attestation with claims |
| `verify-chain` | Verify an agent's attestation chain integrity |
| `list-agents` | List all registered agents |

### Node Commands

| Command | Description |
|---------|-------------|
| `register-node` | Register a new federation node |
| `trust-agent` | Add an agent to node's trusted list |

### Trust Commands

| Command | Description |
|---------|-------------|
| `set-trust` | Set organization trust level and capabilities |
| `create-task` | Create a cross-organization task |
| `get-task` | Retrieve task status and results |

### Message Commands

| Command | Description |
|---------|-------------|
| `send-message` | Enqueue a federation message |
| `receive-message` | Dequeue next message by priority |

## Data Storage

All data is stored locally in `./data/`:
- `identities.json` - Agent identities and public keys
- `nodes.json` - Federation node registry
- `trust-levels.json` - Organization trust configurations
- `message-queue.json` - Pending messages and dead letter queue
- `audit.log` - Immutable audit trail

## Security

- All agent identities use cryptographic key pairs
- Attestation chains provide tamper-evident history
- Organization trust levels restrict cross-org access
- All federation actions are audit logged

## License

MIT License