import { describe, test, expect, beforeEach } from "bun:test";
import { IdentityManager, FederationNodeManager, TrustManager, MessageRouter } from "../src/index";

describe("IdentityManager", () => {
  const dataDir = `/tmp/federation-identity-${Date.now()}-${Math.random().toString(36).slice(2)}`;
  let identityManager: IdentityManager;

  beforeEach(() => {
    identityManager = new IdentityManager(dataDir);
  });

  test("generates key pairs", () => {
    const { publicKey, privateKey } = identityManager.generateKeyPair();
    expect(publicKey).toHaveLength(64);
    expect(privateKey).toHaveLength(64);
  });

  test("registers and retrieves agent", () => {
    const id = `agent-${Date.now()}-${Math.random().toString(36).slice(2)}`;
    const identity = identityManager.registerAgent("org-1", id, { role: "worker" });
    expect(identity.id).toBe(id);
    expect(identity.organizationId).toBe("org-1");
    expect(identity.trustScore).toBe(1.0);
    expect(identity.metadata.role).toBe("worker");
  });

  test("throws on duplicate registration", () => {
    const id = `agent-dup-${Date.now()}`;
    identityManager.registerAgent("org-1", id);
    expect(() => identityManager.registerAgent("org-1", id)).toThrow();
  });

  test("verifies agent signature", () => {
    const id = `agent-sig-${Date.now()}`;
    identityManager.registerAgent("org-1", id);
    const data = { action: "process", input: "test" };
    const signature = identityManager.signData(id, data);
    expect(identityManager.verifySignature(id, data, signature)).toBe(true);
  });

  test("rejects invalid signature", () => {
    const id = `agent-invalid-${Date.now()}`;
    identityManager.registerAgent("org-1", id);
    const data = { action: "process" };
    expect(identityManager.verifySignature(id, data, "invalid")).toBe(false);
  });

  test("issues and verifies attestation", () => {
    const id = `agent-attest-${Date.now()}`;
    identityManager.registerAgent("org-1", id);
    const attestation = identityManager.issueAttestation(id, { role: "admin", clearance: 3 });
    expect(attestation.id).toHaveLength(32);
    expect(attestation.agentId).toBe(id);
    expect(attestation.claims.role).toBe("admin");
  });

  test("verifies attestation chain", () => {
    const id = `agent-chain-${Date.now()}`;
    identityManager.registerAgent("org-1", id);
    identityManager.issueAttestation(id, { step: 1 });
    identityManager.issueAttestation(id, { step: 2 });
    identityManager.issueAttestation(id, { step: 3 });
    const result = identityManager.verifyAttestationChain(id);
    expect(result.valid).toBe(true);
  });

  test("detects broken attestation chain", () => {
    const id = `agent-broken-${Date.now()}`;
    identityManager.registerAgent("org-1", id);
    identityManager.issueAttestation(id, { step: 1 });
    identityManager.issueAttestation(id, { step: 2 });
    const attestations = (identityManager as any).attestations.get(id);
    attestations[0].signature = "corrupted";
    const result = identityManager.verifyAttestationChain(id);
    expect(result.valid).toBe(false);
    expect(result.brokenAt).toBe(0);
  });

  test("lists agents by organization", () => {
    identityManager.registerAgent("org-1", `a1-${Date.now()}`);
    identityManager.registerAgent("org-1", `a2-${Date.now()}`);
    identityManager.registerAgent("org-2", `a3-${Date.now()}`);
    const org1Agents = identityManager.listAgents("org-1");
    expect(org1Agents).toHaveLength(2);
    const allAgents = identityManager.listAgents();
    expect(allAgents).toHaveLength(3);
  });

  test("updates trust score", () => {
    const id = `agent-trust-${Date.now()}`;
    identityManager.registerAgent("org-1", id);
    expect(identityManager.getAgent(id)!.trustScore).toBe(1.0);
    identityManager.updateTrustScore(id, -0.2);
    expect(identityManager.getAgent(id)!.trustScore).toBe(0.8);
    identityManager.updateTrustScore(id, 0.5);
    expect(identityManager.getAgent(id)!.trustScore).toBe(1.0);
  });
});

describe("FederationNodeManager", () => {
  const dataDir = `/tmp/federation-nodes-${Date.now()}-${Math.random().toString(36).slice(2)}`;
  let nodeManager: FederationNodeManager;

  beforeEach(() => {
    nodeManager = new FederationNodeManager(dataDir);
  });

  test("registers and retrieves node", () => {
    const id = `node-${Date.now()}-${Math.random().toString(36).slice(2)}`;
    const node = nodeManager.registerNode({
      id,
      endpoint: "https://node.example.com",
      organizationId: "org-1",
    });
    expect(node.id).toBe(id);
    expect(node.isActive).toBe(true);
    expect(node.trustedAgents.size).toBe(0);
  });

  test("updates heartbeat", () => {
    const id = `node-hb-${Date.now()}`;
    nodeManager.registerNode({ id, endpoint: "https://node.example.com", organizationId: "org-1" });
    const before = nodeManager.getNode(id)!.lastHeartbeat;
    nodeManager.updateHeartbeat(id);
    expect(nodeManager.getNode(id)!.lastHeartbeat).toBeGreaterThanOrEqual(before);
  });

  test("marks node inactive", () => {
    const id = `node-inactive-${Date.now()}`;
    nodeManager.registerNode({ id, endpoint: "https://node.example.com", organizationId: "org-1" });
    nodeManager.markNodeInactive(id);
    expect(nodeManager.getNode(id)!.isActive).toBe(false);
  });

  test("trusts and revokes agent trust", () => {
    const nodeId = `node-trust-${Date.now()}`;
    const agentId = `agent-${Date.now()}`;
    nodeManager.registerNode({ id: nodeId, endpoint: "https://node.example.com", organizationId: "org-1" });
    nodeManager.trustAgent(nodeId, agentId);
    expect(nodeManager.isAgentTrusted(nodeId, agentId)).toBe(true);
    nodeManager.revokeAgentTrust(nodeId, agentId);
    expect(nodeManager.isAgentTrusted(nodeId, agentId)).toBe(false);
  });

  test("prunes inactive nodes", () => {
    const id = `node-prune-${Date.now()}`;
    nodeManager.registerNode({ id, endpoint: "https://node.example.com", organizationId: "org-1" });
    const node = nodeManager.getNode(id)!;
    node.lastHeartbeat = Date.now() - 600000;
    const pruned = nodeManager.pruneInactiveNodes(300000);
    expect(pruned).toBe(1);
    expect(nodeManager.getNode(id)!.isActive).toBe(false);
  });

  test("gets active nodes", () => {
    const id1 = `node-active1-${Date.now()}`;
    const id2 = `node-active2-${Date.now()}`;
    nodeManager.registerNode({ id: id1, endpoint: "https://node1.example.com", organizationId: "org-1" });
    nodeManager.registerNode({ id: id2, endpoint: "https://node2.example.com", organizationId: "org-2" });
    nodeManager.markNodeInactive(id1);
    const activeNodes = nodeManager.getActiveNodes();
    expect(activeNodes).toHaveLength(1);
    expect(activeNodes[0].id).toBe(id2);
  });
});

describe("TrustManager", () => {
  const dataDir = `/tmp/federation-trust-${Date.now()}-${Math.random().toString(36).slice(2)}`;
  const auditLog = `/tmp/audit-${Date.now()}.log`;
  let trustManager: TrustManager;

  beforeEach(() => {
    trustManager = new TrustManager(dataDir, auditLog);
  });

  test("sets organization trust level", () => {
    trustManager.setOrganizationTrust("org-1", "full", ["analysis", "processing"], []);
    const trust = trustManager.getOrganizationTrust("org-1");
    expect(trust?.trustLevel).toBe("full");
    expect(trust?.allowedCapabilities).toEqual(["analysis", "processing"]);
  });

  test("checks capability access - full trust", () => {
    trustManager.setOrganizationTrust("org-1", "full", [], []);
    expect(trustManager.canAccessCapability("org-1", "any-capability")).toBe(true);
  });

  test("checks capability access - partial trust", () => {
    trustManager.setOrganizationTrust("org-1", "partial", ["analysis"], []);
    expect(trustManager.canAccessCapability("org-1", "analysis")).toBe(true);
    expect(trustManager.canAccessCapability("org-1", "restricted")).toBe(false);
  });

  test("checks capability access - no trust", () => {
    trustManager.setOrganizationTrust("org-1", "none", [], []);
    expect(trustManager.canAccessCapability("org-1", "any-capability")).toBe(false);
  });

  test("checks capability access - unknown organization", () => {
    expect(trustManager.canAccessCapability("unknown-org", "any-capability")).toBe(false);
  });

  test("creates cross-org task", () => {
    const agentId = `agent-${Date.now()}`;
    const task = trustManager.createCrossOrgTask({
      requestingAgent: agentId,
      targetOrganization: "org-2",
      taskType: "analysis",
      payload: { data: "sample" },
      priority: 8,
      expiresAt: Date.now() + 600000,
    });
    expect(task.taskId).toHaveLength(32);
    expect(task.status).toBe("pending");
    expect(task.requestingAgent).toBe(agentId);
  });

  test("updates task status", () => {
    const task = trustManager.createCrossOrgTask({
      requestingAgent: "a1",
      targetOrganization: "org-2",
      taskType: "analysis",
      payload: {},
      priority: 5,
      expiresAt: Date.now() + 300000,
    });
    trustManager.updateTaskStatus(task.taskId, "in_progress");
    expect(trustManager.getTask(task.taskId)?.status).toBe("in_progress");
    trustManager.updateTaskStatus(task.taskId, "completed", { result: "done" });
    const updated = trustManager.getTask(task.taskId);
    expect(updated?.status).toBe("completed");
    expect(updated?.result).toEqual({ result: "done" });
  });

  test("gets tasks by status", () => {
    const task1 = trustManager.createCrossOrgTask({
      requestingAgent: "a1",
      targetOrganization: "org-1",
      taskType: "t1",
      payload: {},
      priority: 5,
      expiresAt: Date.now() + 300000,
    });
    trustManager.createCrossOrgTask({
      requestingAgent: "a2",
      targetOrganization: "org-2",
      taskType: "t2",
      payload: {},
      priority: 3,
      expiresAt: Date.now() + 300000,
    });
    trustManager.updateTaskStatus(task1.taskId, "completed");
    const pending = trustManager.getTasksByStatus("pending");
    const completed = trustManager.getTasksByStatus("completed");
    expect(pending).toHaveLength(1);
    expect(completed).toHaveLength(1);
    expect(completed[0].taskId).toBe(task1.taskId);
  });

  test("gets tasks by organization", () => {
    trustManager.createCrossOrgTask({
      requestingAgent: "a1",
      targetOrganization: "org-1",
      taskType: "t1",
      payload: {},
      priority: 5,
      expiresAt: Date.now() + 300000,
    });
    trustManager.createCrossOrgTask({
      requestingAgent: "a2",
      targetOrganization: "org-2",
      taskType: "t2",
      payload: {},
      priority: 5,
      expiresAt: Date.now() + 300000,
    });
    const org1Tasks = trustManager.getTasksByOrganization("org-1");
    expect(org1Tasks).toHaveLength(1);
    expect(org1Tasks[0].targetOrganization).toBe("org-1");
  });

  test("prunes expired tasks", () => {
    const task = trustManager.createCrossOrgTask({
      requestingAgent: "a1",
      targetOrganization: "org-1",
      taskType: "t1",
      payload: {},
      priority: 5,
      expiresAt: Date.now() - 1000,
    });
    const pruned = trustManager.pruneExpiredTasks();
    expect(pruned).toBe(1);
    expect(trustManager.getTask(task.taskId)?.status).toBe("cancelled");
  });

  test("calculates organization risk score", () => {
    trustManager.setOrganizationTrust("org-1", "partial", ["analysis"], []);
    trustManager.createCrossOrgTask({
      requestingAgent: "a1",
      targetOrganization: "org-1",
      taskType: "t1",
      payload: {},
      priority: 5,
      expiresAt: Date.now() + 300000,
    });
    const score = trustManager.getOrganizationRiskScore("org-1");
    expect(score).toBeGreaterThanOrEqual(0);
    expect(score).toBeLessThanOrEqual(1);
  });
});

describe("MessageRouter", () => {
  const dataDir = `/tmp/federation-router-${Date.now()}-${Math.random().toString(36).slice(2)}`;
  let messageRouter: MessageRouter;

  beforeEach(() => {
    messageRouter = new MessageRouter(dataDir);
  });

  test("creates and enqueues message", () => {
    const message = messageRouter.createMessage(
      "task_request",
      "agent-001",
      { task: "analyze" },
      { toOrganization: "org-2" }
    );
    expect(message.id).toHaveLength(32);
    expect(message.type).toBe("task_request");
    expect(message.fromAgent).toBe("agent-001");
    messageRouter.enqueueMessage(message, 5);
    const depth = messageRouter.getQueueDepth();
    expect(depth["5"]).toBe(1);
  });

  test("dequeues by priority", () => {
    const msg1 = messageRouter.createMessage("task_request", "a1", { data: 1 }, {});
    const msg2 = messageRouter.createMessage("task_request", "a2", { data: 2 }, {});
    messageRouter.enqueueMessage(msg1, 8);
    messageRouter.enqueueMessage(msg2, 3);
    const received = messageRouter.dequeueMessage();
    expect(received?.fromAgent).toBe("a2");
  });

  test("moves expired messages to dead letter queue", () => {
    const message = messageRouter.createMessage("task_request", "agent-001", { data: "test" }, { ttl: 1 });
    messageRouter.enqueueMessage(message, 5);
    const received = messageRouter.dequeueMessage(10);
    expect(received).toBeUndefined();
    const dlq = messageRouter.getDeadLetterQueue();
    expect(dlq).toHaveLength(1);
    expect(dlq[0].id).toBe(message.id);
  });

  test("subscribes and unsubscribes", () => {
    messageRouter.subscribe("agent-001", "task-updates");
    messageRouter.subscribe("agent-002", "task-updates");
    const subscribers = messageRouter.getSubscribers("task-updates");
    expect(subscribers).toHaveLength(2);
    messageRouter.unsubscribe("agent-001", "task-updates");
    const remaining = messageRouter.getSubscribers("task-updates");
    expect(remaining).toHaveLength(1);
    expect(remaining[0]).toBe("agent-002");
  });

  test("reprocesses dead letter message", () => {
    const message = messageRouter.createMessage("task_request", "agent-001", { data: "test" });
    messageRouter.enqueueMessage(message, 5);
    messageRouter.dequeueMessage(10);
    const reprocessed = messageRouter.reprocessDeadLetter(message.id);
    expect(reprocessed).toBe(true);
    const depth = messageRouter.getQueueDepth();
    expect(depth["5"]).toBe(1);
  });

  test("returns undefined for empty queue", () => {
    const received = messageRouter.dequeueMessage(100);
    expect(received).toBeUndefined();
  });

  test("gets queue depth for all priorities", () => {
    messageRouter.enqueueMessage(messageRouter.createMessage("heartbeat", "a1", {}), 1);
    messageRouter.enqueueMessage(messageRouter.createMessage("heartbeat", "a2", {}), 2);
    messageRouter.enqueueMessage(messageRouter.createMessage("heartbeat", "a3", {}), 9);
    const depth = messageRouter.getQueueDepth();
    expect(depth["1"]).toBe(1);
    expect(depth["2"]).toBe(1);
    expect(depth["9"]).toBe(1);
  });
});