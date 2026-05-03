#!/usr/bin/env bun
/**
 * agent-federation-network - Multi-agent federation protocol for cross-organizational agent collaboration with identity verification
 * A comprehensive system for enabling AI agents from different organizations to collaborate securely
 */

import { createHash, randomBytes, createHmac, timingSafeEqual } from "crypto";
import { existsSync, readFileSync, writeFileSync, mkdirSync, appendFileSync } from "fs";
import { join } from "path";

// ============== Types ==============

export interface AgentIdentity {
  id: string;
  organizationId: string;
  publicKey: string;
  createdAt: number;
  lastVerified: number;
  trustScore: number;
  metadata: Record<string, string>;
}

export interface FederationNode {
  id: string;
  endpoint: string;
  organizationId: string;
  isActive: boolean;
  lastHeartbeat: number;
  trustedAgents: Set<string>;
}

export interface CrossOrgTask {
  taskId: string;
  requestingAgent: string;
  targetOrganization: string;
  taskType: string;
  payload: unknown;
  priority: number;
  status: 'pending' | 'in_progress' | 'completed' | 'failed' | 'cancelled';
  createdAt: number;
  expiresAt: number;
  result?: unknown;
  error?: string;
}

export interface Attestation {
  id: string;
  agentId: string;
  claims: Record<string, unknown>;
  signature: string;
  issuedAt: number;
  expiresAt: number;
  previousAttestationHash: string;
}

export interface FederationMessage {
  id: string;
  type: 'task_request' | 'task_response' | 'attestation' | 'heartbeat' | 'trust_update' | 'revocation';
  fromAgent: string;
  toAgent?: string;
  toOrganization?: string;
  payload: unknown;
  timestamp: number;
  ttl: number;
  signature: string;
  referencedAttestations: string[];
}

export interface OrganizationTrustLevel {
  organizationId: string;
  trustLevel: 'none' | 'partial' | 'full';
  allowedCapabilities: string[];
  restrictions: string[];
  lastAssessment: number;
}

// ============== IdentityManager ==============

export class IdentityManager {
  private identities: Map<string, AgentIdentity> = new Map();
  private privateKeys: Map<string, string> = new Map();
  private attestations: Map<string, Attestation[]> = new Map();
  private dataDir: string;

  constructor(dataDir: string = './data') {
    this.dataDir = dataDir;
    this.ensureDataDir();
    this.loadIdentities();
  }

  private ensureDataDir(): void {
    if (!existsSync(this.dataDir)) {
      mkdirSync(this.dataDir, { recursive: true });
    }
  }

  private loadIdentities(): void {
    const identitiesFile = join(this.dataDir, 'identities.json');
    if (existsSync(identitiesFile)) {
      try {
        const data = JSON.parse(readFileSync(identitiesFile, 'utf-8'));
        for (const [id, identity] of Object.entries(data.identities || {})) {
          this.identities.set(id, identity as AgentIdentity);
        }
      } catch (e) {
        console.error('Failed to load identities:', e);
      }
    }
  }

  private saveIdentities(): void {
    const identitiesFile = join(this.dataDir, 'identities.json');
    const data: Record<string, unknown> = {};
    for (const [id, identity] of this.identities) {
      data[id] = identity;
    }
    writeFileSync(identitiesFile, JSON.stringify({ identities: data }, null, 2));
  }

  generateKeyPair(): { publicKey: string; privateKey: string } {
    const privateKey = randomBytes(32).toString('hex');
    const publicKey = createHash('sha256').update(privateKey).digest('hex');
    return { publicKey, privateKey };
  }

  registerAgent(organizationId: string, agentId: string, metadata: Record<string, string> = {}): AgentIdentity {
    if (this.identities.has(agentId)) {
      throw new Error(`Agent ${agentId} already registered`);
    }
    const { publicKey, privateKey } = this.generateKeyPair();
    this.privateKeys.set(agentId, privateKey);
    const identity: AgentIdentity = {
      id: agentId,
      organizationId,
      publicKey,
      createdAt: Date.now(),
      lastVerified: Date.now(),
      trustScore: 1.0,
      metadata,
    };
    this.identities.set(agentId, identity);
    this.saveIdentities();
    return identity;
  }

  getAgent(agentId: string): AgentIdentity | undefined {
    return this.identities.get(agentId);
  }

  verifyAgent(agentId: string): boolean {
    const identity = this.identities.get(agentId);
    if (!identity) return false;
    if (Date.now() - identity.lastVerified > 3600000) {
      identity.lastVerified = Date.now();
      identity.trustScore = Math.min(1.0, identity.trustScore + 0.01);
      this.saveIdentities();
    }
    return true;
  }

  signData(agentId: string, data: unknown): string {
    const privateKey = this.privateKeys.get(agentId);
    if (!privateKey) {
      throw new Error(`No private key found for agent ${agentId}`);
    }
    const payload = typeof data === 'string' ? data : JSON.stringify(data);
    return createHmac('sha256', privateKey).update(payload).digest('hex');
  }

  verifySignature(agentId: string, data: unknown, signature: string): boolean {
    const identity = this.identities.get(agentId);
    if (!identity) return false;
    const expectedSignature = this.signData(agentId, data);
    const signatureBuffer = Buffer.from(signature);
    const expectedBuffer = Buffer.from(expectedSignature);
    if (signatureBuffer.length !== expectedBuffer.length) return false;
    return timingSafeEqual(signatureBuffer, expectedBuffer);
  }

  issueAttestation(agentId: string, claims: Record<string, unknown>, validityMs: number = 86400000): Attestation {
    const identity = this.identities.get(agentId);
    if (!identity) {
      throw new Error(`Agent ${agentId} not found`);
    }
    const previousAttestations = this.attestations.get(agentId) || [];
    const previousHash = previousAttestations.length > 0
      ? previousAttestations[previousAttestations.length - 1].signature
      : 'genesis';
    const attestation: Attestation = {
      id: randomBytes(16).toString('hex'),
      agentId,
      claims,
      signature: '',
      issuedAt: Date.now(),
      expiresAt: Date.now() + validityMs,
      previousAttestationHash: previousHash,
    };
    attestation.signature = this.signData(agentId, attestation);
    previousAttestations.push(attestation);
    this.attestations.set(agentId, previousAttestations);
    return attestation;
  }

  verifyAttestationChain(agentId: string): { valid: boolean; brokenAt?: number } {
    const attestations = this.attestations.get(agentId);
    if (!attestations || attestations.length === 0) {
      return { valid: false, brokenAt: 0 };
    }
    for (let i = 0; i < attestations.length; i++) {
      const attestation = attestations[i];
      if (Date.now() > attestation.expiresAt) {
        return { valid: false, brokenAt: i };
      }
      const expectedSignature = this.signData(agentId, attestation);
      if (attestation.signature !== expectedSignature) {
        return { valid: false, brokenAt: i };
      }
      if (i > 0) {
        const previous = attestations[i - 1];
        if (attestation.previousAttestationHash !== previous.signature) {
          return { valid: false, brokenAt: i };
        }
      }
    }
    return { valid: true };
  }

  listAgents(organizationId?: string): AgentIdentity[] {
    const agents = Array.from(this.identities.values());
    if (organizationId) {
      return agents.filter(a => a.organizationId === organizationId);
    }
    return agents;
  }

  updateTrustScore(agentId: string, delta: number): void {
    const identity = this.identities.get(agentId);
    if (identity) {
      identity.trustScore = Math.max(0, Math.min(1.0, identity.trustScore + delta));
      this.saveIdentities();
    }
  }
}

// ============== FederationNodeManager ==============

export class FederationNodeManager {
  private nodes: Map<string, FederationNode> = new Map();
  private dataDir: string;

  constructor(dataDir: string = './data') {
    this.dataDir = dataDir;
    this.loadNodes();
  }

  private loadNodes(): void {
    const nodesFile = join(this.dataDir, 'nodes.json');
    if (existsSync(nodesFile)) {
      try {
        const data = JSON.parse(readFileSync(nodesFile, 'utf-8'));
        for (const [id, node] of Object.entries(data.nodes || {})) {
          const n = node as FederationNode;
          n.trustedAgents = new Set(n.trustedAgents);
          this.nodes.set(id, n);
        }
      } catch (e) {
        console.error('Failed to load nodes:', e);
      }
    }
  }

  private saveNodes(): void {
    const nodesFile = join(this.dataDir, 'nodes.json');
    const data: Record<string, unknown> = {};
    for (const [id, node] of this.nodes) {
      data[id] = { ...node, trustedAgents: Array.from(node.trustedAgents) };
    }
    writeFileSync(nodesFile, JSON.stringify({ nodes: data }, null, 2));
  }

  registerNode(node: Omit<FederationNode, 'isActive' | 'lastHeartbeat' | 'trustedAgents'>): FederationNode {
    const fullNode: FederationNode = {
      ...node,
      isActive: true,
      lastHeartbeat: Date.now(),
      trustedAgents: new Set(),
    };
    this.nodes.set(node.id, fullNode);
    this.saveNodes();
    return fullNode;
  }

  getNode(nodeId: string): FederationNode | undefined {
    return this.nodes.get(nodeId);
  }

  getActiveNodes(): FederationNode[] {
    return Array.from(this.nodes.values()).filter(n => n.isActive);
  }

  updateHeartbeat(nodeId: string): void {
    const node = this.nodes.get(nodeId);
    if (node) {
      node.lastHeartbeat = Date.now();
      node.isActive = true;
      this.saveNodes();
    }
  }

  markNodeInactive(nodeId: string): void {
    const node = this.nodes.get(nodeId);
    if (node) {
      node.isActive = false;
      this.saveNodes();
    }
  }

  trustAgent(nodeId: string, agentId: string): void {
    const node = this.nodes.get(nodeId);
    if (node) {
      node.trustedAgents.add(agentId);
      this.saveNodes();
    }
  }

  revokeAgentTrust(nodeId: string, agentId: string): void {
    const node = this.nodes.get(nodeId);
    if (node) {
      node.trustedAgents.delete(agentId);
      this.saveNodes();
    }
  }

  isAgentTrusted(nodeId: string, agentId: string): boolean {
    const node = this.nodes.get(nodeId);
    return node ? node.trustedAgents.has(agentId) : false;
  }

  pruneInactiveNodes(maxAgeMs: number = 300000): number {
    let pruned = 0;
    const now = Date.now();
    for (const [, node] of this.nodes) {
      if (node.isActive && now - node.lastHeartbeat > maxAgeMs) {
        node.isActive = false;
        pruned++;
      }
    }
    if (pruned > 0) this.saveNodes();
    return pruned;
  }
}

// ============== TrustManager ==============

export class TrustManager {
  private organizationTrust: Map<string, OrganizationTrustLevel> = new Map();
  private crossOrgTasks: Map<string, CrossOrgTask> = new Map();
  private dataDir: string;
  private auditLog: string;

  constructor(dataDir: string = './data', auditLogPath: string = './audit.log') {
    this.dataDir = dataDir;
    this.auditLog = auditLogPath;
    this.loadTrustLevels();
  }

  private loadTrustLevels(): void {
    const trustFile = join(this.dataDir, 'trust-levels.json');
    if (existsSync(trustFile)) {
      try {
        const data = JSON.parse(readFileSync(trustFile, 'utf-8'));
        for (const [id, level] of Object.entries(data.levels || {})) {
          this.organizationTrust.set(id, level as OrganizationTrustLevel);
        }
      } catch (e) {
        console.error('Failed to load trust levels:', e);
      }
    }
  }

  private saveTrustLevels(): void {
    const trustFile = join(this.dataDir, 'trust-levels.json');
    const data: Record<string, unknown> = {};
    for (const [id, level] of this.organizationTrust) {
      data[id] = level;
    }
    writeFileSync(trustFile, JSON.stringify({ levels: data }, null, 2));
  }

  private logAudit(action: string, details: Record<string, unknown>): void {
    const entry = JSON.stringify({
      timestamp: Date.now(),
      action,
      ...details,
    });
    appendFileSync(this.auditLog, entry + '\n');
  }

  setOrganizationTrust(
    organizationId: string,
    trustLevel: 'none' | 'partial' | 'full',
    allowedCapabilities: string[] = [],
    restrictions: string[] = []
  ): void {
    this.organizationTrust.set(organizationId, {
      organizationId,
      trustLevel,
      allowedCapabilities,
      restrictions,
      lastAssessment: Date.now(),
    });
    this.saveTrustLevels();
    this.logAudit('trust_level_set', { organizationId, trustLevel, allowedCapabilities, restrictions });
  }

  getOrganizationTrust(organizationId: string): OrganizationTrustLevel | undefined {
    return this.organizationTrust.get(organizationId);
  }

  canAccessCapability(organizationId: string, capability: string): boolean {
    const trust = this.organizationTrust.get(organizationId);
    if (!trust) return false;
    if (trust.trustLevel === 'none') return false;
    if (trust.trustLevel === 'full') return true;
    return trust.allowedCapabilities.includes(capability);
  }

  createCrossOrgTask(task: Omit<CrossOrgTask, 'status' | 'createdAt' | 'taskId'>): CrossOrgTask {
    const fullTask: CrossOrgTask = {
      ...task,
      taskId: randomBytes(16).toString('hex'),
      status: 'pending',
      createdAt: Date.now(),
    };
    this.crossOrgTasks.set(fullTask.taskId, fullTask);
    this.logAudit('task_created', { taskId: fullTask.taskId, taskType: task.taskType, targetOrganization: task.targetOrganization });
    return fullTask;
  }

  getTask(taskId: string): CrossOrgTask | undefined {
    return this.crossOrgTasks.get(taskId);
  }

  updateTaskStatus(taskId: string, status: CrossOrgTask['status'], result?: unknown, error?: string): void {
    const task = this.crossOrgTasks.get(taskId);
    if (task) {
      task.status = status;
      if (result !== undefined) task.result = result;
      if (error) task.error = error;
      this.logAudit('task_status_update', { taskId, status, error });
    }
  }

  getTasksByStatus(status: CrossOrgTask['status']): CrossOrgTask[] {
    return Array.from(this.crossOrgTasks.values()).filter(t => t.status === status);
  }

  getTasksByOrganization(organizationId: string): CrossOrgTask[] {
    return Array.from(this.crossOrgTasks.values()).filter(t => t.targetOrganization === organizationId);
  }

  pruneExpiredTasks(): number {
    const now = Date.now();
    let pruned = 0;
    for (const [, task] of this.crossOrgTasks) {
      if (task.status !== 'completed' && task.status !== 'failed' && now > task.expiresAt) {
        task.status = 'cancelled';
        pruned++;
      }
    }
    return pruned;
  }

  getOrganizationRiskScore(organizationId: string): number {
    const trust = this.organizationTrust.get(organizationId);
    if (!trust) return 1.0;
    const tasks = this.getTasksByOrganization(organizationId);
    const failedTasks = tasks.filter(t => t.status === 'failed').length;
    const totalTasks = tasks.length || 1;
    const failureRate = failedTasks / totalTasks;
    const timeSinceAssessment = (Date.now() - trust.lastAssessment) / 86400000;
    const stalenessPenalty = Math.min(0.3, timeSinceAssessment * 0.05);
    return Math.min(1.0, failureRate * 0.7 + stalenessPenalty);
  }
}

// ============== MessageRouter ==============

export class MessageRouter {
  private messageQueue: Map<string, FederationMessage[]> = new Map();
  private subscriptions: Map<string, Set<string>> = new Map();
  private deadLetterQueue: FederationMessage[] = [];
  private dataDir: string;

  constructor(dataDir: string = './data') {
    this.dataDir = dataDir;
    this.loadQueue();
  }

  private loadQueue(): void {
    const queueFile = join(this.dataDir, 'message-queue.json');
    if (existsSync(queueFile)) {
      try {
        const data = JSON.parse(readFileSync(queueFile, 'utf-8'));
        for (const [priority, messages] of Object.entries(data.queue || {})) {
          this.messageQueue.set(priority, messages as FederationMessage[]);
        }
        this.deadLetterQueue = data.deadLetter || [];
      } catch (e) {
        console.error('Failed to load message queue:', e);
      }
    }
  }

  private saveQueue(): void {
    const queueFile = join(this.dataDir, 'message-queue.json');
    const queue: Record<string, unknown> = {};
    for (const [priority, messages] of this.messageQueue) {
      queue[priority] = messages;
    }
    writeFileSync(queueFile, JSON.stringify({ queue, deadLetter: this.deadLetterQueue }, null, 2));
  }

  createMessage(
    type: FederationMessage['type'],
    fromAgent: string,
    payload: unknown,
    options: {
      toAgent?: string;
      toOrganization?: string;
      ttl?: number;
      referencedAttestations?: string[];
    } = {}
  ): FederationMessage {
    return {
      id: randomBytes(16).toString('hex'),
      type,
      fromAgent,
      toAgent: options.toAgent,
      toOrganization: options.toOrganization,
      payload,
      timestamp: Date.now(),
      ttl: options.ttl || 300000,
      signature: '',
      referencedAttestations: options.referencedAttestations || [],
    };
  }

  enqueueMessage(message: FederationMessage, priority: number = 5): void {
    const priorityKey = String(priority);
    if (!this.messageQueue.has(priorityKey)) {
      this.messageQueue.set(priorityKey, []);
    }
    this.messageQueue.get(priorityKey)!.push(message);
    this.saveQueue();
  }

  dequeueMessage(_maxWaitMs: number = 1000): FederationMessage | undefined {
    const priorities = ['1', '2', '3', '4', '5', '6', '7', '8', '9', '10'];
    for (const priority of priorities) {
      const queue = this.messageQueue.get(priority);
      if (queue && queue.length > 0) {
        const message = queue.shift()!;
        if (Date.now() - message.timestamp > message.ttl) {
          this.deadLetterQueue.push(message);
          this.saveQueue();
          continue;
        }
        this.saveQueue();
        return message;
      }
    }
    return undefined;
  }

  subscribe(agentId: string, topic: string): void {
    if (!this.subscriptions.has(topic)) {
      this.subscriptions.set(topic, new Set());
    }
    this.subscriptions.get(topic)!.add(agentId);
  }

  unsubscribe(agentId: string, topic: string): void {
    const subscribers = this.subscriptions.get(topic);
    if (subscribers) {
      subscribers.delete(agentId);
    }
  }

  getSubscribers(topic: string): string[] {
    return Array.from(this.subscriptions.get(topic) || []);
  }

  getDeadLetterQueue(): FederationMessage[] {
    return [...this.deadLetterQueue];
  }

  reprocessDeadLetter(messageId: string): boolean {
    const index = this.deadLetterQueue.findIndex(m => m.id === messageId);
    if (index !== -1) {
      const message = this.deadLetterQueue.splice(index, 1)[0];
      message.timestamp = Date.now();
      this.enqueueMessage(message, 5);
      this.saveQueue();
      return true;
    }
    return false;
  }

  getQueueDepth(): Record<string, number> {
    const depth: Record<string, number> = {};
    for (const [priority, messages] of this.messageQueue) {
      depth[priority] = messages.length;
    }
    return depth;
  }
}

// ============== CLI Entry Point ==============

async function runCLI() {
  const { Command } = await import("commander");
  const program = new Command();
  
  program
    .name('agent-federation-network')
    .description('Multi-agent federation protocol for cross-organizational agent collaboration with identity verification')
    .version('1.0.0')
    .option('-d, --data-dir <path>', 'Data directory', './data')
    .option('-c, --config <path>', 'Config file path', 'config.json')
    .option('-v, --verbose', 'Verbose mode');

  const identityManager = new IdentityManager('./data');
  const nodeManager = new FederationNodeManager('./data');
  const trustManager = new TrustManager('./data', './audit.log');
  const messageRouter = new MessageRouter('./data');

  program.command('register-agent')
    .requiredOption('--organization-id <id>', 'Organization ID')
    .requiredOption('--agent-id <id>', 'Agent ID')
    .option('--metadata <json>', 'Agent metadata as JSON')
    .action(async (opts) => {
      const metadata = opts.metadata ? JSON.parse(opts.metadata) : {};
      console.log(JSON.stringify(identityManager.registerAgent(opts.organizationId, opts.agentId, metadata), null, 2));
    });

  program.command('issue-attestation')
    .requiredOption('--agent-id <id>', 'Agent ID')
    .requiredOption('--claims <json>', 'Attestation claims as JSON')
    .option('--validity-ms <ms>', 'Validity period in milliseconds')
    .action(async (opts) => {
      const claims = JSON.parse(opts.claims);
      const validityMs = opts.validityMs ? parseInt(opts.validityMs, 10) : undefined;
      console.log(JSON.stringify(identityManager.issueAttestation(opts.agentId, claims, validityMs), null, 2));
    });

  program.command('verify-chain')
    .requiredOption('--agent-id <id>', 'Agent ID')
    .action(async (opts) => {
      console.log(JSON.stringify(identityManager.verifyAttestationChain(opts.agentId), null, 2));
    });

  program.command('list-agents')
    .option('--organization-id <id>', 'Filter by organization')
    .action(async (opts) => {
      console.log(JSON.stringify(identityManager.listAgents(opts.organizationId), null, 2));
    });

  program.command('register-node')
    .requiredOption('--node-id <id>', 'Node ID')
    .requiredOption('--endpoint <url>', 'Node endpoint URL')
    .requiredOption('--organization-id <id>', 'Organization ID')
    .action(async (opts) => {
      console.log(JSON.stringify(nodeManager.registerNode({
        id: opts.nodeId,
        endpoint: opts.endpoint,
        organizationId: opts.organizationId,
      }), null, 2));
    });

  program.command('trust-agent')
    .requiredOption('--node-id <id>', 'Node ID')
    .requiredOption('--agent-id <id>', 'Agent ID')
    .action(async (opts) => {
      nodeManager.trustAgent(opts.nodeId, opts.agentId);
      console.log(`Agent ${opts.agentId} trusted by node ${opts.nodeId}`);
    });

  program.command('set-trust')
    .requiredOption('--organization-id <id>', 'Organization ID')
    .requiredOption('--level <level>', 'Trust level (none|partial|full)')
    .option('--capabilities <csv>', 'Allowed capabilities (comma-separated)')
    .option('--restrictions <csv>', 'Restrictions (comma-separated)')
    .action(async (opts) => {
      const trustLevel = opts.level as 'none' | 'partial' | 'full';
      const capabilities = opts.capabilities ? opts.capabilities.split(',') : [];
      const restrictions = opts.restrictions ? opts.restrictions.split(',') : [];
      trustManager.setOrganizationTrust(opts.organizationId, trustLevel, capabilities, restrictions);
      console.log(`Trust level set for organization ${opts.organizationId}: ${trustLevel}`);
    });

  program.command('create-task')
    .requiredOption('--requesting-agent <id>', 'Requesting agent ID')
    .requiredOption('--target-org <id>', 'Target organization ID')
    .requiredOption('--task-type <type>', 'Task type')
    .requiredOption('--priority <n>', 'Priority (1-10)', parseInt)
    .option('--ttl-ms <ms>', 'Time to live in milliseconds')
    .action(async (opts) => {
      console.log(JSON.stringify(trustManager.createCrossOrgTask({
        requestingAgent: opts.requestingAgent,
        targetOrganization: opts.targetOrg,
        taskType: opts.taskType,
        payload: {},
        priority: parseInt(String(opts.priority), 10),
        expiresAt: Date.now() + (opts.ttlMs ? parseInt(opts.ttlMs, 10) : 300000),
      }), null, 2));
    });

  program.command('get-task')
    .requiredOption('--task-id <id>', 'Task ID')
    .action(async (opts) => {
      const task = trustManager.getTask(opts.taskId);
      if (task) {
        console.log(JSON.stringify(task, null, 2));
      } else {
        console.error(`Task ${opts.taskId} not found`);
        process.exit(1);
      }
    });

  program.command('send-message')
    .requiredOption('--type <type>', 'Message type')
    .requiredOption('--from <agent>', 'From agent ID')
    .option('--to-agent <id>', 'To agent ID')
    .option('--to-org <id>', 'To organization ID')
    .requiredOption('--payload <json>', 'Message payload as JSON')
    .option('--priority <n>', 'Priority (1-10)', parseInt)
    .action(async (opts) => {
      const message = messageRouter.createMessage(
        opts.type as FederationMessage['type'],
        opts.from,
        JSON.parse(opts.payload),
        { toAgent: opts.toAgent, toOrganization: opts.toOrg }
      );
      messageRouter.enqueueMessage(message, opts.priority ? parseInt(String(opts.priority), 10) : 5);
      console.log(JSON.stringify(message, null, 2));
    });

  program.command('receive-message').action(async () => {
    const message = messageRouter.dequeueMessage();
    if (message) {
      console.log(JSON.stringify(message, null, 2));
    } else {
      console.log('No messages in queue');
    }
  });

  program.command('stats').action(async () => {
    console.log(JSON.stringify({
      identities: { total: identityManager.listAgents().length },
      nodes: { total: nodeManager.getActiveNodes().length + 1, active: nodeManager.getActiveNodes().length },
      tasks: {
        pending: trustManager.getTasksByStatus('pending').length,
        inProgress: trustManager.getTasksByStatus('in_progress').length,
        completed: trustManager.getTasksByStatus('completed').length,
        failed: trustManager.getTasksByStatus('failed').length,
      },
      messages: { queueDepth: messageRouter.getQueueDepth(), deadLetterCount: messageRouter.getDeadLetterQueue().length },
    }, null, 2));
  });

  await program.parseAsync(process.argv);
}

if (import.meta.main) {
  runCLI().catch((e) => {
    console.error(`Error: ${e}`);
    process.exit(1);
  });
}
