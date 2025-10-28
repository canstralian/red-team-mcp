#!/usr/bin/env python3
"""
Distributed Architecture and Resilience Module

Provides distributed server architecture, automatic failover,
data replication, and high availability features.
"""

import asyncio
import json
import time
import hashlib
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
from enum import Enum
import aioredis
import httpx
from contextlib import asynccontextmanager


class NodeStatus(str, Enum):
    """Node operational status."""
    ACTIVE = "active"
    STANDBY = "standby"
    FAILED = "failed"
    MAINTENANCE = "maintenance"


class ReplicationStrategy(str, Enum):
    """Data replication strategies."""
    SYNC = "synchronous"
    ASYNC = "asynchronous"
    EVENTUAL = "eventual_consistency"


@dataclass
class MCPNode:
    """MCP server node representation."""
    node_id: str
    host: str
    port: int
    status: NodeStatus = NodeStatus.STANDBY
    last_heartbeat: float = field(default_factory=time.time)
    load_score: float = 0.0
    capabilities: Set[str] = field(default_factory=set)
    region: str = "default"


class DistributedMCPCluster:
    """Distributed MCP server cluster manager."""
    
    def __init__(self, node_id: str, redis_url: str = "redis://localhost:6379"):
        self.node_id = node_id
        self.redis_url = redis_url
        self.redis_client = None
        self.nodes: Dict[str, MCPNode] = {}
        self.is_leader = False
        self.heartbeat_interval = 30.0  # seconds
        self.failover_threshold = 90.0  # seconds
        
    async def initialize(self):
        """Initialize cluster connection."""
        self.redis_client = await aioredis.from_url(self.redis_url)
        await self.register_node()
        asyncio.create_task(self.heartbeat_worker())
        asyncio.create_task(self.cluster_monitor())
        
    async def register_node(self):
        """Register this node with the cluster."""
        node_data = {
            'node_id': self.node_id,
            'host': 'localhost',  # Should be actual host
            'port': 8000,
            'status': NodeStatus.ACTIVE.value,
            'last_heartbeat': time.time(),
            'capabilities': ['payload_generation', 'exploitation', 'enumeration']
        }
        
        await self.redis_client.hset(
            f"cluster:nodes:{self.node_id}",
            mapping=node_data
        )
        
        # Set node expiration for automatic cleanup
        await self.redis_client.expire(
            f"cluster:nodes:{self.node_id}",
            int(self.failover_threshold)
        )
        
    async def heartbeat_worker(self):
        """Send periodic heartbeats."""
        while True:
            try:
                await self.redis_client.hset(
                    f"cluster:nodes:{self.node_id}",
                    "last_heartbeat",
                    time.time()
                )
                await self.redis_client.expire(
                    f"cluster:nodes:{self.node_id}",
                    int(self.failover_threshold)
                )
                await asyncio.sleep(self.heartbeat_interval)
            except Exception as e:
                print(f"Heartbeat failed: {e}")
                await asyncio.sleep(5)
                
    async def cluster_monitor(self):
        """Monitor cluster health and perform leader election."""
        while True:
            try:
                await self.discover_nodes()
                await self.check_leader_election()
                await self.perform_health_checks()
                await asyncio.sleep(15)
            except Exception as e:
                print(f"Cluster monitoring error: {e}")
                await asyncio.sleep(10)
                
    async def discover_nodes(self):
        """Discover all active nodes in cluster."""
        pattern = "cluster:nodes:*"
        node_keys = await self.redis_client.keys(pattern)
        
        current_nodes = {}
        for key in node_keys:
            node_data = await self.redis_client.hgetall(key)
            if node_data:
                node_id = node_data[b'node_id'].decode()
                current_nodes[node_id] = MCPNode(
                    node_id=node_id,
                    host=node_data[b'host'].decode(),
                    port=int(node_data[b'port']),
                    status=NodeStatus(node_data[b'status'].decode()),
                    last_heartbeat=float(node_data[b'last_heartbeat'])
                )
        
        self.nodes = current_nodes
        
    async def check_leader_election(self):
        """Perform leader election using Redis."""
        try:
            # Attempt to become leader
            result = await self.redis_client.set(
                "cluster:leader",
                self.node_id,
                nx=True,
                ex=60  # Leader lease for 60 seconds
            )
            
            if result:
                self.is_leader = True
                print(f"Node {self.node_id} elected as leader")
            else:
                current_leader = await self.redis_client.get("cluster:leader")
                self.is_leader = (current_leader and 
                                current_leader.decode() == self.node_id)
                
        except Exception as e:
            print(f"Leader election error: {e}")
            self.is_leader = False
            
    async def perform_health_checks(self):
        """Check health of all cluster nodes."""
        if not self.is_leader:
            return
            
        current_time = time.time()
        failed_nodes = []
        
        for node_id, node in self.nodes.items():
            if node_id == self.node_id:
                continue
                
            if current_time - node.last_heartbeat > self.failover_threshold:
                failed_nodes.append(node_id)
                print(f"Node {node_id} marked as failed")
                
        # Remove failed nodes
        for node_id in failed_nodes:
            await self.redis_client.delete(f"cluster:nodes:{node_id}")
            if node_id in self.nodes:
                del self.nodes[node_id]
                
    async def route_request(self, capability: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Route request to appropriate node based on capability and load."""
        available_nodes = [
            node for node in self.nodes.values()
            if node.status == NodeStatus.ACTIVE and capability in node.capabilities
        ]
        
        if not available_nodes:
            # Handle locally if no other nodes available
            return await self.execute_locally(capability, payload)
        
        # Simple load balancing - choose node with lowest load
        target_node = min(available_nodes, key=lambda n: n.load_score)
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"http://{target_node.host}:{target_node.port}/execute",
                    json={'capability': capability, 'payload': payload},
                    timeout=30.0
                )
                return response.json()
        except Exception as e:
            print(f"Request routing failed: {e}")
            # Fallback to local execution
            return await self.execute_locally(capability, payload)
    
    async def execute_locally(self, capability: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Execute request locally."""
        # This would integrate with the main MCP server tools
        return {'status': 'executed_locally', 'capability': capability}


class DataReplication:
    """Data replication across cluster nodes."""
    
    def __init__(self, cluster: DistributedMCPCluster, strategy: ReplicationStrategy):
        self.cluster = cluster
        self.strategy = strategy
        
    async def replicate_data(self, key: str, data: Dict[str, Any]) -> bool:
        """Replicate data across cluster nodes."""
        if self.strategy == ReplicationStrategy.SYNC:
            return await self._sync_replication(key, data)
        elif self.strategy == ReplicationStrategy.ASYNC:
            asyncio.create_task(self._async_replication(key, data))
            return True
        else:  # EVENTUAL
            return await self._eventual_replication(key, data)
    
    async def _sync_replication(self, key: str, data: Dict[str, Any]) -> bool:
        """Synchronous replication to all active nodes."""
        success_count = 0
        total_nodes = len([n for n in self.cluster.nodes.values() 
                          if n.status == NodeStatus.ACTIVE])
        
        if total_nodes == 0:
            return True  # No other nodes to replicate to
        
        tasks = []
        for node in self.cluster.nodes.values():
            if node.status == NodeStatus.ACTIVE and node.node_id != self.cluster.node_id:
                tasks.append(self._replicate_to_node(node, key, data))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        success_count = sum(1 for r in results if r is True)
        
        # Require majority success for sync replication
        return success_count >= (total_nodes // 2)
    
    async def _async_replication(self, key: str, data: Dict[str, Any]):
        """Asynchronous replication (fire and forget)."""
        tasks = []
        for node in self.cluster.nodes.values():
            if node.status == NodeStatus.ACTIVE and node.node_id != self.cluster.node_id:
                tasks.append(self._replicate_to_node(node, key, data))
        
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _eventual_replication(self, key: str, data: Dict[str, Any]) -> bool:
        """Eventual consistency replication."""
        # Store in local queue for eventual replication
        await self.cluster.redis_client.lpush(
            f"replication_queue:{self.cluster.node_id}",
            json.dumps({'key': key, 'data': data, 'timestamp': time.time()})
        )
        return True
    
    async def _replicate_to_node(self, node: MCPNode, key: str, data: Dict[str, Any]) -> bool:
        """Replicate data to specific node."""
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"http://{node.host}:{node.port}/replicate",
                    json={'key': key, 'data': data},
                    timeout=10.0
                )
                return response.status_code == 200
        except Exception:
            return False


class AutoFailover:
    """Automatic failover management."""
    
    def __init__(self, cluster: DistributedMCPCluster):
        self.cluster = cluster
        self.failover_in_progress = False
        
    async def handle_node_failure(self, failed_node_id: str):
        """Handle node failure and initiate failover."""
        if self.failover_in_progress:
            return
            
        self.failover_in_progress = True
        
        try:
            print(f"Initiating failover for failed node: {failed_node_id}")
            
            # Redistribute workload from failed node
            await self._redistribute_workload(failed_node_id)
            
            # Update cluster topology
            await self._update_cluster_topology(failed_node_id)
            
            # Notify monitoring systems
            await self._notify_failure(failed_node_id)
            
        finally:
            self.failover_in_progress = False
    
    async def _redistribute_workload(self, failed_node_id: str):
        """Redistribute workload from failed node."""
        # Get pending work items for failed node
        pending_work = await self.cluster.redis_client.lrange(
            f"work_queue:{failed_node_id}",
            0, -1
        )
        
        # Redistribute to healthy nodes
        if pending_work:
            healthy_nodes = [
                node for node in self.cluster.nodes.values()
                if node.status == NodeStatus.ACTIVE and node.node_id != failed_node_id
            ]
            
            for i, work_item in enumerate(pending_work):
                target_node = healthy_nodes[i % len(healthy_nodes)]
                await self.cluster.redis_client.lpush(
                    f"work_queue:{target_node.node_id}",
                    work_item
                )
        
        # Clean up failed node's queue
        await self.cluster.redis_client.delete(f"work_queue:{failed_node_id}")
    
    async def _update_cluster_topology(self, failed_node_id: str):
        """Update cluster topology after node failure."""
        # Remove failed node from active topology
        await self.cluster.redis_client.delete(f"cluster:nodes:{failed_node_id}")
        
        # Update load balancer configuration
        # This would integrate with actual load balancer
        pass
    
    async def _notify_failure(self, failed_node_id: str):
        """Notify monitoring systems of node failure."""
        failure_event = {
            'event_type': 'node_failure',
            'failed_node': failed_node_id,
            'timestamp': time.time(),
            'cluster_id': self.cluster.node_id
        }
        
        # Log to monitoring system
        await self.cluster.redis_client.lpush(
            "cluster:events",
            json.dumps(failure_event)
        )


# Integration example
@asynccontextmanager
async def resilient_mcp_server(node_id: str):
    """Context manager for resilient MCP server."""
    cluster = DistributedMCPCluster(node_id)
    replication = DataReplication(cluster, ReplicationStrategy.ASYNC)
    failover = AutoFailover(cluster)
    
    try:
        await cluster.initialize()
        yield {
            'cluster': cluster,
            'replication': replication,
            'failover': failover
        }
    finally:
        if cluster.redis_client:
            await cluster.redis_client.close()
