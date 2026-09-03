import { apiGet } from './client'

export interface GraphNode { id: string; name: string; type: string; risk: string; metadata: Record<string, unknown> }
export interface GraphRelation { source_node: string; source_type: string; target_node: string; target_type: string; relation: string; risk: string }
export interface GraphData { nodes: GraphNode[]; relations: GraphRelation[] }

export function getGraph(): Promise<GraphData> {
  return apiGet('/graph')
}
