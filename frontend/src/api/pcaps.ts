import { apiGet, apiPost, apiUpload, downloadUrl } from './client'
import type { PageResult } from '../types/common'
import type { AlertItem, Flow, NetworkFile, Packet, PcapRecord, TrafficOverview } from '../types/pcap'

export interface PcapQuery {
  search?: string
  status?: string
  page: number
  page_size: number
}

export function listPcaps(query: PcapQuery): Promise<PageResult<PcapRecord>> {
  return apiGet('/pcaps', query as unknown as Record<string, unknown>)
}

export function getPcap(id: number): Promise<PcapRecord> {
  return apiGet(`/pcaps/${id}`)
}

export function analyzePcap(id: number): Promise<unknown> {
  return apiPost(`/pcaps/${id}/analyze`)
}

export function uploadPcap(file: File, probeId?: number): Promise<unknown> {
  return apiUpload('/pcaps/upload', file, probeId ? { probe_id: probeId } : {})
}

export function getTraffic(id: number): Promise<TrafficOverview> {
  return apiGet(`/pcaps/${id}/traffic`)
}

export function getPcapFlows(id: number, page = 1, pageSize = 50): Promise<PageResult<Flow>> {
  return apiGet(`/pcaps/${id}/flows`, { page, page_size: pageSize })
}

export function getPcapPackets(id: number, page = 1, pageSize = 100): Promise<PageResult<Packet>> {
  return apiGet(`/pcaps/${id}/packets`, { page, page_size: pageSize })
}

export function getPcapAlerts(id: number): Promise<{ items: AlertItem[] }> {
  return apiGet(`/pcaps/${id}/alerts`)
}

export function getPcapDns(id: number): Promise<{ items: Array<Record<string, unknown>> }> {
  return apiGet(`/pcaps/${id}/dns`)
}

export function getPcapHttp(id: number): Promise<{ items: Array<Record<string, unknown>> }> {
  return apiGet(`/pcaps/${id}/http`)
}

export function getPcapTls(id: number): Promise<{ items: Array<Record<string, unknown>> }> {
  return apiGet(`/pcaps/${id}/tls`)
}

export function getPcapFiles(id: number): Promise<{ items: NetworkFile[] }> {
  return apiGet(`/pcaps/${id}/files`)
}

export function getPcapProtocols(id: number): Promise<Array<Record<string, unknown>>> {
  return apiGet(`/pcaps/${id}/protocols`)
}

export function getPcapAnomalies(id: number): Promise<Array<Record<string, unknown>>> {
  return apiGet(`/pcaps/${id}/anomalies`)
}

export interface PacketDetail {
  packet: Packet
  raw: string
  layers: Array<{ name: string; items: Array<{ label: string; value: string }> }>
}

export function getPcapPacketDetail(pcapId: number, packetId: number): Promise<PacketDetail> {
  return apiGet(`/pcaps/${pcapId}/packets/${packetId}`)
}

export interface TcpStreamFollow {
  stream: string
  nodes: Array<{ node: number; ip: string; port: number }>
  directions: Array<{ direction: string; ascii: string; hex: string }>
}

export function getPcapStream(pcapId: number, streamId: number): Promise<TcpStreamFollow> {
  return apiGet(`/pcaps/${pcapId}/streams/${streamId}`)
}

export function getPcapFileDownloadUrl(pcapId: number, fileId: number): string {
  return downloadUrl(`/pcaps/${pcapId}/files/${fileId}/download`)
}
