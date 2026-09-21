import client, { apiGet, apiPost } from './client'
import type { PageResult } from '../types/common'
export interface FileSource {
  id: number; name: string; protocol: string; host: string; port: number; username: string;
  root_path: string; host_key_sha256: string; enabled: boolean; password_set: boolean;
  limits: Record<string, number>; interval_minutes: number; next_scan_at: string | null;
  last_status: string; last_error: string; last_scan_at: string | null;
}
export interface FileSourceForm {
  name: string; protocol: string; host: string; port: number; username: string; password?: string;
  root_path: string; host_key_sha256: string; enabled: boolean; limits: Record<string, number>; interval_minutes: number;
}
export const listFileSources = (page = 1) => apiGet<PageResult<FileSource>>('/file-sources', { page, page_size: 50 })
export async function saveFileSource(id: number | null, form: FileSourceForm): Promise<FileSource> {
  return id ? (await client.put<FileSource>(`/file-sources/${id}`, form)).data : apiPost('/file-sources', form)
}
export const runFileSource = (id: number, operation: 'test' | 'scan') => apiPost<{id: number}>(`/file-sources/${id}/${operation}`)
export async function deleteFileSource(id: number): Promise<{ id: number }> {
  return (await client.delete<{ id: number }>(`/file-sources/${id}`)).data
}
