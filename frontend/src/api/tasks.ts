import client, { apiGet, apiPost } from './client'
import type { PageResult } from '../types/common'
import type { Task } from '../types/task'

export interface TaskQuery {
  status?: string
  kind?: string
  search?: string
  /** `field` ascending, `-field` descending; see `useTableSort`. */
  order_by?: string
  page: number
  page_size: number
}

export function listTasks(query: TaskQuery): Promise<PageResult<Task>> {
  return apiGet('/tasks', query as unknown as Record<string, unknown>)
}

export function getTask(id: number): Promise<Task> {
  return apiGet(`/tasks/${id}`)
}

export function stopTask(id: number): Promise<Task> {
  return apiPost(`/tasks/${id}/stop`)
}

export async function deleteTask(id: number): Promise<void> {
  await client.delete(`/tasks/${id}`)
}
