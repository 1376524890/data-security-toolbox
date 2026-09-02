import { apiGet } from './client'
import type { PageResult } from '../types/common'
import type { Task } from '../types/task'

export interface TaskQuery {
  status?: string
  kind?: string
  search?: string
  page: number
  page_size: number
}

export function listTasks(query: TaskQuery): Promise<PageResult<Task>> {
  return apiGet('/tasks', query as unknown as Record<string, unknown>)
}

export function getTask(id: number): Promise<Task> {
  return apiGet(`/tasks/${id}`)
}
