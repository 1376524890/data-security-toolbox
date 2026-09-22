import type { Task } from '../types/task'

/**
 * The kinds ``POST /tasks/{id}/stop`` accepts, mirroring ``STOPPABLE_TASK_KINDS``
 * in ``backend/app/api/tasks.py``.
 *
 * Every kind listed here has an executor that can observe ``Cancelled``: a probe
 * on its next poll, a platform worker between units of work, or a monitoring
 * session through its capture segments. Offering stop for anything else would
 * only make a running task look stopped.
 */
export const STOPPABLE_TASK_KINDS = [
  'probe_scan', 'data_asset_scan', 'monitoring', 'pcap',
  'database_scan', 'file_source_scan', 'scan',
]

export function canStop(task: Pick<Task, 'kind'>): boolean {
  return STOPPABLE_TASK_KINDS.includes(task.kind)
}
