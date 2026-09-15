import { apiGet } from './client'
import type { PageResult } from '../types/common'
import type { Ioc, IocAssociation } from '../types/ioc'

export function listIocs(query: { type?: string; source?: string; search?: string; page: number; page_size: number }): Promise<PageResult<Ioc>> {
  const { type, ...rest } = query
  return apiGet('/iocs', { ...rest, ioc_type: type })
}

export function getIocAssociations(id: number): Promise<IocAssociation> {
  return apiGet(`/iocs/${id}/associations`)
}
