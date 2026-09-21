export function statusType(status: string): 'success' | 'warning' | 'danger' | 'info' | 'primary' {
  if (status === 'ok' || status === 'Success') return 'success'
  if (status === 'Pending' || status === 'Running' || status === 'untested') return 'primary'
  if (status === 'Partial') return 'warning'
  if (status === 'Failed' || status === 'unreachable' || status === 'auth_error') return 'danger'
  return 'info'
}

export function testLabel(status: string): string {
  const labels: Record<string, string> = {
    ok: '连通', untested: '未测试', unreachable: '不可达', auth_error: '认证失败',
    permission: '权限不足', read_only_violation: '只读校验失败', credential_error: '凭据不可用',
    error: '失败', failed: '失败',
  }
  return labels[status] || status || '—'
}

export function reasonLabel(reason: string): string {
  const labels: Record<string, string> = {
    complete: '完整读取', table_budget: '达到表数量上限', time_budget: '达到时间上限',
    read_error: '部分表读取失败', no_tables: '没有可读取的表', cancelled: '已取消',
    partial_scan: '部分读取',
  }
  return labels[reason] || reason || '—'
}
