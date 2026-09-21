import { computed, reactive, ref, type Ref } from 'vue'
import { ElMessage } from 'element-plus'
import {
  createDatabaseConnection, updateDatabaseConnection,
  type DatabaseConnection, type EngineOption,
} from '../../../api/databaseConnections'

export interface ConnectionForm {
  name: string
  engine: string
  host: string
  port: number
  database: string
  username: string
  password: string
  tls_mode: string
  enabled: boolean
}

function emptyForm(): ConnectionForm {
  return {
    name: '', engine: 'mysql', host: '', port: 3306, database: '', username: '',
    password: '', tls_mode: '', enabled: true,
  }
}

// Refresh and selection belong to the coordinator; the draft owns write-only credentials.
export function useDatabaseConnectionForm(
  engines: Ref<EngineOption[]>,
  selectCreated: (id: number) => void,
  load: () => Promise<void>,
) {
  const formOpen = ref(false)
  const formId = ref<number | null>(null)
  const form = reactive<ConnectionForm>(emptyForm())
  const saving = ref(false)
  const editing = computed(() => formId.value !== null)

  function openCreate(): void {
    formId.value = null
    Object.assign(form, emptyForm())
    formOpen.value = true
  }

  function openEdit(row: DatabaseConnection): void {
    formId.value = row.id
    Object.assign(form, emptyForm(), {
      name: row.name, engine: row.engine, host: row.host, port: row.port,
      database: row.database, username: row.username, tls_mode: row.tls_mode,
      enabled: row.enabled, password: '',
    })
    formOpen.value = true
  }

  function portFor(engine: string): number {
    return engines.value.find((item) => item.engine === engine)?.default_port ?? 3306
  }

  async function save(): Promise<void> {
    if (!form.name.trim() || !form.host.trim()) {
      ElMessage.warning('请填写连接名称与主机地址')
      return
    }
    saving.value = true
    try {
      const payload = {
        name: form.name.trim(), engine: form.engine, host: form.host.trim(),
        port: form.port || portFor(form.engine), database: form.database.trim(),
        username: form.username.trim(), tls_mode: form.tls_mode, enabled: form.enabled,
      }
      if (formId.value === null) {
        const created = await createDatabaseConnection({ ...payload, password: form.password })
        selectCreated(created.id)
        ElMessage.success('连接已创建；密码已加密保存，只写不读')
      } else {
        // An empty box means "keep the stored password", not "erase it".
        const body: Record<string, unknown> = { ...payload }
        if (form.password) body.password = form.password
        await updateDatabaseConnection(formId.value, body)
        ElMessage.success('连接已更新')
      }
      form.password = ''
      formOpen.value = false
      await load()
    } catch (err) {
      ElMessage.error(err instanceof Error ? err.message : String(err))
    } finally {
      saving.value = false
    }
  }

  return { formOpen, formId, form, saving, editing, openCreate, openEdit, save }
}
