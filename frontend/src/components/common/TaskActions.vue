<script setup lang="ts">
import { ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { stopTask, deleteTask } from '../../api/tasks'
import { canStop } from '../../api/taskKinds'
import { useAuthStore } from '../../stores/auth'
import type { Task } from '../../types/task'

const props = defineProps<{ task: Task }>()
const emit = defineEmits<{ changed: [] }>()
const auth = useAuthStore()
const busy = ref(false)
const terminal = (task: Task) => ['Success', 'Failed', 'Partial', 'Cancelled'].includes(task.status)
async function act(remove: boolean) {
  if (busy.value) return
  try {
    await ElMessageBox.confirm(remove ? `删除任务 #${props.task.id}？已采集的数据仍保留。` : `停止任务 #${props.task.id}？等待中的任务将不再下发；已领取的任务由新版探针检查后退出，迟到结果不再入库。`, remove ? '删除任务' : '停止任务', { confirmButtonText: remove ? '删除' : '停止', cancelButtonText: '取消', type: 'warning' })
  } catch { return }
  busy.value = true
  try {
    if (remove) await deleteTask(props.task.id)
    else await stopTask(props.task.id)
    ElMessage.success(remove ? '任务已删除' : '任务已停止')
    emit('changed')
  } catch (err) { ElMessage.error(err instanceof Error ? err.message : String(err)) }
  finally { busy.value = false }
}
</script>

<template>
  <span v-if="auth.user?.role === 'admin'" @click.stop>
    <el-button v-if="!terminal(task) && canStop(task)" size="small" type="warning" :loading="busy" @click="act(false)">停止</el-button>
    <el-button v-if="terminal(task)" size="small" type="danger" :loading="busy" @click="act(true)">删除</el-button>
  </span>
</template>
