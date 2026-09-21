<script setup lang="ts">
import type { EngineOption } from '../../../api/databaseConnections'
import type { ConnectionForm } from '../composables/useDatabaseConnectionForm'

const open = defineModel<boolean>({ required: true })
// The parent owns the reactive draft; inputs edit its fields without copying credentials.
defineProps<{ form: ConnectionForm; engines: EngineOption[]; editing: boolean; saving: boolean }>()
const emit = defineEmits<{ save: [] }>()
</script>

<template>
  <el-dialog v-model="open" :title="editing ? '编辑数据库连接' : '新建数据库连接'" width="640px">
    <el-form label-width="120px">
      <el-form-item label="名称">
        <el-input v-model="form.name" placeholder="例如 业务库-只读盘点" />
      </el-form-item>
      <el-row :gutter="12">
        <el-col :span="12">
          <el-form-item label="引擎">
            <el-select v-model="form.engine" style="width: 100%"
                       @change="form.port = engines.find((item) => item.engine === form.engine)?.default_port || form.port">
              <el-option v-for="item in engines" :key="item.engine" :label="item.label" :value="item.engine" />
            </el-select>
          </el-form-item>
        </el-col>
        <el-col :span="12">
          <el-form-item label="TLS 模式">
            <el-select v-model="form.tls_mode" style="width: 100%">
              <el-option label="默认（驱动决定）" value="" />
              <el-option label="disable" value="disable" />
              <el-option label="prefer" value="prefer" />
              <el-option label="require" value="require" />
              <el-option label="verify-full" value="verify-full" />
            </el-select>
          </el-form-item>
        </el-col>
      </el-row>
      <el-row :gutter="12">
        <el-col :span="16">
          <el-form-item label="主机">
            <el-input v-model="form.host" placeholder="IP 或主机名，例如 192.168.191.130" />
          </el-form-item>
        </el-col>
        <el-col :span="8">
          <el-form-item label="端口">
            <el-input-number v-model="form.port" :min="1" :max="65535" controls-position="right"
                             style="width: 100%" />
          </el-form-item>
        </el-col>
      </el-row>
      <el-row :gutter="12">
        <el-col :span="12">
          <el-form-item label="库 / schema">
            <el-input v-model="form.database" placeholder="留空表示按库列表选择" />
          </el-form-item>
        </el-col>
        <el-col :span="12">
          <el-form-item label="账号">
            <el-input v-model="form.username" placeholder="建议只读账号" />
          </el-form-item>
        </el-col>
      </el-row>
      <el-form-item label="密码">
        <el-input v-model="form.password" type="password" show-password
                  :placeholder="editing ? '留空表示不修改已保存的密码' : '留空表示无密码'" />
      </el-form-item>
      <el-form-item label="启用">
        <el-switch v-model="form.enabled" />
        <span class="muted small" style="margin-left: 10px">停用的连接不能发起采集</span>
      </el-form-item>
    </el-form>
    <el-alert type="warning" :closable="false" show-icon
              title="密码由平台加密保存，接口只回传 password_set，任何响应与审计记录都不含密码明文。" />
    <template #footer>
      <el-button @click="open = false">取消</el-button>
      <el-button type="primary" :loading="saving" @click="emit('save')">保存</el-button>
    </template>
  </el-dialog>
</template>

<style scoped>
.muted { color: var(--soc-text-dim); }
.small { font-size: 12px; }
</style>
