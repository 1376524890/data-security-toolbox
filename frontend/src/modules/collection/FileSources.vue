<script setup lang="ts">
import { useRouter } from 'vue-router'
import { useFileSources } from './composables/useFileSources'
const router = useRouter()
const { rows, total, page, error, loading, open, editing, saving, busy, form, load, edit, save, run, remove } = useFileSources()
</script>
<template>
  <div class="toolbar"><strong>共享文件源</strong><span class="muted">FTP · FTPS · SFTP</span><div class="toolbar-spacer" />
    <el-button @click="load()">刷新</el-button><el-button type="primary" @click="edit()">添加文件源</el-button></div>
  <el-alert v-if="error" :title="error" type="error" :closable="false" />
  <el-table :data="rows" v-loading="loading" size="small" empty-text="尚未配置共享文件源">
    <el-table-column label="来源 / 目标" min-width="220"><template #default="{ row }"><strong>{{ row.name }}</strong><div class="muted">{{ row.protocol.toUpperCase() }} · {{ row.host }}:{{ row.port }}{{ row.root_path }}</div></template></el-table-column>
    <el-table-column label="最近结果" min-width="170"><template #default="{ row }"><el-tag size="small" :type="row.last_status === 'Success' ? 'success' : row.last_status === 'Failed' ? 'danger' : 'info'">{{ row.last_status }}</el-tag><div class="muted">{{ row.last_error || (row.last_scan_at ? new Date(row.last_scan_at).toLocaleString() : '尚未采集') }}</div></template></el-table-column>
    <el-table-column label="巡检计划" width="190"><template #default="{ row }">{{ !row.enabled ? '已停用' : row.interval_minutes ? `每 ${row.interval_minutes} 分钟` : '手动采集' }}<div class="muted" v-if="row.enabled && row.next_scan_at">下次 {{ new Date(row.next_scan_at).toLocaleString() }}</div></template></el-table-column>
    <el-table-column label="操作" width="270"><template #default="{ row }">
      <el-button link type="primary" :disabled="!row.enabled || busy === row.id" @click="run(row, 'scan')">采集</el-button>
      <el-button link :disabled="!row.enabled || busy === row.id" @click="run(row, 'test')">测试</el-button>
      <el-button link @click="router.push({ path: '/asset-inventory', query: { owner_key: `file-source:${row.id}` } })">资产</el-button>
      <el-button link @click="edit(row)">配置</el-button>
      <el-button link type="danger" :disabled="busy === row.id" @click="remove(row)">删除</el-button>
    </template></el-table-column>
  </el-table>
  <el-pagination :current-page="page" :total="total" :page-size="50" layout="total, prev, pager, next" @current-change="load" />
  <el-drawer v-model="open" :title="editing ? '配置文件源' : '添加文件源'" size="560px">
    <el-form label-width="110px" size="small">
      <el-form-item label="名称"><el-input v-model="form.name" /></el-form-item>
      <el-form-item label="协议"><el-select v-model="form.protocol" :disabled="!!editing" @change="form.port = form.protocol === 'sftp' ? 22 : 21"><el-option v-for="p in ['ftp','ftps','sftp']" :key="p" :label="p.toUpperCase()" :value="p" /></el-select></el-form-item>
      <el-form-item label="地址"><el-input v-model="form.host" :disabled="!!editing" /></el-form-item>
      <el-form-item label="端口"><el-input-number v-model="form.port" :min="1" :max="65535" :disabled="!!editing" /></el-form-item>
      <el-form-item label="根目录"><el-input v-model="form.root_path" /><span class="muted">改目录不需要新建来源；移出目录的文件只会标记「未再观测」</span></el-form-item>
      <el-form-item label="用户名"><el-input v-model="form.username" /></el-form-item>
      <el-form-item label="密码"><el-input v-model="form.password" type="password" show-password :placeholder="editing ? '留空保持原密码' : ''" autocomplete="new-password" /></el-form-item>
      <el-form-item v-if="form.protocol === 'sftp'" label="主机指纹"><el-input v-model="form.host_key_sha256" placeholder="SHA256:…（从服务器管理员处获取）" /></el-form-item>
      <el-form-item label="启用"><el-switch v-model="form.enabled" /></el-form-item>
      <el-form-item label="周期（分钟）"><el-input-number v-model="form.interval_minutes" :min="0" :max="43200" /><span class="muted">0 = 手动</span></el-form-item>
      <el-form-item label="文件数上限"><el-input-number v-model="form.limits.max_files" :min="1" :max="2000" /></el-form-item>
      <el-form-item label="目录深度"><el-input-number v-model="form.limits.max_depth" :min="0" :max="8" /></el-form-item>
      <el-form-item label="时限（秒）"><el-input-number v-model="form.limits.max_seconds" :min="1" :max="900" /></el-form-item>
      <el-alert title="只读读取；临时下载文件检测后清理。FTPS 使用显式 TLS；SFTP 校验主机指纹。协议/地址/端口改动请新建来源（保留原来源历史）；共享目录可随时修改。" type="info" :closable="false" />
      <el-form-item style="margin-top:16px"><el-button type="primary" :loading="saving" @click="save">保存</el-button></el-form-item>
    </el-form>
  </el-drawer>
</template>
<style scoped>.muted { color:var(--soc-text-dim); font-size:12px; margin:4px 8px 4px 0; } .el-pagination { margin-top:12px; }</style>
