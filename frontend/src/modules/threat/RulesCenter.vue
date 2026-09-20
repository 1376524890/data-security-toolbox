<script setup lang="ts">
import StateBox from '../../components/common/StateBox.vue'
import StatusBadge from '../../components/security/StatusBadge.vue'
import RawViewer from '../../components/evidence/RawViewer.vue'
import type { RuleItem } from '../../api/rules'
import { useRulesCenter } from './composables/useRulesCenter'

// The inventory, the engine list, the filters and the add dialog live in the
// composable; this view keeps the static execution labels and binds the state
// into the template below.
const {
  loading, error, rules, activeType, activeEngine, engines, keyword, page, dialog, saving, draft,
  openAdd, readRule, saveRule, filtered, visible, types, expandRule, load,
} = useRulesCenter()

const executionLabels: Record<string, string> = {
  active: '已接入执行', external: '待外部部署', unsupported: '语法不兼容', incomplete: '缺少依赖',
}

</script>

<template>
  <div>
    <div class="toolbar">
      <el-select v-model="activeEngine" clearable filterable placeholder="全部引擎" style="width: 230px">
        <el-option v-for="engine in engines" :key="engine.name" :value="engine.name" :label="`${engine.label || engine.name} (${engine.rule_count || 0})`" />
      </el-select>
      <el-select v-model="activeType" clearable placeholder="全部类型" style="width: 150px">
        <el-option v-for="type in types" :key="type" :value="type" :label="type" />
      </el-select>
      <el-input v-model="keyword" clearable placeholder="搜索规则名称或 ID" style="width: 230px" />
      <div class="toolbar-spacer" />
      <el-button type="primary" @click="openAdd">添加 / 导入检查规则</el-button>
    </div>
    <el-dialog v-model="dialog" title="添加检查规则" width="760px">
      <el-form label-width="100px">
        <el-form-item label="规则类型"><el-select v-model="draft.rule_type"><el-option label="Suricata 网络规则" value="suricata" /><el-option label="YARA 文件规则" value="yara" /></el-select></el-form-item>
        <el-form-item label="规则库名称"><el-input v-model="draft.name" placeholder="英文字母、数字、下划线或连字符" maxlength="100" /></el-form-item>
        <el-form-item label="导入文件"><el-upload :auto-upload="false" :show-file-list="false" :on-change="readRule" accept=".rules,.yar,.yara"><el-button>选择本地规则文件</el-button></el-upload></el-form-item>
        <el-form-item label="规则内容"><el-input v-model="draft.content" type="textarea" :rows="12" placeholder="输入完整 Suricata 或 YARA 规则" /></el-form-item>
      </el-form>
      <template #footer><el-button @click="dialog=false">取消</el-button><el-button :loading="saving" type="primary" @click="saveRule">校验并添加</el-button></template>
    </el-dialog>
    <StateBox :loading="loading" :error="error" :empty="!filtered.length" @retry="load">
      <el-table :data="visible" :row-key="(row: RuleItem) => `${row.engine}:${row.path}`" @expand-change="expandRule">
        <el-table-column type="expand"><template #default="{ row }"><RawViewer :value="row.content" language="plaintext" :height="280" /></template></el-table-column>
        <el-table-column prop="name" label="规则 / 文件" min-width="260" show-overflow-tooltip />
        <el-table-column prop="engine" label="引擎" min-width="170" />
        <el-table-column prop="type" label="类型" width="110" />
        <el-table-column label="接入状态" width="140"><template #default="{ row }">{{ executionLabels[row.execution] || '待核实' }}</template></el-table-column>
        <el-table-column prop="size" label="大小 (B)" width="120" />
      </el-table>
      <el-pagination v-model:current-page="page" :page-size="30" :total="filtered.length" layout="total, prev, pager, next" style="margin-top: 12px" />
    </StateBox>
  </div>
</template>

<style scoped>
.rule-card { display: flex; flex-direction: column; gap: 8px; }
.rule-head { display: flex; align-items: center; justify-content: space-between; }
.rule-name { font-weight: 700; color: var(--soc-text-strong); }
.rule-meta { display: flex; gap: 16px; color: var(--soc-text-muted); font-size: 12px; }
.rule-path { color: var(--soc-text-dim); font-size: 11px; word-break: break-all; }
.gap-note { color: var(--soc-warning); font-size: 11px; }
</style>
