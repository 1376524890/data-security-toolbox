<script setup lang="ts">
import JsonViewer from '../../components/evidence/JsonViewer.vue'
import HexViewer from '../../components/evidence/HexViewer.vue'
import { downloadUrl } from '../../api/client'
import { useNetworkDlp } from './composables/useNetworkDlp'

// The policy, the transfers and the rule catalogue live in the composable;
// this view only binds them into the template below.
const {
  config, keywords, hashes, cidrs, error, busy, items, coverage, selected, drawer,
  binary, binaryError, binaryLoading, rules, ruleDialog, ruleBusy, newRule,
  openTransfer, alertableHit, matchedText, hasMatchedText, toggleRule, addRule, importPresidio, load, save,
} = useNetworkDlp()
</script>
<template>
  <div v-loading="busy">
    <el-alert title="旁路防泄密检测：重组明文 TCP，识别 HTTP 上传 / 下载、表单、文件指纹及敏感内容。生成告警，不直接阻断；不解密 HTTPS。" type="info" :closable="false" style="margin-bottom:16px" />
    <el-alert v-if="error" :title="error" type="error" />
    <div class="toolbar" style="margin:16px 0"><b>现有规则库（{{rules.length}}）</b><div class="toolbar-spacer" />
      <el-button :loading="ruleBusy" @click="importPresidio">下载 / 更新 Presidio 规则库并导入</el-button>
      <el-button type="primary" @click="ruleDialog=true">手动添加规则</el-button>
    </div>
    <el-alert title="Presidio 导入官方静态正则，不包含 NLP、上下文评分和 Python 校验器；置信度低于告警阈值的规则默认停用，可按业务启用。IP、MAC、日期等定位符与弱规则只作为传输证据，不会单独触发告警；重新导入 Presidio 可刷新各规则置信度。所有变更对后续分析生效。" type="info" :closable="false" />
    <el-table :data="rules" max-height="320" size="small">
      <el-table-column prop="name" label="规则名称" min-width="220" />
      <el-table-column prop="source" label="来源" width="100" />
      <el-table-column prop="entity" label="敏感类别" min-width="140" />
      <el-table-column prop="confidence" label="置信度" width="90" />
      <el-table-column label="可告警" width="90"><template #default="{row}"><el-tag :type="row.alertable ? 'success' : 'info'" size="small">{{row.alertable ? '是' : '仅证据'}}</el-tag></template></el-table-column>
      <el-table-column label="启用" width="80"><template #default="{row}"><el-switch :model-value="row.enabled" @change="(value: boolean | string | number)=>toggleRule(row, Boolean(value))" /></template></el-table-column>
      <el-table-column prop="pattern" label="正则表达式" min-width="260" show-overflow-tooltip />
    </el-table>
    <el-dialog v-model="ruleDialog" title="添加防泄密规则" width="650px">
      <el-form label-width="100px">
        <el-form-item label="规则名称"><el-input v-model="newRule.name" maxlength="200" /></el-form-item>
        <el-form-item label="敏感类别"><el-input v-model="newRule.entity" placeholder="例如：INTERNAL_DOCUMENT" /></el-form-item>
        <el-form-item label="正则表达式"><el-input v-model="newRule.pattern" type="textarea" :rows="5" placeholder="例如：内部编号：[A-Z]{2}-[0-9]{6}" /></el-form-item>
        <el-form-item label="立即启用"><el-switch v-model="newRule.enabled" /></el-form-item>
      </el-form>
      <template #footer><el-button @click="ruleDialog=false">取消</el-button><el-button type="primary" :loading="ruleBusy" @click="addRule">校验并保存</el-button></template>
    </el-dialog>
    <el-collapse><el-collapse-item title="检测策略" name="policy">
      <el-form label-width="120px">
        <el-form-item label="开启检测"><el-switch v-model="config.enabled" /></el-form-item>
        <el-form-item label="敏感类别"><el-checkbox-group v-model="config.categories"><el-checkbox v-for="item in [['phone','手机号'],['id_card','身份证'],['email','邮箱'],['bank_card','银行卡'],['api_key','API 密钥'],['token','长 Token']]" :key="item[0]" :value="item[0]">{{item[1]}}</el-checkbox></el-checkbox-group></el-form-item>
        <el-form-item label="最少命中次数"><el-input-number v-model="config.min_matches" :min="1" :max="1000" /></el-form-item>
        <el-form-item label="告警最低置信度"><el-input-number v-model="config.min_confidence" :min="0" :max="1" :step="0.05" :precision="2" /><span style="margin-left:8px;color:var(--el-text-color-secondary)">命中置信度低于该值的规则只记录证据，不产生告警</span></el-form-item>
        <el-form-item label="忽略网段"><el-input v-model="cidrs" type="textarea" :rows="3" placeholder="每行一个网段，例如：127.0.0.0/8；回环、链路本地与组播地址始终忽略" /></el-form-item>
        <el-form-item label="敏感关键词"><el-input v-model="keywords" type="textarea" :rows="3" placeholder="每行一个关键词，例如：内部机密" /></el-form-item>
        <el-form-item label="文件 SHA256"><el-input v-model="hashes" type="textarea" :rows="3" placeholder="每行一个受保护文件的 SHA256，完整文件传输时精确匹配" /></el-form-item>
        <el-form-item><el-button type="primary" @click="save">保存策略</el-button></el-form-item>
      </el-form>
    </el-collapse-item></el-collapse>
    <div style="margin:16px 0"><b>传输对象与匹配结果</b><el-button style="float:right" @click="load">刷新</el-button></div>
    <el-table :data="items" size="small" @row-click="openTransfer">
      <el-table-column prop="pcap_id" label="PCAP" width="70" />
      <el-table-column prop="filename" label="对象 / 文件" min-width="170" show-overflow-tooltip />
      <el-table-column label="传输方向" min-width="230"><template #default="{row}">{{row.src_ip}}:{{row.src_port}} → {{row.dst_ip}}:{{row.dst_port}}</template></el-table-column>
      <el-table-column prop="sha256" label="SHA256（捕获内容）" min-width="200" show-overflow-tooltip />
      <el-table-column prop="size" label="字节数" width="90" />
      <el-table-column label="完整性" width="100"><template #default="{row}">{{row.complete ? '完整' : '部分 / 未确认'}}</template></el-table-column>
      <el-table-column label="命中" min-width="220"><template #default="{row}"><el-tag v-for="(hit,index) in row.matches" :key="index" :type="alertableHit(hit) ? 'danger' : 'info'" size="small">{{hit.kind}} × {{hit.count}}{{alertableHit(hit) ? '' : '（仅证据）'}}</el-tag><span v-if="hasMatchedText(row)" class="text-dim" style="margin-left:6px">可查看传输原文</span><span v-if="!row.matches.length">未命中当前策略</span></template></el-table-column>
    </el-table>
    <el-empty v-if="!items.length" description="上传并分析 PCAP 后显示传输内容；也可导入演示场景" />
    <el-collapse style="margin-top:16px"><el-collapse-item title="检测覆盖范围与截断信息"><JsonViewer :value="coverage" /></el-collapse-item></el-collapse>
    <el-drawer v-model="drawer" title="传输文件证据" size="70%">
      <template v-if="selected">
        <el-descriptions :column="1" border>
          <el-descriptions-item label="SHA256"><span style="overflow-wrap:anywhere">{{selected.sha256}}</span></el-descriptions-item>
          <el-descriptions-item label="哈希范围">{{selected.complete ? '完整重组文件' : '已捕获片段，不能作为完整文件哈希'}}</el-descriptions-item>
        </el-descriptions>
        <div style="margin:16px 0">
          <b>命中原文</b>
          <el-alert type="info" :closable="false" style="margin:8px 0" title="命中处的原文（每命中最多 3 条，value ≤120 字符、上下文 ≤240 字符），与敏感发现的证据出口同一上限；仅命中字段名/关键字而没有取值的规则不会给出原文。" />
          <el-table v-if="matchedText(selected).length" :data="matchedText(selected)" size="small" max-height="260">
            <el-table-column prop="kind" label="匹配类型" width="130" show-overflow-tooltip />
            <el-table-column prop="count" label="命中次数" width="90" />
            <el-table-column prop="ruleId" label="规则 ID" min-width="150" show-overflow-tooltip />
            <el-table-column prop="source" label="来源" width="120" show-overflow-tooltip />
            <el-table-column label="命中值" min-width="180"><template #default="{row}"><span class="mono">{{row.value}}</span></template></el-table-column>
            <el-table-column label="上下文" min-width="240"><template #default="{row}"><span class="mono">{{row.context || '（无上下文）'}}</span></template></el-table-column>
          </el-table>
          <div v-else class="text-dim">该传输没有可回传的原文（旧分析，或只命中了字段名/关键字）。</div>
        </div>
        <div v-if="selected.binary_available" style="margin:16px 0">
          <el-link :href="downloadUrl(`/dlp/transfers/${selected.task_id}/${selected.id}/content?download=true`)" type="primary">下载捕获二进制（{{selected.size}} 字节）</el-link>
          <p>原始字节预览（最多 4096 字节，未脱敏）</p>
          <el-alert v-if="binaryError" :title="binaryError" type="error" />
          <div v-loading="binaryLoading" style="max-height:360px;overflow:auto"><HexViewer :data="binary" /></div>
        </div>
        <el-alert v-else title="未保留二进制证据；敏感传输的历史 PCAP 需重新分析。" type="info" />
        <JsonViewer :value="selected" />
      </template>
    </el-drawer>
  </div>
</template>
