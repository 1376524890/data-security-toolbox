<script setup lang="ts">
import { computed } from 'vue'
import StateBox from '../../../components/common/StateBox.vue'
import StatCard from '../../../components/common/StatCard.vue'
import HexViewer from '../../../components/evidence/HexViewer.vue'
import JsonViewer from '../../../components/evidence/JsonViewer.vue'
import { downloadUrl } from '../../../api/client'
import type { Packet } from '../../../types/pcap'
import { useEgressDetail } from './composables/useEgressDetail'

// 数据出境报告: where the traffic went, and — for every transfer — whether the
// content was sensitive, which rule caught it, which file it was, and the actual
// packets behind it. All state (including the packet paging of the selected
// flow) lives in the composable.
const {
  loading, error, data, transfers, buckets, regions, rules, policy, sensitiveCount,
  selected, drawer, packets, packetTotal, packetsLoading, packetsNote, detail,
  load, open, loadPackets, openPacket, matchedValues,
} = useEgressDetail()

const bucketLabels: Record<string, string> = {
  internal: '内网', whitelist: '白名单', blacklist: '黑名单', country: '可判定出境', unknown: '未识别',
}
const outgoing = computed(() => transfers.value.filter(
  (row) => row.bucket === 'country' || row.bucket === 'blacklist'))

function flowText(row: { src_ip: string; src_port: number; dst_ip: string; dst_port: number }): string {
  return `${row.src_ip}:${row.src_port} → ${row.dst_ip}:${row.dst_port}`
}
</script>

<template>
  <StateBox :loading="loading" :error="error" :empty="!data" @retry="load">
    <template v-if="data">
      <div class="soc-card conclusion">
        <el-icon><InfoFilled /></el-icon>
        <div><strong>{{ data.title }}</strong><div class="muted">{{ data.conclusion }}</div></div>
      </div>

      <div class="stat-grid cols-4" style="margin-top: 12px">
        <StatCard v-for="item in data.kpis" :key="item.key" :label="item.label"
                  :value="String(item.value)"
                  :sub="`分母 ${item.denominator}${item.unit ? ' ' + item.unit : ''}`"
                  :tone="item.tone as never" />
      </div>

      <div class="grid cols-2" style="margin-top: 12px">
        <div v-if="buckets" class="soc-card">
          <div class="soc-card-title"><span class="dot warn" />出境判定</div>
          <el-descriptions :column="3" border size="small">
            <el-descriptions-item v-for="(count, bucket) in buckets" :key="bucket"
                                  :label="bucketLabels[String(bucket)] || String(bucket)">
              {{ count }}
            </el-descriptions-item>
          </el-descriptions>
        </div>
        <div class="soc-card">
          <div class="soc-card-title"><span class="dot" />命中的敏感规则</div>
          <el-table :data="rules" size="small" max-height="200" empty-text="未命中任何规则">
            <el-table-column prop="rule_id" label="规则" min-width="160" />
            <el-table-column prop="objects" label="涉及对象" width="100" />
          </el-table>
        </div>
      </div>

      <div class="soc-card" style="margin-top: 12px">
        <div class="soc-card-title"><span class="dot danger" />传输对象、敏感信息与报文</div>
        <div class="muted toolbar-line">
          共 {{ transfers.length }} 个对象，其中 {{ sensitiveCount }} 个命中敏感规则，
          {{ outgoing.length }} 个为可判定外发；点击行可查看具体流量、报文与命中的规则原文。
        </div>
        <el-table :data="transfers" size="small" max-height="440" @row-click="open">
          <el-table-column prop="pcap_id" label="抓包" width="80" />
          <el-table-column prop="filename" label="对象" min-width="150" show-overflow-tooltip />
          <el-table-column label="流量" min-width="230">
            <template #default="{ row }"><span class="mono">{{ flowText(row) }}</span></template>
          </el-table-column>
          <el-table-column label="目的判定" width="140">
            <template #default="{ row }">
              <el-tag size="small" :type="row.bucket === 'blacklist' ? 'danger'
                : row.bucket === 'country' ? 'warning' : 'info'">
                {{ bucketLabels[row.bucket] || row.bucket }}
              </el-tag>
              <div v-if="row.region" class="muted">{{ row.region }}</div>
            </template>
          </el-table-column>
          <el-table-column label="敏感信息" width="120">
            <template #default="{ row }">
              <el-tag size="small" :type="row.sensitive ? 'danger' : 'info'">
                {{ row.sensitive ? `${row.hit_count} 次命中` : '未发现' }}
              </el-tag>
            </template>
          </el-table-column>
          <el-table-column label="命中规则" min-width="180">
            <template #default="{ row }">
              <el-tag v-for="rule in row.rule_ids" :key="rule" size="small" style="margin: 2px">{{ rule }}</el-tag>
              <span v-if="!row.rule_ids.length" class="muted">—</span>
            </template>
          </el-table-column>
          <el-table-column prop="size" label="字节" width="90" />
          <el-table-column label="对应文件" min-width="160">
            <template #default="{ row }">
              <el-tag v-if="row.file_bound" size="small" type="success">
                {{ row.files[0].name || row.files[0].path }}
              </el-tag>
              <span v-else class="muted">未匹配到已盘点文件</span>
            </template>
          </el-table-column>
        </el-table>
        <el-empty v-if="!transfers.length"
                  description="尚无传输对象；下发监测任务抓包后自动产生" />
      </div>

      <el-collapse style="margin-top: 12px">
        <el-collapse-item title="口径与缺口">
          <el-table :data="data.gaps" size="small" empty-text="无">
            <el-table-column prop="label" label="项" width="150" />
            <el-table-column prop="status" label="状态" width="120" />
            <el-table-column prop="detail" label="说明" min-width="240" show-overflow-tooltip />
          </el-table>
          <div class="muted" style="margin-top: 8px">
            出境判定名单：白名单 {{ (policy.whitelist as unknown[] || []).length }} 条 ·
            黑名单 {{ (policy.blacklist as unknown[] || []).length }} 条 ·
            内网网段 {{ (policy.internal_cidrs as unknown[] || []).length }} 条
          </div>
          <ul class="notes"><li v-for="(note, index) in data.caliber.notes" :key="index">{{ note }}</li></ul>
        </el-collapse-item>
      </el-collapse>
    </template>
  </StateBox>

  <el-drawer v-model="drawer" title="出境对象：流量、报文与敏感信息" size="72%">
    <template v-if="selected">
      <el-descriptions :column="2" border size="small">
        <el-descriptions-item label="流量">
          <span class="mono">{{ flowText(selected) }}</span>
        </el-descriptions-item>
        <el-descriptions-item label="抓包 / 任务">
          #{{ selected.pcap_id ?? '—' }} / #{{ selected.task_id }}
        </el-descriptions-item>
        <el-descriptions-item label="对象">{{ selected.filename || '未命名对象' }}</el-descriptions-item>
        <el-descriptions-item label="大小 / 完整性">
          {{ selected.size }} 字节 · {{ selected.complete ? '完整重组' : '片段（不能作为完整文件哈希）' }}
        </el-descriptions-item>
        <el-descriptions-item label="内容类型">{{ selected.content_type || '未知' }}</el-descriptions-item>
        <el-descriptions-item label="目的判定">
          {{ bucketLabels[selected.bucket] || selected.bucket }}{{ selected.reason ? `（${selected.reason}）` : '' }}
        </el-descriptions-item>
        <el-descriptions-item label="SHA256" :span="2"><span class="wrap">{{ selected.sha256 }}</span></el-descriptions-item>
      </el-descriptions>

      <div class="section-title">是否包含敏感信息</div>
      <el-alert v-if="!selected.sensitive" type="success" :closable="false"
                title="该对象的已捕获内容未命中任何敏感规则（不解密 TLS，加密通道内的内容不可见）" />
      <template v-else>
        <el-alert type="warning" :closable="false"
                  :title="`命中 ${selected.hit_count} 处敏感信息，规则：${selected.rule_ids.join('、') || '未回传规则编号'}`" />
        <el-table :data="matchedValues(selected)" size="small" style="margin-top: 8px"
                  empty-text="规则命中但未回传原文（FIELD_ONLY 类型不计入敏感值命中）">
          <el-table-column prop="kind" label="类别" width="120" />
          <el-table-column prop="ruleId" label="规则" min-width="140" />
          <el-table-column prop="value" label="命中值" min-width="170" />
          <el-table-column prop="context" label="上下文" min-width="240" show-overflow-tooltip />
        </el-table>
      </template>

      <div class="section-title">对应文件</div>
      <el-alert v-if="!selected.file_bound" type="info" :closable="false"
                title="内容未匹配到已盘点的文件（可能来自未纳入盘点范围的目录，或只是片段）" />
      <el-table v-else :data="selected.files" size="small">
        <el-table-column prop="name" label="文件" min-width="160" show-overflow-tooltip />
        <el-table-column prop="path" label="路径" min-width="240" show-overflow-tooltip />
        <el-table-column prop="host" label="主机" width="130" />
        <el-table-column prop="sensitivity" label="敏感级" width="90" />
      </el-table>

      <div class="section-title">原始报文（解析）</div>
      <div class="muted" style="margin-bottom: 6px">{{ packetsNote }}</div>
      <div class="toolbar" v-if="selected.pcap_id">
        <el-button size="small" :disabled="!selected.binary_available"
                   @click="downloadUrl(`/dlp/transfers/${selected.task_id}/${selected.object_id}/content?download=true`)">
          下载对象二进制证据
        </el-button>
        <span class="muted">共 {{ packetTotal }} 个报文</span>
        <div class="toolbar-spacer" />
        <el-button size="small" @click="loadPackets(1)">刷新报文</el-button>
      </div>
      <el-table v-loading="packetsLoading" :data="packets" size="small" max-height="260"
                style="margin-top: 8px" @row-click="openPacket">
        <el-table-column prop="number" label="#" width="70" />
        <el-table-column prop="protocol" label="协议" width="90" />
        <el-table-column label="方向" min-width="220">
          <template #default="{ row }">{{ row.src_ip }}:{{ row.src_port }} → {{ row.dst_ip }}:{{ row.dst_port }}</template>
        </el-table-column>
        <el-table-column prop="length" label="长度" width="80" />
        <el-table-column prop="info" label="摘要" min-width="240" show-overflow-tooltip />
      </el-table>
      <template v-if="detail">
        <div class="section-title">报文 #{{ detail.packet.number }} 解析</div>
        <el-descriptions :column="2" border size="small">
          <el-descriptions-item v-for="layer in detail.layers" :key="layer.name" :label="layer.name" :span="2">
            <span v-for="item in layer.items" :key="item.label" class="layer-item">
              <span class="muted">{{ item.label }}</span> {{ item.value }}
            </span>
          </el-descriptions-item>
        </el-descriptions>
        <div class="section-title">原始字节</div>
        <HexViewer v-if="detail.raw" :data="detail.raw" />
        <span v-else class="muted">该报文没有保留原始字节</span>
      </template>
    </template>
  </el-drawer>
</template>

<style scoped>
.conclusion { display: flex; gap: 10px; align-items: flex-start; }
.muted { color: var(--soc-text-dim); font-size: 12px; }
.mono { font-family: var(--soc-mono, monospace); font-size: 12px; }
.section-title { font-weight: 600; margin: 14px 0 8px; }
.toolbar-line { margin-bottom: 8px; line-height: 1.6; }
.wrap { overflow-wrap: anywhere; }
.layer-item { margin-right: 14px; }
.notes { color: var(--soc-text-dim); font-size: 12px; margin: 10px 0 0; padding-left: 18px; line-height: 1.6; }
:deep(.el-table__row) { cursor: pointer; }
</style>
