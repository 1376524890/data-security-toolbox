<script setup lang="ts">
/**
 * 地理位置态势 — 内网 / 国内 / 境外 on the wall.
 *
 * The China map carries 国内 plus the enterprise's own address space as one
 * labelled hub (private ranges have no geography, so drawing them per host
 * would be a claim nobody measured) and the globe carries 境外. Every marker is
 * one region/country group from ``GET /dashboard/geo-map``, sized by volume and
 * coloured by the highest data-classification level detected on any host in
 * that group - the colour is a fact about the data, not a guess about the link.
 *
 * The geometry lives in ``../geoProjection``; this view only binds it.
 */
import { computed } from 'vue'
import { formatBytes } from '../../../utils/format'
import type { GeoDistribution, GeoPoint } from '../../../types/dashboard'
import {
  CHINA_ISLANDS, CHINA_MAINLAND, CHINA_BOUNDS, dotGrid, globeMeridians, globeParallel, outlinePath,
  projectEquirectangular, projectGlobe,
} from '../geoProjection'
import { sensitivityColors } from '../chartTheme'

const props = defineProps<{ geo: GeoDistribution | null }>()

// Design sizes: the panel is laid out once at the wall's resolution and merely
// scaled, exactly like every other card on the screen.
const CHINA = { width: 430, height: 250 }
const GLOBE = { width: 430, height: 250, radius: 104 }
//: The longitude the globe faces when nothing has been classified as 境外 yet.
const GLOBE_DEFAULT_LON = 105
const PARALLELS = [60, 30, 0, -30, -60]

/** The enterprise's own address space, drawn as one schematic hub: RFC1918 has
 *  no location, so it sits over open water and the note below says so. */
const INTERNAL_HUB = projectEquirectangular(84.5, 19.0, CHINA.width, CHINA.height)

interface Placed { point: GeoPoint; x: number; y: number; r: number }
/** A globe placement also knows whether it is on the drawn hemisphere. */
interface GlobePlaced extends Placed { visible: boolean }

const mainlandPath = computed(() => outlinePath(CHINA_MAINLAND, CHINA.width, CHINA.height))
const islandPaths = computed(() =>
  CHINA_ISLANDS.map((island) => outlinePath(island, CHINA.width, CHINA.height)))
const dots = computed(() => dotGrid(CHINA.width, CHINA.height))
const meridians = computed(() => globeMeridians(GLOBE.radius))
const parallels = computed(() =>
  PARALLELS.map((lat) => ({ lat, ...globeParallel(lat, GLOBE.radius, GLOBE.height / 2) })))

const points = computed<GeoPoint[]>(() => props.geo?.points || [])
const regions = computed(() => props.geo?.regions || [])
const totals = computed(() => props.geo?.totals || null)
const levels = computed(() => props.geo?.levels || [])
const unrated = computed(() => props.geo?.unrated_label || '未评级')

/** The server's level table, so a marker caption reads exactly like the legend. */
const levelNames = computed(() => Object.fromEntries(
  levels.value.map((level) => [level.key, level.name])))

/** A group's caption: the level table names a rated group, the honest label
 *  names an unrated one - never a bare code with nothing behind it. */
function levelText(point: GeoPoint): string {
  if (!point.level) return point.level_label || unrated.value
  return `${point.level} ${levelNames.value[point.level] || point.level}`
}

/** Marker area by volume: the eye should find the busiest destination first. */
const maxBytes = computed(() => Math.max(1, ...points.value.map((item) => item.bytes)))
function radiusOf(point: GeoPoint): number {
  return 3 + 7 * (Math.log(1 + point.bytes) / Math.log(1 + maxBytes.value))
}

function colorOf(point: GeoPoint): string {
  return sensitivityColors[point.level] || sensitivityColors.unknown
}

/** 内网 has no geography - private ranges are the enterprise's own space - so
 *  it is one schematic hub and every link starts from it. */
interface Hub { x: number; y: number; r: number; point: GeoPoint | null }

/**
 * The globe can only face one way, and the fixed 105°E centre pointed away from
 * where the data actually went: a US address sat on the far side and was dropped
 * from the panel with nothing said about it. The view now turns to the busiest
 * 境外 destination - which is the one an operator needs to see - and the
 * destinations still behind the globe are counted in the note rather than lost.
 */
const overseasPoints = computed(() => points.value.filter(
  (item) => item.region === 'overseas' && item.lat !== null && item.lon !== null))

const globeView = computed(() => {
  const busiest = [...overseasPoints.value].sort((a, b) => b.bytes - a.bytes)[0]
  return {
    lat: 0,
    lon: busiest ? Number(busiest.lon) : GLOBE_DEFAULT_LON,
    radius: GLOBE.radius,
    cx: GLOBE.width / 2,
    cy: GLOBE.height / 2,
  }
})

/** The globe's hub sits at the middle of the drawn disc: a fixed geographic
 *  guess would fall off the back as soon as the globe turned, and 内网 has no
 *  geography to be right about. The marker is labelled 内网（示意）. */
const globeHub = computed(() => ({ x: GLOBE.width / 2, y: GLOBE.height / 2 }))

const hub = computed<Hub | null>(() => {
  const internal = points.value.find((item) => item.region === 'internal')
  const hasTargets = points.value.some((item) => item.region !== 'internal')
  if (!internal && !hasTargets) return null
  return {
    x: INTERNAL_HUB.x,
    y: INTERNAL_HUB.y,
    r: internal ? radiusOf(internal) : Math.max(4, radiusOf(points.value[0]) - 2),
    point: internal || null,
  }
})

/** The hub's caption states its own numbers when the server sent a 内网 group
 *  and says it is schematic when it did not - a caption must not invent hosts. */
const hubCaption = computed(() => (hub.value?.point
  ? `${hub.value.point.region_label} ${hostText(hub.value.point)}` : '内网（示意）'))
const hubLevel = computed(() => (hub.value?.point ? levelText(hub.value.point) : '链路起点'))

/** 国内 sits on the country's label point from the same shared table. */
const domesticMarkers = computed<Placed[]>(() => {
  const domestic = points.value.find((item) => item.region === 'domestic')
  if (!domestic || domestic.lat === null || domestic.lon === null) return []
  const at = projectEquirectangular(domestic.lon, domestic.lat, CHINA.width, CHINA.height)
  return [{ point: domestic, x: at.x, y: at.y, r: radiusOf(domestic) }]
})

/** A link is "the enterprise sent this much data to this place": the server
 *  resolves a country per destination and no position per host, so drawing a
 *  host-to-host line would claim a geometry nobody measured. Width is the
 *  volume, colour is the destination's sensitivity - the same two readings as
 *  the markers, so the line and the dot cannot disagree. */
function linkPath(from: { x: number; y: number }, to: { x: number; y: number }): string {
  const dx = to.x - from.x
  const dy = to.y - from.y
  const length = Math.hypot(dx, dy) || 1
  const bow = Math.min(16, length * 0.16)
  const cx = (from.x + to.x) / 2 - (dy / length) * bow
  const cy = (from.y + to.y) / 2 + (dx / length) * bow
  return `M ${from.x.toFixed(1)} ${from.y.toFixed(1)}`
    + ` Q ${cx.toFixed(1)} ${cy.toFixed(1)} ${to.x.toFixed(1)} ${to.y.toFixed(1)}`
}

const maxLinkBytes = computed(() => Math.max(1, ...points.value.map((item) => item.bytes)))
function linkWidth(point: GeoPoint): number {
  return 0.8 + 3.2 * (Math.log(1 + point.bytes) / Math.log(1 + maxLinkBytes.value))
}

interface FlowLine { key: string; path: string; width: number; color: string; title: string }

function linesTo(targets: Placed[], origin: { x: number; y: number }): FlowLine[] {
  return targets.map((target) => ({
    key: target.point.id,
    path: linkPath(origin, target),
    width: linkWidth(target.point),
    color: colorOf(target.point),
    title: `${hub.value?.point?.region_label || '内网'} → `
      + `${target.point.country_name || target.point.region_label} · `
      + `${hostText(target.point)} · ${levelText(target.point)}`,
  }))
}

const chinaLinks = computed(() =>
  (hub.value ? linesTo(domesticMarkers.value, hub.value) : []))

/** The globe is drawn from the equator, so a marker on the far side is folded
 *  away rather than drawn on the wrong hemisphere. */
const globePlaced = computed<GlobePlaced[]>(() =>
  overseasPoints.value.map((item) => {
    const at = projectGlobe(Number(item.lat), Number(item.lon), globeView.value)
    return { point: item, x: at.x, y: at.y, r: radiusOf(item), visible: at.visible }
  }))

const globeDots = computed<GlobePlaced[]>(() => globePlaced.value.filter((item) => item.visible))

/** Destinations on the far side of the globe: not drawn, but not ignored. */
const globeHidden = computed(() => globePlaced.value.length - globeDots.value.length)

const globeLinks = computed(() => linesTo(globeDots.value, globeHub.value))

const globeLabels = computed(() =>
  [...globeDots.value]
    .sort((a, b) => b.point.bytes - a.point.bytes)
    .slice(0, 4)
    .map((item) => ({
      ...item,
      text: `${item.point.country_name || item.point.country} ${item.point.hosts}`,
      anchor: item.x >= GLOBE.width / 2 ? 'start' : 'end',
      dx: item.x >= GLOBE.width / 2 ? 7 : -7,
    })))

/** Groups the region table could not place: reported in the note rather than
 *  dropped, because "we could not place it" is not "there was nothing there". */
const unplaced = computed(() =>
  points.value.filter(
    (item) => item.region === 'unknown' || (item.region === 'overseas' && item.lat === null)))

function hostText(point: GeoPoint): string {
  return `${point.hosts} 主机 · ${formatBytes(point.bytes)}`
}
</script>

<template>
  <section class="ds-panel ds-geo">
    <div class="ds-panel-head">
      <span class="ds-panel-title">地理位置态势</span>
      <div class="ds-legend">
        <span v-for="level in levels" :key="level.key" class="ds-legend-item">
          <i :style="{ background: sensitivityColors[level.key] }" />{{ level.key }} {{ level.name }}
        </span>
        <span class="ds-legend-item">
          <i :style="{ background: sensitivityColors.unknown }" />{{ unrated }}
        </span>
      </div>
    </div>

    <div class="ds-panel-body">
      <div v-if="!points.length" class="ds-empty">
        <div>暂无地址分布数据<span>分析完成的 PCAP 会话会按目的地址汇聚到这里</span></div>
      </div>

      <template v-else>
        <!-- 中国地图：国内 + 本企业私网 -->
        <div class="ds-geo-half">
          <svg class="ds-geo-svg" :viewBox="`0 0 ${CHINA.width} ${CHINA.height}`"
               preserveAspectRatio="xMidYMid meet" role="img" aria-label="中国地图：国内与本企业内网">
            <path :d="mainlandPath" class="ds-geo-land" />
            <path v-for="(island, index) in islandPaths" :key="`i${index}`" :d="island" class="ds-geo-land" />
            <circle v-for="(dot, index) in dots" :key="`d${index}`" :cx="dot.x" :cy="dot.y"
                    r="1" class="ds-geo-dot" />
            <!-- 数据流动链路：内网 -> 每个目的国家/地区，粗细是数据量、颜色是敏感等级 -->
            <path v-for="line in chinaLinks" :key="line.key" :d="line.path"
                  class="ds-geo-link ds-geo-flow" :stroke="line.color" :stroke-width="line.width">
              <title>{{ line.title }}</title>
            </path>
            <g v-if="hub" :transform="`translate(${hub.x} ${hub.y})`">
              <circle :r="hub.r + 6"
                      :fill="hub.point ? colorOf(hub.point) : sensitivityColors.unknown"
                      class="ds-geo-halo" />
              <circle :r="hub.r"
                      :fill="hub.point ? colorOf(hub.point) : sensitivityColors.unknown"
                      class="ds-geo-marker" />
              <text x="14" y="4" class="ds-geo-label">{{ hubCaption }}</text>
              <text x="14" y="17" class="ds-geo-sublabel">{{ hubLevel }}</text>
            </g>
            <g v-for="marker in domesticMarkers" :key="marker.point.id"
               :transform="`translate(${marker.x} ${marker.y})`">
              <circle :r="marker.r + 6" :fill="colorOf(marker.point)" class="ds-geo-halo" />
              <circle :r="marker.r" :fill="colorOf(marker.point)" class="ds-geo-marker" />
              <text x="14" y="4" class="ds-geo-label">
                {{ marker.point.region_label }} {{ hostText(marker.point) }}
              </text>
              <text x="14" y="17" class="ds-geo-sublabel">
                {{ levelText(marker.point) }}
              </text>
            </g>
            <text v-if="!hub && !domesticMarkers.length" :x="CHINA.width - 6"
                  :y="CHINA.height - 8" text-anchor="end" class="ds-geo-hint">国内暂无目的地址</text>
            <text :x="CHINA.width - 6" :y="12" text-anchor="end" class="ds-geo-hint">
              地图范围 {{ CHINA_BOUNDS.lonMin }}–{{ CHINA_BOUNDS.lonMax }}°E
            </text>
          </svg>
        </div>

        <!-- 地球：境外 -->
        <div class="ds-geo-half">
          <svg class="ds-geo-svg" :viewBox="`0 0 ${GLOBE.width} ${GLOBE.height}`"
               preserveAspectRatio="xMidYMid meet" role="img" aria-label="地球：境外目的国家">
            <circle :cx="GLOBE.width / 2" :cy="GLOBE.height / 2" :r="GLOBE.radius" class="ds-globe-body" />
            <ellipse v-for="(meridian, index) in meridians" :key="`m${index}`"
                     :cx="GLOBE.width / 2" :cy="GLOBE.height / 2"
                     :rx="meridian.rx" :ry="meridian.ry" class="ds-globe-line" />
            <line v-for="parallel in parallels" :key="`p${parallel.lat}`"
                  :x1="GLOBE.width / 2 - parallel.half" :x2="GLOBE.width / 2 + parallel.half"
                  :y1="parallel.y" :y2="parallel.y" class="ds-globe-line" />
            <path v-for="line in globeLinks" :key="line.key" :d="line.path"
                  class="ds-geo-link ds-geo-flow" :stroke="line.color" :stroke-width="line.width">
              <title>{{ line.title }}</title>
            </path>
            <g v-if="globeDots.length" :transform="`translate(${globeHub.x} ${globeHub.y})`" class="ds-geo-anchor">
              <circle r="5" class="ds-geo-marker ds-geo-hub-outline" />
              <text x="10" y="4" class="ds-geo-sublabel">内网（示意）</text>
            </g>
            <circle v-for="(marker, index) in globeDots" :key="`g${index}`"
                    :cx="marker.x" :cy="marker.y" :r="marker.r"
                    :fill="colorOf(marker.point)" class="ds-geo-marker">
              <title>{{ marker.point.country_name || marker.point.country }} · {{ marker.point.hosts }} 主机 · {{ formatBytes(marker.point.bytes) }}</title>
            </circle>
            <text v-for="(label, index) in globeLabels" :key="`l${index}`"
                  :x="label.x + label.dx" :y="label.y + 3" :text-anchor="label.anchor"
                  class="ds-geo-label">{{ label.text }}</text>
            <text v-if="!globeDots.length" :x="GLOBE.width / 2" :y="GLOBE.height / 2"
                  text-anchor="middle" class="ds-geo-hint">境外暂无已判定目的地址</text>
          </svg>
        </div>
      </template>

      <div v-if="points.length" class="ds-geo-totals">
        <span v-for="region in regions" :key="region.key">
          {{ region.label }} <b>{{ region.hosts }}</b> 主机 / <b>{{ formatBytes(region.bytes) }}</b>
        </span>
      </div>
    </div>

    <div class="ds-geo-note">
      连线是聚合成链路的会话：起点内网（位置为示意），终点是国内/境外的目的国家或地区，粗细是数据量、颜色是敏感等级。
      按目的地址聚合：内网是本企业私网地址段（位置为示意），国内/境外由离线地区表判定，未命中地区表的目的地址不计入「境外」。
      <span v-if="totals"> 会话 {{ totals.sessions }} · 数据包 {{ totals.packets }}</span>
      <span v-if="unplaced.length"> · 未定位 {{ unplaced.length }} 组（无该国家标签点）</span>
      <span v-if="globeHidden"> · 地球背面 {{ globeHidden }} 组未绘制</span>
    </div>
  </section>
</template>

<style scoped>
.ds-panel {
  display: flex; flex-direction: column; height: 100%; min-height: 0; padding: 8px 10px 6px;
  border-radius: 6px; border: 1px solid rgba(53, 160, 255, 0.2); background: rgba(9, 26, 48, 0.86);
  position: relative; overflow: hidden;
}
.ds-panel-head { display: flex; align-items: center; justify-content: space-between; gap: 8px; z-index: 1; }
.ds-panel-title {
  font-size: 13px; font-weight: 600; color: #d7e6f7; letter-spacing: 0.06em;
  padding-left: 10px; position: relative; white-space: nowrap;
}
.ds-panel-title::before {
  content: ''; position: absolute; left: 0; top: 50%; width: 3px; height: 12px;
  transform: translateY(-50%); border-radius: 2px; background: linear-gradient(180deg, #35a0ff, #22d3ee);
}
.ds-legend { display: flex; gap: 10px; font-size: 10px; color: #9ec2e6; flex-wrap: wrap; justify-content: flex-end; }
.ds-legend-item { display: inline-flex; align-items: center; gap: 4px; }
.ds-legend-item i { width: 8px; height: 8px; border-radius: 50%; }
.ds-panel-body { flex: 1; min-height: 0; position: relative; display: flex; gap: 6px; z-index: 1; }
.ds-geo-half { flex: 1; min-width: 0; min-height: 0; }
.ds-geo-svg { width: 100%; height: 100%; display: block; }
.ds-geo-land { fill: rgba(53, 160, 255, 0.09); stroke: rgba(53, 160, 255, 0.42); stroke-width: 0.8; }
.ds-geo-dot { fill: rgba(90, 160, 235, 0.35); }
.ds-globe-body { fill: rgba(18, 58, 100, 0.5); stroke: rgba(53, 160, 255, 0.42); stroke-width: 1; }
.ds-globe-line { fill: none; stroke: rgba(53, 160, 255, 0.18); stroke-width: 0.7; }
.ds-geo-marker { stroke: rgba(6, 20, 36, 0.9); stroke-width: 1; }
.ds-geo-halo { opacity: 0.16; }
/* The link layer sits under the markers. The dashes travel hub -> destination,
   which is the one thing a static line cannot say: which way the data went. */
.ds-geo-link { fill: none; opacity: 0.9; }
.ds-geo-flow { stroke-dasharray: 5 9; animation: ds-geo-flow 1.4s linear infinite; }
.ds-geo-anchor .ds-geo-hub-outline { fill: none; stroke: #9ec2e6; stroke-width: 1; }
@keyframes ds-geo-flow { to { stroke-dashoffset: -14; } }
.ds-geo-label { fill: #bad6f3; font-size: 10px; }
.ds-geo-sublabel { fill: #7f9bc0; font-size: 9px; }
.ds-geo-hint { fill: #4f6b8a; font-size: 10px; }
.ds-geo-totals {
  position: absolute; left: 4px; bottom: 0; display: flex; gap: 12px; flex-wrap: wrap;
  font-size: 10px; color: #7f9bc0; pointer-events: none;
}
.ds-geo-totals b { color: #dbeaf9; font-variant-numeric: tabular-nums; }
.ds-geo-note { margin-top: 2px; font-size: 10px; color: #4f6b8a; z-index: 1; line-height: 1.5; }
.ds-empty { flex: 1; display: grid; place-items: center; text-align: center; font-size: 13px; color: #6f90b3; }
.ds-empty span { display: block; margin-top: 6px; font-size: 11px; color: #4f6b8a; }
</style>
