/**
 * Geometry for the 大屏's 内网/国内/境外 map.
 *
 * The platform ships no map data and reaches no CDN (the deployment is
 * offline), so the two shapes this panel draws are built here from a simplified
 * outline and a projection - not from a downloaded GeoJSON. That keeps the
 * bundle self-contained and every figure deterministic.
 *
 * What the panel may and may not claim: the classifier resolves a *country*,
 * never a place inside it, so the map draws one marker per region/country group
 * at that country's label point. Hosts inside the enterprise's own address
 * space have no geography at all - they are drawn as one schematic hub, and the
 * panel says so.
 */

export type LonLat = [number, number]

export interface LonLatBounds {
  lonMin: number
  lonMax: number
  latMin: number
  latMax: number
}

/** The window the China map is drawn in: the mainland plus the islands. */
export const CHINA_BOUNDS: LonLatBounds = {
  lonMin: 72.5, lonMax: 136.5, latMin: 17.0, latMax: 54.5,
}

/**
 * Mainland outline, clockwise from the northernmost point (Mohe), simplified to
 * the points a wall display can show. The border is drawn to about a degree -
 * this is a situational map, not a survey: no operator decision rests on a
 * coastline pixel, and inventing detail that was never measured would be worse
 * than a coarse but honest outline.
 */
export const CHINA_MAINLAND: LonLat[] = [
  [122.3, 53.5], [125.5, 52.0], [127.5, 50.2], [130.0, 48.5], [133.5, 48.3],
  [134.8, 48.4], [133.5, 45.5], [131.5, 44.5], [131.2, 43.0], [130.5, 42.5],
  [128.0, 42.0], [126.0, 41.0], [124.4, 40.0], [122.2, 39.4], [121.2, 40.6],
  [118.2, 39.2], [117.6, 38.4], [119.2, 37.4], [122.7, 37.4], [120.8, 36.0],
  [119.5, 35.0], [120.3, 34.3], [121.9, 30.9], [121.6, 29.9], [120.5, 27.5],
  [119.5, 25.5], [117.5, 24.0], [115.0, 22.7], [113.8, 22.5], [113.0, 21.8],
  [110.5, 21.0], [110.2, 20.2], [109.6, 21.4], [108.5, 21.6], [108.0, 21.5],
  [106.7, 22.0], [105.3, 23.3], [103.9, 22.5], [102.5, 22.4], [101.1, 21.2],
  [99.2, 22.1], [97.5, 23.9], [98.7, 25.9], [97.5, 28.3], [96.2, 29.0],
  [95.0, 28.0], [92.5, 27.8], [91.5, 27.8], [89.0, 27.3], [87.0, 27.9],
  [85.0, 28.2], [82.0, 30.3], [79.0, 32.5], [78.7, 33.5], [76.8, 35.5],
  [74.5, 37.0], [73.6, 39.4], [74.0, 40.5], [75.0, 42.0], [80.2, 42.9],
  [80.5, 45.0], [82.5, 45.2], [83.0, 47.2], [85.5, 48.0], [87.8, 49.1],
  [90.0, 47.9], [91.0, 45.2], [95.5, 44.0], [96.4, 42.8], [100.0, 42.6],
  [105.0, 41.8], [109.0, 42.5], [111.5, 43.5], [114.0, 45.0], [117.5, 49.6],
  [120.0, 52.0], [121.5, 53.0],
]

/** Hainan and Taiwan: small, but leaving them out makes the map read as a
 *  different country, so they are drawn as their own outlines. */
export const CHINA_ISLANDS: LonLat[][] = [
  [[109.2, 20.1], [110.6, 20.3], [111.0, 19.6], [110.5, 18.6], [109.6, 18.2],
    [108.7, 19.0], [108.6, 19.9]],
  [[121.0, 25.3], [122.0, 24.9], [121.6, 23.0], [120.9, 21.9], [120.1, 23.1],
    [120.4, 24.6]],
]

/** Ray casting: is ``[lon, lat]`` inside the polygon? */
export function insidePolygon(point: LonLat, polygon: LonLat[]): boolean {
  const [x, y] = point
  let inside = false
  for (let i = 0, j = polygon.length - 1; i < polygon.length; j = i, i += 1) {
    const [xi, yi] = polygon[i]
    const [xj, yj] = polygon[j]
    if ((yi > y) !== (yj > y) && x < ((xj - xi) * (y - yi)) / (yj - yi) + xi) {
      inside = !inside
    }
  }
  return inside
}

/** Equirectangular projection onto a box - the shape a China map is drawn in. */
export function projectEquirectangular(
  lon: number, lat: number, width: number, height: number, bounds: LonLatBounds = CHINA_BOUNDS,
): { x: number; y: number } {
  return {
    x: ((lon - bounds.lonMin) / (bounds.lonMax - bounds.lonMin)) * width,
    y: ((bounds.latMax - lat) / (bounds.latMax - bounds.latMin)) * height,
  }
}

/** The SVG path of an outline in box coordinates. */
export function outlinePath(
  polygon: LonLat[], width: number, height: number, bounds: LonLatBounds = CHINA_BOUNDS,
): string {
  return polygon
    .map(([lon, lat], index) => {
      const { x, y } = projectEquirectangular(lon, lat, width, height, bounds)
      return `${index ? 'L' : 'M'}${x.toFixed(1)} ${y.toFixed(1)}`
    })
    .join(' ') + ' Z'
}

/**
 * The dot grid the map is filled with: every sample inside the landmass. Drawn
 * instead of an SVG fill because a flat fill on a dark wall reads as a hole in
 * the panel, while a grid reads as a map.
 */
export function dotGrid(
  width: number, height: number, step = 6, bounds: LonLatBounds = CHINA_BOUNDS,
): Array<{ x: number; y: number }> {
  const shapes = [CHINA_MAINLAND, ...CHINA_ISLANDS]
  const lonStep = ((bounds.lonMax - bounds.lonMin) * step) / width
  const latStep = ((bounds.latMax - bounds.latMin) * step) / height
  const dots: Array<{ x: number; y: number }> = []
  for (let lat = bounds.latMin; lat <= bounds.latMax; lat += latStep) {
    for (let lon = bounds.lonMin; lon <= bounds.lonMax; lon += lonStep) {
      if (!shapes.some((shape) => insidePolygon([lon, lat], shape))) continue
      dots.push(projectEquirectangular(lon, lat, width, height, bounds))
    }
  }
  return dots
}

export interface GlobeView {
  /** Latitude/longitude the globe is turned towards. */
  lat: number
  lon: number
  radius: number
  cx: number
  cy: number
}

/**
 * Orthographic projection: the globe as seen from outside.
 *
 * A point on the far side comes back ``visible: false`` instead of being folded
 * onto the front - drawing it would put a destination on the wrong hemisphere.
 */
export function projectGlobe(
  lat: number, lon: number, view: GlobeView,
): { x: number; y: number; visible: boolean } {
  const toRad = (deg: number) => (deg * Math.PI) / 180
  const lat0 = toRad(view.lat)
  const lat1 = toRad(lat)
  const delta = toRad(lon - view.lon)
  const cosc = Math.sin(lat0) * Math.sin(lat1) + Math.cos(lat0) * Math.cos(lat1) * Math.cos(delta)
  return {
    x: view.cx + view.radius * Math.cos(lat1) * Math.sin(delta),
    y: view.cy - view.radius * (Math.cos(lat0) * Math.sin(lat1)
      - Math.sin(lat0) * Math.cos(lat1) * Math.cos(delta)),
    visible: cosc > 0,
  }
}

/**
 * Meridians every ``step`` degrees, as ellipse semi-axes.
 *
 * The globe is centred on the equator, where an orthographic projection turns
 * each meridian into an ellipse of width ``R·|sin(Δlon)|`` and height ``R``;
 * the parallels then come out as horizontal chords (see ``globeParallel``).
 * That is the wireframe the panel draws - no look-up table, no map data.
 */
export function globeMeridians(radius: number, step = 30): Array<{ rx: number; ry: number }> {
  const meridians: Array<{ rx: number; ry: number }> = []
  for (let lon = -180 + step / 2; lon < 180; lon += step) {
    meridians.push({ rx: Math.abs(radius * Math.sin((lon * Math.PI) / 180)), ry: radius })
  }
  return meridians
}

/** A parallel at ``lat``: a horizontal chord across the visible hemisphere. */
export function globeParallel(lat: number, radius: number, cy: number): { y: number; half: number } {
  const rad = (lat * Math.PI) / 180
  return { y: cy - radius * Math.sin(rad), half: radius * Math.cos(rad) }
}
