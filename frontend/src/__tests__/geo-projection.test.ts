import { describe, expect, it } from 'vitest'
import {
  CHINA_BOUNDS, CHINA_ISLANDS, CHINA_MAINLAND, dotGrid, globeMeridians, globeParallel,
  insidePolygon, outlinePath, projectEquirectangular, projectGlobe, type GlobeView,
} from '../modules/dashboard/geoProjection'

describe('geoProjection 几何', () => {
  it('places the mainland outline on the country and open ocean off it', () => {
    // Beijing sits inside the simplified outline; the Pacific does not.
    expect(insidePolygon([116.4, 39.9], CHINA_MAINLAND)).toBe(true)
    expect(insidePolygon([140.0, 20.0], CHINA_MAINLAND)).toBe(false)
    // Hainan and Taiwan are their own shapes, so mainland-only tests miss them.
    expect(insidePolygon([109.8, 19.4], CHINA_ISLANDS[0])).toBe(true)
    expect(insidePolygon([121.0, 23.7], CHINA_ISLANDS[1])).toBe(true)
  })

  it('maps the bounds onto the box corners, north at the top', () => {
    const { lonMin, lonMax, latMin, latMax } = CHINA_BOUNDS
    expect(projectEquirectangular(lonMin, latMax, 430, 250)).toEqual({ x: 0, y: 0 })
    expect(projectEquirectangular(lonMax, latMin, 430, 250)).toEqual({ x: 430, y: 250 })
  })

  it('closes every outline path and fills the landmass with dots', () => {
    const path = outlinePath(CHINA_MAINLAND, 430, 250)
    expect(path.startsWith('M')).toBe(true)
    expect(path.endsWith(' Z')).toBe(true)

    const dots = dotGrid(430, 250)
    expect(dots.length).toBeGreaterThan(100)
    expect(dots.every((dot) => dot.x >= 0 && dot.x <= 430 && dot.y >= 0 && dot.y <= 250)).toBe(true)
  })

  it('hides the far side of the globe instead of folding it onto the front', () => {
    const view: GlobeView = { lat: 0, lon: 105, radius: 104, cx: 215, cy: 125 }
    // 105°E is the centre the globe is turned towards.
    expect(projectGlobe(0, 105, view).visible).toBe(true)
    // The antipode is behind the globe.
    const far = projectGlobe(0, -75, view)
    expect(far.visible).toBe(false)
    // A visible point still lands inside the drawn disc.
    const near = projectGlobe(35, 105, view)
    expect(near.visible).toBe(true)
    expect(Math.hypot(near.x - view.cx, near.y - view.cy)).toBeLessThanOrEqual(view.radius)
  })

  it('draws a wireframe whose parallels are chords of the disc', () => {
    const meridians = globeMeridians(104)
    expect(meridians).toHaveLength(12)
    expect(meridians.every((m) => m.rx >= 0 && m.rx <= 104 && m.ry === 104)).toBe(true)
    // Equator: full-width chord through the centre.
    expect(globeParallel(0, 104, 125)).toEqual({ y: 125, half: 104 })
    // Poles shrink to nothing.
    expect(globeParallel(90, 104, 125).half).toBeCloseTo(0, 6)
  })
})
