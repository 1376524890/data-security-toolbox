import { createApp } from 'vue'
import ElementPlus from 'element-plus'
import zhCn from 'element-plus/es/locale/lang/zh-cn'
import * as ElementPlusIconsVue from '@element-plus/icons-vue'
import 'element-plus/dist/index.css'
import 'element-plus/theme-chalk/dark/css-vars.css'
import App from './App.vue'
import router from './router'
import { createPinia } from 'pinia'
import { applyTheme, type ThemeMode } from './utils/theme'

// Theme: 数据安全驾驶舱 is designed light-first, so a first-time visitor gets
// the light console; the dark wall screen keeps its own fixed palette either way
// and the header toggle remembers the choice per browser. applyTheme (not a bare
// classList.add) is used so the shared themeMode ref the chart wrappers read is
// set before the first chart is built.
const savedTheme: ThemeMode = localStorage.getItem('dst-theme') === 'dark' ? 'dark' : 'light'
applyTheme(savedTheme)

const app = createApp(App)
app.use(createPinia())
app.use(router)
app.use(ElementPlus, { locale: zhCn })

// Register all Element Plus icons globally for dynamic <component :is="iconName" />
for (const [key, component] of Object.entries(ElementPlusIconsVue)) {
  app.component(key, component as any)
}

app.mount('#app')
