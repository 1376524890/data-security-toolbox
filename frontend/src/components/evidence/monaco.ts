import * as monaco from 'monaco-editor'
import editorWorker from 'monaco-editor/editor/editor.worker.js?worker'
import jsonWorker from 'monaco-editor/language/json/json.worker.js?worker'
import cssWorker from 'monaco-editor/language/css/css.worker.js?worker'
import htmlWorker from 'monaco-editor/language/html/html.worker.js?worker'
import tsWorker from 'monaco-editor/language/typescript/ts.worker.js?worker'
import '../../../node_modules/monaco-editor/min/vs/editor/editor.main.css'

self.MonacoEnvironment = {
  getWorker(_workerId: string, label: string) {
    if (label === 'json') return new jsonWorker()
    if (label === 'css' || label === 'scss' || label === 'less') return new cssWorker()
    if (label === 'html' || label === 'handlebars' || label === 'razor') return new htmlWorker()
    if (label === 'typescript' || label === 'javascript') return new tsWorker()
    return new editorWorker()
  },
}

export type MonacoLanguage = 'json' | 'yaml' | 'python' | 'javascript' | 'typescript' | 'plaintext' | 'shell' | 'sql'
export type MonacoTheme = 'vs-dark' | 'soc-dark'

monaco.editor.defineTheme('soc-dark', {
  base: 'vs-dark',
  inherit: true,
  rules: [
    { token: 'string.key.json', foreground: '7dd3fc' },
    { token: 'string.value.json', foreground: 'a5b4fc' },
    { token: 'number', foreground: 'fbbf24' },
    { token: 'keyword', foreground: 'f472b6' },
  ],
  colors: {
    'editor.background': '#0e1626',
    'editor.foreground': '#e5e7eb',
    'editor.lineHighlightBackground': '#1a2438',
    'editorLineNumber.foreground': '#4b5563',
    'editorLineNumber.activeForeground': '#9ca3af',
    'editorIndentGuide.background': '#1f2937',
  },
})

export { monaco }
