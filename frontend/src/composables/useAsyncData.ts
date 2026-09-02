import { onMounted, ref, type Ref } from 'vue'

export function useAsyncData<T>(loader: () => Promise<T>) {
  const loading = ref(false)
  const error = ref('')
  const data = ref<T | null>(null) as Ref<T | null>

  async function load(): Promise<void> {
    loading.value = true
    error.value = ''
    try {
      data.value = await loader()
    } catch (err) {
      error.value = err instanceof Error ? err.message : String(err)
    } finally {
      loading.value = false
    }
  }

  onMounted(load)
  return { loading, error, data, load }
}
