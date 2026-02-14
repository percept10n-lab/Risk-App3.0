import { useState, useCallback } from 'react'

interface UseApiOptions<T> {
  onSuccess?: (data: T) => void
  onError?: (error: string) => void
}

export function useApi<T>(
  apiCall: (...args: any[]) => Promise<{ data: T }>,
  options: UseApiOptions<T> = {}
) {
  const [data, setData] = useState<T | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const execute = useCallback(
    async (...args: any[]) => {
      setLoading(true)
      setError(null)
      try {
        const response = await apiCall(...args)
        setData(response.data)
        options.onSuccess?.(response.data)
        return response.data
      } catch (err: any) {
        const message = err.response?.data?.detail || err.message || 'An error occurred'
        setError(message)
        options.onError?.(message)
        return null
      } finally {
        setLoading(false)
      }
    },
    [apiCall]
  )

  return { data, loading, error, execute }
}
