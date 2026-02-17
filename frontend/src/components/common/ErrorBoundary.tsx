import React from 'react'

interface Props {
  children: React.ReactNode
}

interface State {
  hasError: boolean
  error: Error | null
  errorInfo: React.ErrorInfo | null
}

export default class ErrorBoundary extends React.Component<Props, State> {
  constructor(props: Props) {
    super(props)
    this.state = { hasError: false, error: null, errorInfo: null }
  }

  static getDerivedStateFromError(error: Error) {
    return { hasError: true, error }
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
    this.setState({ errorInfo })
    console.error('[ErrorBoundary] Caught error:', error)
    console.error('[ErrorBoundary] Component stack:', errorInfo.componentStack)
  }

  render() {
    if (this.state.hasError) {
      return (
        <div style={{
          padding: 32,
          fontFamily: 'system-ui, -apple-system, sans-serif',
          maxWidth: 800,
          margin: '40px auto',
        }}>
          <div style={{
            background: '#fef2f2',
            border: '2px solid #ef4444',
            borderRadius: 12,
            padding: 24,
          }}>
            <h1 style={{ color: '#dc2626', fontSize: 20, margin: '0 0 8px 0' }}>
              Application Error
            </h1>
            <p style={{ color: '#991b1b', fontSize: 14, margin: '0 0 16px 0' }}>
              The app crashed. Details below:
            </p>

            <div style={{
              background: '#1f2937',
              color: '#f9fafb',
              borderRadius: 8,
              padding: 16,
              fontSize: 13,
              fontFamily: 'monospace',
              whiteSpace: 'pre-wrap',
              wordBreak: 'break-word',
              maxHeight: 200,
              overflow: 'auto',
              marginBottom: 12,
            }}>
              {this.state.error?.toString()}
            </div>

            {this.state.errorInfo?.componentStack && (
              <details style={{ marginBottom: 12 }}>
                <summary style={{
                  color: '#6b7280',
                  fontSize: 13,
                  cursor: 'pointer',
                  marginBottom: 8,
                }}>
                  Component Stack Trace
                </summary>
                <div style={{
                  background: '#1f2937',
                  color: '#9ca3af',
                  borderRadius: 8,
                  padding: 16,
                  fontSize: 12,
                  fontFamily: 'monospace',
                  whiteSpace: 'pre-wrap',
                  maxHeight: 300,
                  overflow: 'auto',
                }}>
                  {this.state.errorInfo.componentStack}
                </div>
              </details>
            )}

            <button
              onClick={() => window.location.reload()}
              style={{
                background: '#dc2626',
                color: 'white',
                border: 'none',
                borderRadius: 6,
                padding: '8px 16px',
                fontSize: 14,
                cursor: 'pointer',
              }}
            >
              Reload Page
            </button>
          </div>
        </div>
      )
    }

    return this.props.children
  }
}
