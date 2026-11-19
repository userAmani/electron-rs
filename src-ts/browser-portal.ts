import { ipcRenderer } from 'electron'

if (process.isMainFrame && location.origin === 'https://web.shuiwujia.com' && ['/pc/detail', '/pc/detail/'].includes(location.pathname)) {
  const params = new URLSearchParams(location.search)
  if (!params.has('waterbuddy_token') && !params.has('waterbuddy_logout')) {
    const token: unknown = ipcRenderer.sendSync('waterbuddy:consume-preview-login')
    const key = 'waterbuddy-portal-token'
    const managed = 'waterbuddy-preview-login'
    try {
      if (typeof token === 'string' && token) {
        sessionStorage.setItem(key, token)
        sessionStorage.setItem(managed, '1')
      } else if (sessionStorage.getItem(managed) === '1') {
        sessionStorage.removeItem(key)
        sessionStorage.removeItem(managed)
      }
    } catch { }
  }
}
