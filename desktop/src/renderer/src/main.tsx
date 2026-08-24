import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App'
import SnipOverlay from './components/SnipOverlay'
import './i18n'
import './index.css'

// 截图浮层窗口用同一份渲染包，靠 #snip 路由到极简浮层（不挂载整个 App）
const isSnip = window.location.hash === '#snip'

ReactDOM.createRoot(document.getElementById('root') as HTMLElement).render(
  <React.StrictMode>{isSnip ? <SnipOverlay /> : <App />}</React.StrictMode>
)
