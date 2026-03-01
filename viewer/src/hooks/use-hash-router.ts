import { useState, useEffect, useCallback } from 'react'

export interface HashRoute {
  type: 'class' | 'enum' | 'global' | 'globals' | 'tree' | 'protobuf' | 'entities' | null
  module: string
  name: string
}

function parseHash(): HashRoute {
  const hash = decodeURIComponent(location.hash.slice(1))
  if (!hash) return { type: null, module: '', name: '' }

  const p = hash.split('/')
  if (p[0] === 'class' && p.length >= 3) {
    return { type: 'class', module: p[1], name: p.slice(2).join('/') }
  }
  if (p[0] === 'enum' && p.length >= 3) {
    return { type: 'enum', module: p[1], name: p.slice(2).join('/') }
  }
  if (p[0] === 'global' && p.length >= 3) {
    return { type: 'global', module: p[1], name: p.slice(2).join('/') }
  }
  if (p[0] === 'globals') {
    return { type: 'globals', module: '', name: '' }
  }
  if (p[0] === 'tree') {
    return { type: 'tree', module: '', name: '' }
  }
  if (p[0] === 'protobuf' && p.length >= 3) {
    return { type: 'protobuf', module: p[1], name: p.slice(2).join('/') }
  }
  if (p[0] === 'protobuf') {
    return { type: 'protobuf', module: '', name: '' }
  }
  if (p[0] === 'entities') {
    return { type: 'entities', module: '', name: '' }
  }
  return { type: null, module: '', name: '' }
}

export function useHashRouter() {
  const [route, setRoute] = useState<HashRoute>(parseHash)

  useEffect(() => {
    const handler = () => setRoute(parseHash())
    window.addEventListener('hashchange', handler)
    return () => window.removeEventListener('hashchange', handler)
  }, [])

  const navigate = useCallback((type: string, module?: string, name?: string) => {
    if (type === 'class') location.hash = 'class/' + encodeURIComponent(module!) + '/' + encodeURIComponent(name!)
    else if (type === 'enum') location.hash = 'enum/' + encodeURIComponent(module!) + '/' + encodeURIComponent(name!)
    else if (type === 'globals') location.hash = 'globals'
    else if (type === 'global') location.hash = 'global/' + encodeURIComponent(module!) + '/' + encodeURIComponent(name!)
    else if (type === 'tree') location.hash = 'tree'
    else if (type === 'protobuf' && module && name) location.hash = 'protobuf/' + encodeURIComponent(module) + '/' + encodeURIComponent(name)
    else if (type === 'protobuf') location.hash = 'protobuf'
    else if (type === 'entities') location.hash = 'entities'
  }, [])

  return { route, navigate }
}
