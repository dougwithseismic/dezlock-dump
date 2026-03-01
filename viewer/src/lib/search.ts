import type { SearchEntry } from '../types/schema'

export interface SearchResult {
  index: number
  score: number
}

export function syncSearch(
  query: string,
  entries: SearchEntry[],
  limit = 200,
): SearchResult[] {
  const q = query.toLowerCase().trim()
  if (!q) return []

  const results: SearchResult[] = []
  for (let i = 0; i < entries.length; i++) {
    const name = entries[i].name.toLowerCase()
    if (name.includes(q)) {
      let score = 0
      if (name === q) score = 1000
      else if (name.startsWith(q)) score = 500 - name.length
      else score = 200 - name.indexOf(q)

      const cat = entries[i].category
      if (cat === 'c') score += 10
      else if (cat === 'e') score += 5
      results.push({ index: i, score })
    }
  }

  results.sort((a, b) => b.score - a.score)
  return results.slice(0, limit)
}
