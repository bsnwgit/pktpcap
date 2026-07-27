import clsx from 'clsx'

/**
 * Page-number bar: shows every page when there are 5 or fewer, otherwise a
 * sliding block of 5 around the current page (plus 1/.. and ..N/last-page
 * jump shortcuts once the block doesn't already include the ends) — plus
 * prev/next buttons.
 */
export default function Pagination({ page, totalPages, onChange }: { page: number; totalPages: number; onChange: (p: number) => void }) {
  if (totalPages <= 1) return null
  const blockStart = Math.floor((page - 1) / 5) * 5 + 1
  const blockEnd   = Math.min(blockStart + 4, totalPages)
  const pages = Array.from({ length: blockEnd - blockStart + 1 }, (_, i) => blockStart + i)
  const btn = (p: number) => clsx(
    'text-xs min-w-[1.75rem] px-2 py-1 rounded-lg border transition-colors',
    p === page
      ? 'bg-sky-600/30 border-sky-500 text-sky-200'
      : 'bg-gray-800 border-gray-700 text-gray-400 hover:text-white',
  )
  return (
    <div className="flex items-center gap-1.5">
      <button onClick={() => onChange(Math.max(1, page - 1))} disabled={page === 1}
        className="text-xs px-2.5 py-1 rounded-lg border border-gray-700 bg-gray-800 text-gray-300 hover:text-white disabled:opacity-40 disabled:cursor-not-allowed transition-colors">
        ← Prev
      </button>
      {blockStart > 1 && (<><button onClick={() => onChange(1)} className={btn(1)}>1</button><span className="px-1 text-gray-500 text-xs">..</span></>)}
      {pages.map(p => <button key={p} onClick={() => onChange(p)} className={btn(p)}>{p}</button>)}
      {blockEnd < totalPages && (<><span className="px-1 text-gray-500 text-xs">..</span><button onClick={() => onChange(totalPages)} className={btn(totalPages)}>{totalPages}</button></>)}
      <button onClick={() => onChange(Math.min(totalPages, page + 1))} disabled={page === totalPages}
        className="text-xs px-2.5 py-1 rounded-lg border border-gray-700 bg-gray-800 text-gray-300 hover:text-white disabled:opacity-40 disabled:cursor-not-allowed transition-colors">
        Next →
      </button>
    </div>
  )
}
