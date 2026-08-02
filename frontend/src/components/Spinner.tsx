// Simple circular loading indicator — used anywhere a fetch/parse is in
// progress and the page would otherwise look empty/idle while it works.
export default function Spinner({ className = 'w-4 h-4', label }: { className?: string; label?: string }) {
  return (
    <span className="inline-flex items-center gap-2">
      <svg className={`${className} animate-spin text-sky-400`} viewBox="0 0 24 24" fill="none">
        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
        <path className="opacity-90" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
      </svg>
      {label && <span className="text-sm text-gray-400">{label}</span>}
    </span>
  )
}
