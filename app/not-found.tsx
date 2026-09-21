import Link from "next/link";

export default function NotFound() {
  return (
    <div className="min-h-screen bg-[#09090b] text-neutral-100 flex flex-col items-center justify-center p-6 text-center font-sans">
      <div className="w-10 h-10 rounded-xl bg-neutral-900 border border-neutral-800 flex items-center justify-center font-bold text-white mb-4">
        C
      </div>
      <h2 className="text-xl font-semibold text-white mb-2">Page Not Found</h2>
      <p className="text-xs text-neutral-400 max-w-sm mb-6">
        The requested resource or session could not be located on this Crux instance.
      </p>
      <Link
        href="/"
        className="px-4 py-2 rounded-xl text-xs font-medium bg-white text-neutral-950 hover:bg-neutral-100 transition-all"
      >
        Return to Crux
      </Link>
    </div>
  );
}
