import UnifiedScanView from "@/components/UnifiedScanView";
//for commiting 
export default function Home() {
  return (
    <main className="min-h-screen bg-zinc-50 dark:bg-zinc-950 py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-7xl mx-auto mb-8 text-center">
        <h1 className="text-3xl font-black text-zinc-900 dark:text-zinc-100 tracking-tight">
          Website Intelligence & Vulnerability Scanner
        </h1>
        <p className="text-sm text-zinc-500 dark:text-zinc-400 mt-2">
          Automated vulnerability assessment, discovery, and site verification dashboard.
        </p>
      </div>
      <UnifiedScanView />
    </main>
  );
}
