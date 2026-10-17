import UnifiedScanView from "@/components/UnifiedScanView";
import VantaBackground from "@/components/VantaBackground";

export default function Home() {
  return (
    <VantaBackground>
      <main className="min-h-screen py-12 px-4 sm:px-6 lg:px-8">
        <div className="max-w-7xl mx-auto mb-8 text-center">
          <h1 className="text-4xl sm:text-5xl lg:text-6xl font-black text-white tracking-tight drop-shadow-[0_4px_30px_rgba(42,172,53,0.35)] relative">
            <span className="relative z-10">SECWEB</span>
            <span className="absolute inset-0 blur-xl text-emerald-400/30 -z-10 scale-110 select-none">SECWEB</span>
          </h1>
          <p className="text-sm sm:text-base text-zinc-300/90 mt-3 drop-shadow-lg font-light tracking-wide">
            Automated vulnerability assessment, discovery, and site verification dashboard.
          </p>
        </div>
        <UnifiedScanView />
      </main>
    </VantaBackground>
  );
}
