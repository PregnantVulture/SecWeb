import UnifiedScanView from "@/components/UnifiedScanView";
import VantaBackground from "@/components/VantaBackground";

export default function Home() {
  return (
    <VantaBackground>
      <main className="min-h-screen py-12 px-4 sm:px-6 lg:px-8">
        <div className="max-w-7xl mx-auto mb-8 text-center">
          <h1 className="text-3xl font-black text-white tracking-tight drop-shadow-md">
            SECWEB - Secure your website with ease
          </h1>
          <p className="text-sm text-zinc-300 mt-2 drop-shadow">
            Automated vulnerability assessment, discovery, and site verification dashboard.
          </p>
        </div>
        <UnifiedScanView />
      </main>
    </VantaBackground>
  );
}
