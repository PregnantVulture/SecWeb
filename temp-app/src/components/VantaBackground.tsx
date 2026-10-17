/* eslint-disable @typescript-eslint/no-explicit-any */
'use client';

import React, { useEffect, useRef, useState } from 'react';

export default function VantaBackground({ children }: { children: React.ReactNode }) {
  const vantaRef = useRef<HTMLDivElement>(null);
  const [initialized, setInitialized] = useState(false);

  useEffect(() => {
    let effect: any = null;
    let isMounted = true;

    const loadScript = (src: string): Promise<void> => {
      return new Promise((resolve, reject) => {
        if (document.querySelector(`script[src="${src}"]`)) {
          resolve();
          return;
        }
        const script = document.createElement('script');
        script.src = src;
        script.async = true;
        script.onload = () => resolve();
        script.onerror = () => reject(new Error(`Failed to load script ${src}`));
        document.body.appendChild(script);
      });
    };

    async function setupVanta() {
      try {
        await loadScript('https://cdnjs.cloudflare.com/ajax/libs/three.js/r134/three.min.js');
        await loadScript('https://cdn.jsdelivr.net/npm/vanta@latest/dist/vanta.net.min.js');

        if (isMounted && vantaRef.current && (window as any).VANTA && !effect) {
          effect = (window as any).VANTA.NET({
            el: vantaRef.current,
            mouseControls: true,
            touchControls: true,
            gyroControls: false,
            minHeight: 200.00,
            minWidth: 200.00,
            scale: 1.00,
            scaleMobile: 1.00,
            color: 0x2aac35,
            backgroundColor: 0x1b1a24
          });
          setInitialized(true);
        }
      } catch (e) {
        console.error('Vanta load error:', e);
      }
    }

    // Small timeout to ensure DOM element is fully mounted
    const timer = setTimeout(() => {
      setupVanta();
    }, 50);

    return () => {
      isMounted = false;
      clearTimeout(timer);
      if (effect) {
        try {
          effect.destroy();
        } catch {}
      }
    };
  }, []);

  return (
    <div className="relative min-h-screen w-full bg-[#1b1a24]">
      {/* Vanta background target element */}
      <div
        ref={vantaRef}
        className="fixed inset-0 w-full h-full pointer-events-none z-0"
        style={{ opacity: initialized ? 1 : 0, transition: 'opacity 0.5s ease-in-out' }}
      />
      {/* Subtle overlay for contrast */}
      <div className="fixed inset-0 pointer-events-none z-0 bg-[#1b1a24]/50" />

      {/* Content wrapper */}
      <div className="relative z-10 w-full min-h-screen">
        {children}
      </div>
    </div>
  );
}
