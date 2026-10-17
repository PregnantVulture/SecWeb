import { NextResponse } from 'next/server';

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const { url } = body;

    if (!url || typeof url !== 'string') {
      return NextResponse.json(
        { error: 'Valid target URL is required' },
        { status: 400 }
      );
    }

    let parsedUrl: URL;
    try {
      parsedUrl = new URL(url);
    } catch {
      return NextResponse.json(
        { error: 'Invalid URL format' },
        { status: 400 }
      );
    }

    if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
      return NextResponse.json(
        { error: 'Only HTTP and HTTPS protocols are supported' },
        { status: 400 }
      );
    }

    const apiKey = process.env.TINYFISH_API_KEY;
    if (!apiKey) {
      return NextResponse.json(
        { error: 'Server configuration error: TinyFish API key missing' },
        { status: 500 }
      );
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 30000);

    const tinyfishResponse = await fetch('https://api.fetch.tinyfish.ai', {
      method: 'POST',
      headers: {
        'X-API-Key': apiKey,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ urls: [url] }),
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    if (!tinyfishResponse.ok) {
      const errorText = await tinyfishResponse.text();
      return NextResponse.json(
        { error: `TinyFish API error (${tinyfishResponse.status}): ${errorText}` },
        { status: tinyfishResponse.status }
      );
    }

    const data = await tinyfishResponse.json();
    const resultItem = data.results && data.results[0] ? data.results[0] : null;

    return NextResponse.json({
      success: true,
      data: {
        url: resultItem?.url || url,
        finalUrl: resultItem?.final_url || url,
        title: resultItem?.title || '',
        description: resultItem?.description || '',
        language: resultItem?.language || '',
        text: resultItem?.text || '',
        author: resultItem?.author || null,
        publishedDate: resultItem?.published_date || null,
        latencyMs: resultItem?.latency_ms || 0,
        format: resultItem?.format || 'markdown',
      },
      raw: data,
    });
  } catch (err: unknown) {
    const errorObj = err as { name?: string; message?: string };
    if (errorObj.name === 'AbortError') {
      return NextResponse.json(
        { error: 'Request to TinyFish API timed out' },
        { status: 504 }
      );
    }
    return NextResponse.json(
      { error: errorObj.message || 'Internal server error' },
      { status: 500 }
    );
  }
}
