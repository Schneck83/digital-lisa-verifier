import { NextRequest, NextResponse } from 'next/server';
import { createHash } from 'crypto';
import { Buffer } from 'buffer';
import { verify } from '@noble/secp256k1';

// Mapping Lisa-ID → Arweave TX-IDs
function getLisaTx(id: string): { json: string, sig: string } {
  if (id === '0001') return {
    json: 'xXXekbk0xxUKia4EFkMfbWdbi1Pwn5GULAJJ5J-TXiI',
    sig: '7eFxu_1xmh9R8K4N4dEHi7G1PZJ9VQ7CFXXE0yz_gkI'
  };
  if (id === '0002') return {
    json: 'Fat-f687B5YGUSJ8ga06iVAdm9nl5OLxxOwaxhfbeN8',
    sig: 'V2I1NnYFyUXESuEiI9jKfMH0nFyH5A7FNTWlkk4U5d4'
  };
  if (id === '0003') return {
    json: 'I-8XTVl27R78-u09MvEQTBekeLZeB9JDRqsogShffnM',
    sig: 'IAvI6WZc2NLImcU1pU-SZP_4HOALM2akHvZBY2F4fZw'
  };
  return { json: '', sig: '' };
}

// Hilfsfunktion: SHA256 für Nachricht
function sha256(msg: string): Uint8Array {
  return createHash('sha256').update(msg).digest();
}

export async function GET(req: NextRequest) {
  try {
    const { searchParams } = new URL(req.url);
    const lisaId = searchParams.get('lisa');
    if (!lisaId) {
      return NextResponse.json({ error: 'Missing Lisa ID' }, { status: 400 });
    }

    const tx = getLisaTx(lisaId);
    if (!tx.json || !tx.sig) {
      return NextResponse.json({ error: 'Unknown Lisa ID' }, { status: 404 });
    }

    // Lade JSON-Anchor
    const jsonRes = await fetch(`https://arweave.net/${tx.json}`);
    const jsonText = await jsonRes.text();
    const jsonData = JSON.parse(jsonText);

    // Lade Signature-Datei
    const sigRes = await fetch(`https://arweave.net/${tx.sig}`);
    const sigData = await sigRes.json();
    const pubKey = sigData.public_key;
    const signature = Buffer.from(sigData.signature, 'base64').toString('hex');
    const hash = sha256(jsonText);

    const validSignature = await verify(signature, hash, pubKey);

    return NextResponse.json({
      lisaId,
      anchorName: jsonData.name,
      imagePreview: jsonData.image_preview,
      hqKeyRequestUrl: jsonData.hq_key_request_url,
      pubKey,
      signature: sigData.signature,
      validSignature
    });
  } catch (err: any) {
    console.error('Auto-verification error:', err);
    return NextResponse.json({
      error: 'Internal Server Error',
      message: err.message,
      stack: err.stack || null,
    }, { status: 500 });
  }
}