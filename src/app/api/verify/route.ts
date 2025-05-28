import { NextRequest, NextResponse } from 'next/server';
import { Buffer } from 'buffer';
import { verify } from '@noble/secp256k1';

// 🔁 DER → RAW Signaturkonvertierung (Ledger-kompatibel)
function derToRawSignature(der: Uint8Array): Uint8Array {
  const hex = Buffer.from(der).toString('hex');
  if (!hex.startsWith('30')) throw new Error('Not a DER signature');
  const rLen = parseInt(hex.slice(6, 8), 16);
  const r = hex.slice(8, 8 + rLen * 2).padStart(64, '0');
  const sOffset = 8 + rLen * 2 + 2;
  const sLen = parseInt(hex.slice(sOffset - 2, sOffset), 16);
  const s = hex.slice(sOffset, sOffset + sLen * 2).padStart(64, '0');
  return Buffer.from(r + s, 'hex');
}

// Lisa → Arweave TX mapping
function getLisaTx(id: string): { json: string; sig: string } {
  if (id === '0001') return {
    json: 'xXXekbk0xxUKia4EFkMfbWdbi1Pwn5GULAJJ5J-TXiI',
    sig: 'qNkRki18W_N_vUPXAnajK2ED7jviCjGeCK0SpjLpwFU'
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

    // JSON-Anchor laden
    const jsonRes = await fetch(`https://arweave.net/${tx.json}`);
    const jsonText = await jsonRes.text();
    const jsonData = JSON.parse(jsonText);

    // Signature-Datei laden
    const sigRes = await fetch(`https://arweave.net/${tx.sig}`);
    if (!sigRes.ok) throw new Error(`Signature file not found`);
    const sigData = await sigRes.json();

    const anchorHash = jsonData.anchor_hash;
    const pubKey = sigData.public_key;
    const signatureDer = Buffer.from(sigData.signature, 'base64');
    const signatureRaw = derToRawSignature(signatureDer);
    const hash = Buffer.from(anchorHash, 'hex');

    const validSignature = await verify(signatureRaw, hash, pubKey);

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
    return NextResponse.json({
      error: 'Internal Server Error',
      message: err.message,
      stack: err.stack || null,
    }, { status: 500 });
  }
}