import { NextRequest, NextResponse } from 'next/server';
import { createHash } from 'crypto';
import { Buffer } from 'buffer';

// 🔐 Signatur prüfen mit secp256k1
import * as secp256k1 from 'tiny-secp256k1';

export async function GET(req: NextRequest) {
  try {
    const { searchParams } = new URL(req.url);
    const lisaId = searchParams.get('lisa');
    const pubKey = searchParams.get('pub');
    const signature = searchParams.get('sig');

    if (!lisaId || !pubKey || !signature) {
      return NextResponse.json({ error: 'Missing parameters' }, { status: 400 });
    }

    const anchorUrl = `https://arweave.net/${getArweaveTxForLisa(lisaId)}`;
    const res = await fetch(anchorUrl);

    if (!res.ok) {
      return NextResponse.json({ error: 'Failed to load Arweave JSON' }, { status: 500 });
    }

    const jsonText = await res.text();
    const anchorData = JSON.parse(jsonText);

    const validSignature = verifySignature(pubKey, signature, jsonText);
    const isCreatorPubKey = anchorData?.creator?.public_key === pubKey;

    return NextResponse.json({
      validSignature,
      isCreatorPubKey,
      lisaId,
      anchorName: anchorData.name,
      imagePreview: anchorData.image_preview,
      hqKeyRequestUrl: anchorData.hq_key_request_url,
    });
  } catch (err: any) {
    console.error('VERIFY ROUTE ERROR:', err);
    return NextResponse.json({ error: 'Internal error', message: err.message }, { status: 500 });
  }
}

function verifySignature(pubKeyHex: string, sigBase64: string, message: string): boolean {
  try {
    const pubKeyBuffer = Buffer.from(pubKeyHex, 'hex');
    const sigBuffer = Buffer.from(sigBase64, 'base64');
    const msgHash = sha256(Buffer.from(message));
    return secp256k1.verify(sigBuffer, msgHash, pubKeyBuffer);
  } catch (e) {
    console.error('Signature verification error:', e);
    return false;
  }
}

function sha256(buffer: Buffer): Buffer {
  return createHash('sha256').update(buffer).digest();
}

function getArweaveTxForLisa(id: string): string {
  if (id === '0001') return 'xXXekbk0xxUKia4EFkMfbWdbi1Pwn5GULAJJ5J-TXiI';
  if (id === '0002') return 'Fat-f687B5YGUSJ8ga06iVAdm9nl5OLxxOwaxhfbeN8';
  if (id === '0003') return 'I-8XTVl27R78-u09MvEQTBekeLZeB9JDRqsogShffnM';
  return '';
}