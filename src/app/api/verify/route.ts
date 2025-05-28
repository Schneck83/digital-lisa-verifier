import { NextRequest, NextResponse } from 'next/server';
import * as secp256k1 from 'tiny-secp256k1';
import { Buffer } from 'buffer';
import { createHash } from 'crypto';

export async function GET(req: NextRequest) {
  try {
    const { searchParams } = new URL(req.url);
    const lisaId = searchParams.get('lisa');
    const pubKey = searchParams.get('pub');
    const signature = searchParams.get('sig');

    if (!lisaId || !pubKey || !signature) {
      return NextResponse.json({ error: 'Missing parameters' }, { status: 400 });
    }

    // Load the Arweave file based on lisaId
    const arweaveTx = getArweaveTxForLisa(lisaId);
    if (!arweaveTx) {
      return NextResponse.json({ error: 'Invalid Lisa ID' }, { status: 400 });
    }

    const anchorUrl = `https://arweave.net/${arweaveTx}`;
    const res = await fetch(anchorUrl);

    if (!res.ok) {
      return NextResponse.json({ error: 'Failed to fetch Arweave file' }, { status: 500 });
    }

    const jsonText = await res.text();
    const anchorData = JSON.parse(jsonText);

    const isCreatorPubKey = anchorData?.creator?.public_key === pubKey;
    const validSignature = verifySignature(pubKey, signature, jsonText);

    return NextResponse.json({
      validSignature,
      isCreatorPubKey,
      lisaId,
      anchorName: anchorData.name,
      imagePreview: anchorData.image_preview,
      hqKeyRequestUrl: anchorData.hq_key_request_url,
    });

  } catch (err: any) {
    console.error('API VERIFY ERROR:', err);
    return NextResponse.json({
      error: 'Internal Server Error',
      message: err.message || 'Unknown error',
      stack: err.stack || null,
    }, { status: 500 });
  }
}

// Signature verification logic
function verifySignature(pubKeyHex: string, sigBase64: string, message: string): boolean {
  try {
    const pubKeyBuffer = Buffer.from(pubKeyHex, 'hex');
    const sigBuffer = Buffer.from(sigBase64, 'base64');
    const msgHash = sha256(Buffer.from(message));
    return secp256k1.verify(sigBuffer, msgHash, pubKeyBuffer);
  } catch (e) {
    console.error('Signature verification failed:', e);
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