import { NextRequest, NextResponse } from 'next/server';
import * as secp256k1 from 'tiny-secp256k1';
import { Buffer } from 'buffer';

export async function GET(req: NextRequest) {
  const { searchParams } = new URL(req.url);
  const lisaId = searchParams.get('lisa');
  const pubKey = searchParams.get('pub');
  const signature = searchParams.get('sig');

  if (!lisaId || !pubKey || !signature) {
    return NextResponse.json({ error: 'Missing parameters' }, { status: 400 });
  }

  // 1. Lade Arweave-JSON
  const anchorUrl = `https://arweave.net/${getArweaveTxForLisa(lisaId)}`;
  const res = await fetch(anchorUrl);
  const jsonText = await res.text(); // ← Signatur prüfen über diesen Text
  const anchorData = JSON.parse(jsonText); // ← danach wie gehabt benutzen

  // 2. TODO: Signatur prüfen (kommt gleich)
  function verifySignature(pubKeyHex: string, sigBase64: string, message: string): boolean {
  try {
    const pubKeyBuffer = Buffer.from(pubKeyHex, 'hex');
    const sigBuffer = Buffer.from(sigBase64, 'base64');
    const msgHash = sha256(Buffer.from(message)); // Bitcoin-style hash

    return secp256k1.verify(sigBuffer, msgHash, pubKeyBuffer);
  } catch (e) {
    console.error('Signature verification error:', e);
    return false;
  }
}

// Einfacher SHA256-Wrapper
function sha256(buffer: Buffer): Buffer {
  const crypto = require('crypto');
  return crypto.createHash('sha256').update(buffer).digest();
}

const validSignature = verifySignature(pubKey, signature, jsonText);
  const creatorKey = anchorData?.creator?.public_key;

  const isCreatorPubKey = creatorKey === pubKey;

  return NextResponse.json({
    validSignature,
    isCreatorPubKey,
    lisaId,
    anchorName: anchorData.name,
    imagePreview: anchorData.image_preview,
    hqKeyRequestUrl: anchorData.hq_key_request_url,
  });
}

// Temporäre Zuordnung – später dynamisch mit Arweave-Registry
function getArweaveTxForLisa(id: string): string {
  if (id === '0001') return 'xXXekbk0xxUKia4EFkMfbWdbi1Pwn5GULAJJ5J-TXiI';
  if (id === '0002') return 'Fat-f687B5YGUSJ8ga06iVAdm9nl5OLxxOwaxhfbeN8';
  if (id === '0003') return 'I-8XTVl27R78-u09MvEQTBekeLZeB9JDRqsogShffnM';
  return '';
}