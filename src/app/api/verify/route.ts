import { NextRequest, NextResponse } from 'next/server';
import { Buffer } from 'buffer';
import * as bitcoin from 'bitcoinjs-lib';
import * as tinySecp from 'tiny-secp256k1';
import * as secp from '@noble/secp256k1';

bitcoin.initEccLib(tinySecp);

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

// Flexible Signaturparser & Verifikation
async function verifyFlexibleSignature(
  address: string,
  messageHash: Buffer,
  signatureBase64: string,
  pubKeyHex: string
): Promise<boolean> {
  const sig = Buffer.from(signatureBase64, 'base64');
  const pubkey = Buffer.from(pubKeyHex, 'hex');

  // 1. Prüfe kompakte 65-Byte Signatur mit Recovery-Byte
  if (sig.length === 65) {
    try {
      const recovery = (sig[0] - 27) % 4;
      if (recovery < 0 || recovery > 3) throw new Error('Invalid recovery byte');
      const compactSig = sig.slice(1);
      const recoveredPubkey = Buffer.from(secp.recover(messageHash, compactSig, recovery, true));
      const derivedAddress = bitcoin.payments.p2wpkh({ pubkey: recoveredPubkey }).address;
      if (derivedAddress !== address) return false;
      return secp.verify(compactSig, messageHash, pubkey);
    } catch {
      // Falls Fehler, einfach weiter prüfen
    }
  }

  // 2. Prüfe 64-Byte RAW Signatur
  if (sig.length === 64) {
    try {
      return secp.verify(sig, messageHash, pubkey);
    } catch {
      // Falls Fehler, weiter prüfen
    }
  }

  // 3. Versuche DER Format zu parsen und zu verifizieren
  if (sig.length >= 65 && sig.length <= 72 && sig[0] === 0x30) {
    try {
      // DER → Raw umwandeln
      const hex = sig.toString('hex');
      const rLen = parseInt(hex.slice(6, 8), 16);
      const r = hex.slice(8, 8 + rLen * 2).padStart(64, '0');
      const sOffset = 8 + rLen * 2 + 2;
      const sLen = parseInt(hex.slice(sOffset - 2, sOffset), 16);
      const s = hex.slice(sOffset, sOffset + sLen * 2).padStart(64, '0');
      const rawSig = Buffer.from(r + s, 'hex');
      return secp.verify(rawSig, messageHash, pubkey);
    } catch {
      return false;
    }
  }

  // Wenn alles fehlschlägt, Signatur ungültig
  return false;
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

    const jsonRes = await fetch(`https://arweave.net/${tx.json}`);
    const jsonText = await jsonRes.text();
    const jsonData = JSON.parse(jsonText);

    const sigRes = await fetch(`https://arweave.net/${tx.sig}`);
    if (!sigRes.ok) throw new Error(`Signature file not found`);
    const sigData = await sigRes.json();

    const anchorHash = Buffer.from(jsonData.anchor_hash, 'hex');
    const pubKey = sigData.public_key;
    const address = sigData.address;
    const signature = sigData.signature;

    const validSignature = await verifyFlexibleSignature(address, anchorHash, signature, pubKey);

    return NextResponse.json({
      lisaId,
      anchorName: jsonData.name,
      imagePreview: jsonData.image_preview,
      hqKeyRequestUrl: jsonData.hq_key_request_url,
      address,
      pubKey,
      signature,
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