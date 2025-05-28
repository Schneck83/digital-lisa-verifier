import { NextRequest, NextResponse } from 'next/server';
import { Buffer } from 'buffer';
import * as bitcoin from 'bitcoinjs-lib';
import * as secp from '@bitcoinerlab/secp256k1';
import * as tinySecp from 'tiny-secp256k1';

// Bitcoinjs muss mit tiny-secp256k1 arbeiten
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

// Hauptfunktion zur Prüfung einer BIP322-Signatur
function verifySignatureBIP322(address: string, messageHash: Buffer, signatureBase64: string): boolean {
  try {
    const sig = Buffer.from(signatureBase64, 'base64');

    // 65-Byte: Compact + Recovery → Recovery Byte abspalten
    if (sig.length !== 65) throw new Error('Unexpected signature length');
    const recovery = sig[0] - 27;
    const signature = sig.slice(1);

    if (recovery < 0 || recovery > 3) throw new Error('Invalid recovery byte');

    // PubKey aus Recovery wiederherstellen
    const pubkey = Buffer.from(secp.recoverPublicKey(messageHash, signature, recovery, true));
    const { address: derived } = bitcoin.payments.p2wpkh({ pubkey });

    return derived === address;
  } catch (err) {
    console.error('verifySignatureBIP322 error:', err);
    return false;
  }
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
    if (!sigRes.ok) throw new Error(`Signature file not found`);
    const sigData = await sigRes.json();

    const anchorHash = Buffer.from(jsonData.anchor_hash, 'hex');
    const address = sigData.address;
    const signature = sigData.signature;

    const validSignature = verifySignatureBIP322(address, anchorHash, signature);

    return NextResponse.json({
      lisaId,
      anchorName: jsonData.name,
      imagePreview: jsonData.image_preview,
      hqKeyRequestUrl: jsonData.hq_key_request_url,
      address,
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