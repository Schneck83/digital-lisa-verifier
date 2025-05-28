import { NextRequest, NextResponse } from 'next/server';
import { Buffer } from 'buffer';
import * as bitcoin from 'bitcoinjs-lib';

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

    // Lade JSON-Anchor
    const jsonRes = await fetch(`https://arweave.net/${tx.json}`);
    const jsonText = await jsonRes.text();
    const jsonData = JSON.parse(jsonText);

    // Lade Signature-Datei
    const sigRes = await fetch(`https://arweave.net/${tx.sig}`);
    if (!sigRes.ok) throw new Error(`Signature file not found`);
    const sigData = await sigRes.json();

    const address = sigData.address;
    const signature = sigData.signature;
    const anchorHash = jsonData.anchor_hash;

    const msgPrefix = '\x18Bitcoin Signed Message:\n';
    const message = Buffer.from(anchorHash, 'hex');
    const lengthBuffer = Buffer.from([message.length]);
    const messageBuffer = Buffer.concat([
      Buffer.from(msgPrefix),
      lengthBuffer,
      message,
    ]);
    const hash = bitcoin.crypto.sha256(bitcoin.crypto.sha256(messageBuffer));

    let validSignature = false;
    try {
      const sig = Buffer.from(signature, 'base64');
      validSignature = bitcoin.ECPair.fromPublicKeyBuffer
        ? bitcoinMessage.verify(anchorHash, address, sig)
        : false;
    } catch (err) {
      validSignature = false;
    }

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
    return NextResponse.json({
      error: 'Internal Server Error',
      message: err.message,
      stack: err.stack || null,
    }, { status: 500 });
  }
}