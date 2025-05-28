import { NextRequest, NextResponse } from 'next/server';
import { Buffer } from 'buffer';
import * as bitcoin from 'bitcoinjs-lib';
import { createHash } from 'crypto';
import * as secp from 'noble-secp256k1';
import * as varuint from 'varuint-bitcoin';

// Bitcoin-Message Hash nach BIP322 mit VarInt Länge
function bitcoinMessageHash(message: string): Buffer {
  const prefix = Buffer.from('\x18Bitcoin Signed Message:\n', 'utf8');
  const messageBuffer = Buffer.from(message, 'utf8');

  const lengthEncoded = varuint.encode(messageBuffer.length);
  const lengthBuffer = Buffer.from(lengthEncoded);

  const buffer = Buffer.concat([prefix, lengthBuffer, messageBuffer]);
  const hash1 = createHash('sha256').update(buffer).digest();
  const hash2 = createHash('sha256').update(hash1).digest();
  return hash2;
}

async function verifySignature(
  pubKeyHex: string,
  signatureBase64: string,
  messageHash: Buffer
): Promise<boolean> {
  const sig = Buffer.from(signatureBase64, 'base64');

  if (sig.length !== 65) {
    console.log('Ungültige Signaturlänge:', sig.length);
    return false;
  }

  let recovery = sig[0];

  if (recovery > 30) {
    recovery = recovery - 27;
  }

  if (recovery < 0 || recovery > 3) {
    console.log('Ungültiges Recovery-Byte:', sig[0], 'nach Anpassung:', recovery);
    return false;
  }

  const compactSig = sig.slice(1);

  try {
    const pubkeyCompressed = Uint8Array.from(Buffer.from(pubKeyHex, 'hex'));
    const pubkey = secp.Point.fromHex(pubkeyCompressed).toRawBytes(false).slice(1);

    const recoveredPubkeyCompressed = secp.recoverPublicKey(messageHash, compactSig, recovery);
    if (!recoveredPubkeyCompressed) {
      console.log('Fehler: Konnte Public Key nicht rekonstruieren');
      return false;
    }
    const recoveredPubkey = secp.Point.fromHex(recoveredPubkeyCompressed).toRawBytes(false).slice(1);

    const derivedAddress = bitcoin.payments.p2wpkh({ pubkey: Buffer.from(recoveredPubkey) }).address;
    const originalAddress = bitcoin.payments.p2wpkh({ pubkey: Buffer.from(pubkey) }).address;

    if (derivedAddress !== originalAddress) {
      console.log('Recovered address stimmt nicht mit Original überein');
      return false;
    }

    return await secp.verify(compactSig, messageHash, pubkey);
  } catch (e) {
    console.log('Fehler bei Verifikation:', e);
    return false;
  }
}

export async function GET(req: NextRequest) {
  try {
    const { searchParams } = new URL(req.url);

    const uid = searchParams.get('uid');
    const lisaId = searchParams.get('lisa');
    const pubKey = searchParams.get('pub');
    const signature = searchParams.get('sig');

    if (!uid || !lisaId || !pubKey || !signature) {
      return NextResponse.json({ error: 'Fehlende Parameter' }, { status: 400 });
    }

    const message = `uid=${uid}&lisa_id=${lisaId}`;

    console.log('Verifiziere NFC Signatur mit Parametern:');
    console.log('Message:', message);
    console.log('Public Key:', pubKey);
    console.log('Signature (Base64):', signature);

    const messageHash = bitcoinMessageHash(message);

    const validSignature = await verifySignature(pubKey, signature, messageHash);

    console.log('Signatur gültig:', validSignature);

    const anchorName = `Digital Lisa #${lisaId}`;
    const imagePreview = `ar://OOqqylcAolOZbrnoEMmKmCyP9J3ZXiwkU6sCkT-dRU4`;
    const hqKeyRequestUrl = `https://verify.digital-lisa-club.xyz/request-key?lisa_id=${lisaId}`;

    return NextResponse.json({
      uid,
      lisaId,
      pubKey,
      signature,
      validSignature,
      anchorName,
      imagePreview,
      hqKeyRequestUrl,
    });
  } catch (err: any) {
    console.error('Fehler bei NFC Verifikation:', err);
    return NextResponse.json({
      error: 'Interner Serverfehler',
      message: err.message,
      stack: err.stack || null,
    }, { status: 500 });
  }
}